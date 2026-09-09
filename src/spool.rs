//! Hold-then-forward request body above Pingora's 64 KiB retry buffer.
//!
//! Unset `SPOOL_DIR` keeps spool off. The directory is validated and leftover
//! `spool-*` files are wiped only when the loaded Config has `max_decoded_body`.

use bytes::Bytes;
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::config::Config;

pub const DEFAULT_DIR: &str = "/var/lib/ferroada/spool";
pub const MEMORY_CEILING: usize = 256 * 1024;
pub const DEFAULT_MAX_BYTES: usize = 512 * 1024 * 1024;
pub const DEFAULT_MAX_FILES: usize = 256;
const REPLAY_CHUNK: usize = 64 * 1024;

static FILE_SEQ: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub enum SpoolError {
    Overflow,
    Budget,
    Files,
    NotConfigured,
    Io(std::io::Error),
}

impl SpoolError {
    pub fn is_overflow(&self) -> bool {
        matches!(self, Self::Overflow)
    }

    pub fn is_capacity(&self) -> bool {
        matches!(self, Self::Budget | Self::Files | Self::NotConfigured)
    }
}

struct ByteBudget {
    current: AtomicUsize,
    max: usize,
}

impl ByteBudget {
    fn new(max: usize) -> Self {
        Self {
            current: AtomicUsize::new(0),
            max,
        }
    }

    fn reserve(&self, bytes: usize) -> bool {
        self.current
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(bytes).filter(|next| *next <= self.max)
            })
            .is_ok()
    }

    fn release(&self, bytes: usize) {
        if bytes > 0 {
            self.current.fetch_sub(bytes, Ordering::AcqRel);
        }
    }
}

struct FileBudget {
    current: AtomicUsize,
    max: usize,
}

impl FileBudget {
    fn new(max: usize) -> Self {
        Self {
            current: AtomicUsize::new(0),
            max,
        }
    }

    fn acquire(&self) -> bool {
        self.current
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < self.max).then_some(current + 1)
            })
            .is_ok()
    }

    fn release(&self) {
        self.current.fetch_sub(1, Ordering::AcqRel);
    }
}

enum Storage {
    Memory(Vec<u8>),
    File {
        path: PathBuf,
        file: tokio::fs::File,
        inspect: Option<Vec<u8>>,
    },
}

/// Per-process spool directory and aggregate budgets. Inactive when no route
/// declares `max_decoded_body`.
pub struct SpoolRuntime {
    dir: Option<PathBuf>,
    bytes: ByteBudget,
    files: FileBudget,
}

impl SpoolRuntime {
    pub fn from_config(config: &Config) -> Self {
        if !config.has_spool_routes() {
            return Self::off();
        }
        Self {
            dir: Some(dir_from_env()),
            bytes: ByteBudget::new(env_usize("SPOOL_MAX_BYTES", DEFAULT_MAX_BYTES)),
            files: FileBudget::new(env_usize("SPOOL_MAX_FILES", DEFAULT_MAX_FILES)),
        }
    }

    pub fn off() -> Self {
        Self {
            dir: None,
            bytes: ByteBudget::new(DEFAULT_MAX_BYTES),
            files: FileBudget::new(DEFAULT_MAX_FILES),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.dir.is_some()
    }

    pub fn dir(&self) -> Option<&Path> {
        self.dir.as_deref()
    }
}

pub struct SpoolHandle {
    storage: Storage,
    len: usize,
    max: usize,
    replay_at: u64,
    replay_done: bool,
    reserved: usize,
    holds_file_slot: bool,
    runtime: Arc<SpoolRuntime>,
}

impl SpoolHandle {
    pub fn new(max: usize, runtime: Arc<SpoolRuntime>) -> Self {
        Self {
            storage: Storage::Memory(Vec::new()),
            len: 0,
            max,
            replay_at: 0,
            replay_done: false,
            reserved: 0,
            holds_file_slot: false,
            runtime,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub async fn push(&mut self, chunk: &[u8]) -> Result<(), SpoolError> {
        if chunk.is_empty() {
            return Ok(());
        }
        let next = self
            .len
            .checked_add(chunk.len())
            .filter(|size| *size <= self.max)
            .ok_or(SpoolError::Overflow)?;
        if !self.runtime.bytes.reserve(chunk.len()) {
            return Err(SpoolError::Budget);
        }
        self.reserved += chunk.len();

        let spill = matches!(&self.storage, Storage::Memory(buf) if buf.len() + chunk.len() > MEMORY_CEILING);
        if spill {
            return self.spill_to_file(chunk).await;
        }

        match &mut self.storage {
            Storage::Memory(buf) => {
                buf.extend_from_slice(chunk);
                self.len = next;
            }
            Storage::File { file, inspect, .. } => {
                file.write_all(chunk).await.map_err(SpoolError::Io)?;
                inspect.take();
                self.len = next;
            }
        }
        Ok(())
    }

    async fn spill_to_file(&mut self, extra: &[u8]) -> Result<(), SpoolError> {
        let dir = self
            .runtime
            .dir
            .as_ref()
            .ok_or(SpoolError::NotConfigured)?;
        if !self.runtime.files.acquire() {
            return Err(SpoolError::Files);
        }
        self.holds_file_slot = true;
        let path = unique_spool_path(dir);
        let mut opts = tokio::fs::OpenOptions::new();
        opts.create_new(true).read(true).write(true);
        #[cfg(unix)]
        {
            opts.mode(0o600);
        }
        let mut file = match opts.open(&path).await {
            Ok(file) => file,
            Err(error) => {
                self.runtime.files.release();
                self.holds_file_slot = false;
                return Err(SpoolError::Io(error));
            }
        };
        let existing = match &self.storage {
            Storage::Memory(buf) => buf.clone(),
            Storage::File { .. } => Vec::new(),
        };
        if let Err(error) = file.write_all(&existing).await {
            let _ = tokio::fs::remove_file(&path).await;
            self.runtime.files.release();
            self.holds_file_slot = false;
            return Err(SpoolError::Io(error));
        }
        if let Err(error) = file.write_all(extra).await {
            let _ = tokio::fs::remove_file(&path).await;
            self.runtime.files.release();
            self.holds_file_slot = false;
            return Err(SpoolError::Io(error));
        }
        self.len += extra.len();
        self.storage = Storage::File {
            path,
            file,
            inspect: None,
        };
        Ok(())
    }

    pub async fn inspect_bytes(&mut self) -> Result<&[u8], SpoolError> {
        match &mut self.storage {
            Storage::Memory(buf) => Ok(buf.as_slice()),
            Storage::File { file, inspect, .. } => {
                if inspect.is_none() {
                    file.seek(SeekFrom::Start(0))
                        .await
                        .map_err(SpoolError::Io)?;
                    let mut buf = Vec::with_capacity(self.len);
                    file.read_to_end(&mut buf).await.map_err(SpoolError::Io)?;
                    *inspect = Some(buf);
                }
                Ok(inspect.as_deref().expect("inspect buffer just filled"))
            }
        }
    }

    /// Next chunk for `request_body_filter`. First call after inspection rewinds
    /// a file-backed handle. Empty spool yields a single `None`.
    pub async fn next_replay_chunk(&mut self) -> Result<Option<Bytes>, SpoolError> {
        if self.replay_done {
            return Ok(None);
        }
        match &mut self.storage {
            Storage::Memory(buf) => {
                self.replay_done = true;
                if buf.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(Bytes::copy_from_slice(buf)))
                }
            }
            Storage::File { file, inspect, .. } => {
                inspect.take();
                if self.replay_at == 0 {
                    file.seek(SeekFrom::Start(0))
                        .await
                        .map_err(SpoolError::Io)?;
                }
                let mut buf = vec![0_u8; REPLAY_CHUNK.min(self.len.saturating_sub(self.replay_at as usize).max(1))];
                let read = file.read(&mut buf).await.map_err(SpoolError::Io)?;
                if read == 0 {
                    self.replay_done = true;
                    return Ok(None);
                }
                buf.truncate(read);
                self.replay_at += read as u64;
                if self.replay_at as usize >= self.len {
                    self.replay_done = true;
                }
                Ok(Some(Bytes::from(buf)))
            }
        }
    }

    pub fn replay_finished(&self) -> bool {
        self.replay_done
    }
}

impl Drop for SpoolHandle {
    fn drop(&mut self) {
        self.runtime.bytes.release(self.reserved);
        self.reserved = 0;
        if self.holds_file_slot {
            self.runtime.files.release();
            self.holds_file_slot = false;
        }
        if let Storage::File { path, .. } = &self.storage {
            let _ = std::fs::remove_file(path);
        }
    }
}

pub fn dir_from_env() -> PathBuf {
    std::env::var("SPOOL_DIR")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DIR))
}

/// No-op when the Config has no `max_decoded_body`. Otherwise the directory
/// must already exist; leftover `spool-*` files are deleted; any other name
/// refuses boot.
pub fn boot(config: &Config) -> Result<(), String> {
    if !config.has_spool_routes() {
        return Ok(());
    }
    prepare(&dir_from_env())
}

pub fn prepare(dir: &Path) -> Result<(), String> {
    match std::fs::metadata(dir) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => {
            return Err(format!(
                "SPOOL_DIR {} existe mas não é um diretório",
                dir.display()
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!(
                "SPOOL_DIR {} não existe; crie-o (tmpfiles.d) antes de ligar max_decoded_body",
                dir.display()
            ));
        }
        Err(error) => {
            return Err(format!("SPOOL_DIR {}: {error}", dir.display()));
        }
    }

    let entries = std::fs::read_dir(dir)
        .map_err(|error| format!("SPOOL_DIR {}: {error}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("SPOOL_DIR {}: {error}", dir.display()))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("spool-") {
            return Err(format!(
                "SPOOL_DIR {} não é dedicado: encontrou {name}",
                dir.display()
            ));
        }
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| format!("{}: {error}", path.display()))?;
        if !file_type.is_file() {
            return Err(format!(
                "SPOOL_DIR {} contém {name} que não é um ficheiro spool-*",
                dir.display()
            ));
        }
        std::fs::remove_file(&path)
            .map_err(|error| format!("falha a apagar leftover {}: {error}", path.display()))?;
    }
    Ok(())
}

fn unique_spool_path(dir: &Path) -> PathBuf {
    let seq = FILE_SEQ.fetch_add(1, Ordering::Relaxed);
    dir.join(format!(
        "spool-{}-{seq}-{}",
        std::process::id(),
        now_nanos()
    ))
}

fn now_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_dir(label: &str) -> PathBuf {
        let nanos = now_nanos();
        let dir = std::env::temp_dir().join(format!(
            "ferroada-spool-{}-{}-{label}",
            std::process::id(),
            nanos
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn prepare_refuses_missing_directory_without_creating_it() {
        let dir = std::env::temp_dir().join(format!(
            "ferroada-spool-missing-{}-{}",
            std::process::id(),
            now_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        let error = prepare(&dir).unwrap_err();
        assert!(!dir.exists(), "prepare must not mkdir");
        assert!(error.contains("não existe"), "{error}");
    }

    #[test]
    fn prepare_wipes_spool_star_and_refuses_other_names() {
        let dir = temp_dir("wipe");
        let leftover = dir.join("spool-leftover");
        fs::write(&leftover, b"pii").unwrap();
        prepare(&dir).unwrap();
        assert!(!leftover.exists());

        fs::write(dir.join("notes.txt"), b"no").unwrap();
        let error = prepare(&dir).unwrap_err();
        assert!(error.contains("não é dedicado"), "{error}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn boot_without_spool_routes_does_not_touch_disk() {
        let config = Config::from_target_url("http://127.0.0.1:9");
        assert!(!config.has_spool_routes());
        boot(&config).unwrap();
    }

    #[tokio::test]
    async fn memory_spool_stays_in_ram_under_ceiling() {
        let runtime = Arc::new(SpoolRuntime::off());
        let mut handle = SpoolHandle::new(MEMORY_CEILING, runtime);
        handle.push(&[b'a'; 1024]).await.unwrap();
        assert!(matches!(handle.storage, Storage::Memory(_)));
        assert_eq!(handle.inspect_bytes().await.unwrap().len(), 1024);
        let chunk = handle.next_replay_chunk().await.unwrap().unwrap();
        assert_eq!(chunk.len(), 1024);
        assert!(handle.next_replay_chunk().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn push_over_max_is_overflow() {
        let runtime = Arc::new(SpoolRuntime::off());
        let mut handle = SpoolHandle::new(4, runtime);
        handle.push(b"abcd").await.unwrap();
        assert!(matches!(
            handle.push(b"e").await.unwrap_err(),
            SpoolError::Overflow
        ));
    }

    #[tokio::test]
    async fn file_spool_is_wiped_on_drop() {
        let dir = temp_dir("drop");
        let runtime = Arc::new(SpoolRuntime {
            dir: Some(dir.clone()),
            bytes: ByteBudget::new(DEFAULT_MAX_BYTES),
            files: FileBudget::new(DEFAULT_MAX_FILES),
        });
        let path = {
            let mut handle = SpoolHandle::new(MEMORY_CEILING + 4096, Arc::clone(&runtime));
            handle
                .push(&vec![b'x'; MEMORY_CEILING + 1])
                .await
                .unwrap();
            match &handle.storage {
                Storage::File { path, .. } => path.clone(),
                Storage::Memory(_) => panic!("expected spill to file"),
            }
        };
        assert!(!path.exists(), "Drop must unlink spool-*");
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn byte_budget_exhaustion_is_503_signal() {
        let runtime = Arc::new(SpoolRuntime {
            dir: None,
            bytes: ByteBudget::new(8),
            files: FileBudget::new(DEFAULT_MAX_FILES),
        });
        let mut handle = SpoolHandle::new(1024, runtime);
        handle.push(b"12345678").await.unwrap();
        assert!(matches!(
            handle.push(b"9").await.unwrap_err(),
            SpoolError::Budget
        ));
    }
}
