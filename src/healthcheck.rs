use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use std::time::Duration;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_RESPONSE_BYTES: usize = 8192;

/// GET `http://DASHBOARD_BIND:DASHBOARD_PORT/healthz`. Exit 0 of the binary
/// maps to `Ok`; anything else is `Err` (connection, timeout, non-200).
pub fn probe_from_env() -> Result<(), String> {
    let bind = std::env::var("DASHBOARD_BIND").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = std::env::var("DASHBOARD_PORT").unwrap_or_else(|_| "9000".to_string());
    let ip: IpAddr = bind
        .parse()
        .map_err(|_| format!("DASHBOARD_BIND inválido: {bind}"))?;
    let port: u16 = port
        .parse()
        .map_err(|_| format!("DASHBOARD_PORT inválido: {port}"))?;
    probe(SocketAddr::new(ip, port), DEFAULT_TIMEOUT)
}

pub fn probe(addr: SocketAddr, timeout: Duration) -> Result<(), String> {
    let mut stream = TcpStream::connect_timeout(&addr, timeout)
        .map_err(|error| format!("healthcheck: não ligou a {addr}: {error}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| format!("healthcheck: {error}"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|error| format!("healthcheck: {error}"))?;

    let host = host_header(addr);
    let request = format!("GET /healthz HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("healthcheck: escrita falhou: {error}"))?;
    let _ = stream.shutdown(Shutdown::Write);

    let buf = read_limited(&mut stream, MAX_RESPONSE_BYTES)?;
    let text = String::from_utf8_lossy(&buf);
    let status = parse_status(&text)?;
    if status == 200 {
        Ok(())
    } else {
        Err(format!("healthcheck: /healthz devolveu {status}"))
    }
}

fn read_limited(stream: &mut TcpStream, max: usize) -> Result<Vec<u8>, String> {
    let mut buf = vec![0_u8; max];
    let mut filled = 0;
    while filled < max {
        match stream.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                if filled == 0 {
                    return Err("healthcheck: tempo esgotado".to_string());
                }
                break;
            }
            Err(error) => {
                return Err(format!("healthcheck: leitura falhou: {error}"));
            }
        }
    }
    buf.truncate(filled);
    Ok(buf)
}

fn host_header(addr: SocketAddr) -> String {
    match addr {
        SocketAddr::V4(v4) => v4.to_string(),
        SocketAddr::V6(v6) => format!("[{}]:{}", v6.ip(), v6.port()),
    }
}

fn parse_status(response: &str) -> Result<u16, String> {
    let first = response
        .lines()
        .next()
        .ok_or_else(|| "healthcheck: resposta HTTP vazia".to_string())?;
    let mut parts = first.split_whitespace();
    let version = parts
        .next()
        .ok_or_else(|| "healthcheck: status HTTP malformado".to_string())?;
    if !version.starts_with("HTTP/") {
        return Err("healthcheck: resposta não é HTTP".to_string());
    }
    let code = parts
        .next()
        .ok_or_else(|| "healthcheck: status HTTP malformado".to_string())?;
    code.parse()
        .map_err(|_| "healthcheck: status HTTP malformado".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn parse_status_reads_code() {
        assert_eq!(parse_status("HTTP/1.1 200 OK\r\n\r\nok\n").unwrap(), 200);
        assert_eq!(parse_status("HTTP/1.0 503 nope").unwrap(), 503);
        assert!(parse_status("").is_err());
        assert!(parse_status("not http").is_err());
    }

    #[test]
    fn probe_ok_on_200_healthz() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0_u8; 1024];
            let n = stream.read(&mut buf).unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..n]);
            assert!(request.starts_with("GET /healthz HTTP/1.1"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n")
                .unwrap();
        });
        probe(addr, Duration::from_secs(2)).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn probe_err_on_non_200() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0_u8; 512];
            let _ = stream.read(&mut buf);
            stream
                .write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .unwrap();
        });
        let err = probe(addr, Duration::from_secs(2)).unwrap_err();
        assert!(err.contains("503"), "{err}");
        server.join().unwrap();
    }

    #[test]
    fn probe_err_when_nothing_listens() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        assert!(probe(addr, Duration::from_millis(200)).is_err());
    }
}
