//! ClientHello fingerprint for abuse identity.
//!
//! This is **not** the public JA4 string. Pingora 0.8.1 does not expose JA4.
//! We hash the ClientHello fields OpenSSL 1.1.1+ gives in the hello callback:
//! legacy version, offered cipher-suite bytes (wire order) and compression
//! methods. The 32-byte random is omitted so the value is stable across
//! connections from the same stack. HTTP-only listeners have no TLS
//! fingerprint; [`http_fingerprint`](crate::abuse::http_fingerprint) still applies.

use async_trait::async_trait;
use once_cell::sync::Lazy;
use openssl::ex_data::Index;
use pingora::listeners::TlsAccept;
use pingora::protocols::tls::TlsRef;
use pingora::tls::ssl::{
    ClientHelloResponse, Ssl, SslAcceptorBuilder, SslAlert, SslFiletype, SslRef,
};
use pingora::listeners::tls::TlsSettings;
use std::any::Any;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

static HELLO_INDEX: Lazy<Index<Ssl, u64>> =
    Lazy::new(|| Ssl::new_ex_index().expect("SSL ex_index for ClientHello fingerprint"));

/// Stable hash stored on the TLS session digest.
#[derive(Clone, Copy, Debug)]
pub struct ClientHelloFingerprint(pub u64);

pub fn install_client_hello(builder: &mut SslAcceptorBuilder) {
    builder.set_client_hello_callback(|ssl: &mut SslRef, _alert: &mut SslAlert| {
        let fingerprint = hash_client_hello(ssl);
        ssl.set_ex_data(*HELLO_INDEX, fingerprint);
        Ok(ClientHelloResponse::SUCCESS)
    });
}

pub fn from_ssl(ssl: &SslRef) -> Option<u64> {
    ssl.ex_data(*HELLO_INDEX).copied()
}

pub fn from_session_digest(digest: Option<&pingora::protocols::Digest>) -> Option<u64> {
    digest
        .and_then(|digest| digest.ssl_digest.as_ref())
        .and_then(|ssl| ssl.extension.get::<ClientHelloFingerprint>())
        .map(|fp| fp.0)
}

fn hash_client_hello(ssl: &SslRef) -> u64 {
    let mut hasher = DefaultHasher::new();
    if let Some(version) = ssl.client_hello_legacy_version() {
        format!("{version:?}").hash(&mut hasher);
    }
    if let Some(ciphers) = ssl.client_hello_ciphers() {
        ciphers.hash(&mut hasher);
    }
    if let Some(compression) = ssl.client_hello_compression_methods() {
        compression.hash(&mut hasher);
    }
    hasher.finish()
}

pub struct HelloFingerprint;

#[async_trait]
impl TlsAccept for HelloFingerprint {
    async fn handshake_complete_callback(
        &self,
        tls_ref: &TlsRef,
    ) -> Option<Arc<dyn Any + Send + Sync>> {
        from_ssl(tls_ref).map(|fp| Arc::new(ClientHelloFingerprint(fp)) as Arc<dyn Any + Send + Sync>)
    }
}

pub fn proxy_tls_settings(cert_path: &str, key_path: &str) -> Result<TlsSettings, String> {
    let mut settings = TlsSettings::with_callbacks(Box::new(HelloFingerprint))
        .map_err(|error| format!("TLS do proxy: {error}"))?;
    settings
        .set_certificate_chain_file(cert_path)
        .map_err(|error| format!("falha a ler o certificado TLS {cert_path}: {error}"))?;
    settings
        .set_private_key_file(key_path, SslFiletype::PEM)
        .map_err(|error| format!("falha a ler a chave TLS {key_path}: {error}"))?;
    install_client_hello(&mut settings);
    Ok(settings)
}

#[cfg(test)]
mod tests {
    use super::hash_client_hello;
    use pingora::tls::ssl::{Ssl, SslContext, SslMethod};

    #[test]
    fn hello_hash_is_defined_outside_callback_as_empty_fields() {
        let ctx = SslContext::builder(SslMethod::tls_client()).unwrap().build();
        let ssl = Ssl::new(&ctx).unwrap();
        let a = hash_client_hello(&ssl);
        let b = hash_client_hello(&ssl);
        assert_eq!(a, b);
    }
}
