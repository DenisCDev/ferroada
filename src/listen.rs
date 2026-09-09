use std::net::SocketAddr;

pub const DEFAULT_PROXY: &str = "0.0.0.0:3000";
pub const DEFAULT_TLS: &str = "0.0.0.0:3443";

/// `PROXY_LISTEN` / `TLS_LISTEN`. Unset uses `default`. Empty is an error.
pub fn from_env(name: &str, default: &str) -> Result<String, String> {
    parse(name, std::env::var(name).ok().as_deref(), default)
}

pub fn parse(name: &str, raw: Option<&str>, default: &str) -> Result<String, String> {
    let value = match raw {
        None => default.to_string(),
        Some(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Err(format!("{name} está vazio; use um endereço como {default}"));
            }
            trimmed.to_string()
        }
    };
    value
        .parse::<SocketAddr>()
        .map_err(|_| format!("{name} inválido ({value}); use um endereço como {default}"))?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_uses_default() {
        assert_eq!(
            parse("PROXY_LISTEN", None, DEFAULT_PROXY).unwrap(),
            "0.0.0.0:3000"
        );
        assert_eq!(
            parse("TLS_LISTEN", None, DEFAULT_TLS).unwrap(),
            "0.0.0.0:3443"
        );
    }

    #[test]
    fn custom_address_is_kept() {
        assert_eq!(
            parse("PROXY_LISTEN", Some("127.0.0.1:3000"), DEFAULT_PROXY).unwrap(),
            "127.0.0.1:3000"
        );
        assert_eq!(
            parse("PROXY_LISTEN", Some("0.0.0.0:80"), DEFAULT_PROXY).unwrap(),
            "0.0.0.0:80"
        );
        assert_eq!(
            parse("TLS_LISTEN", Some("[::]:443"), DEFAULT_TLS).unwrap(),
            "[::]:443"
        );
    }

    #[test]
    fn empty_or_garbage_is_rejected() {
        assert!(parse("PROXY_LISTEN", Some(""), DEFAULT_PROXY).is_err());
        assert!(parse("PROXY_LISTEN", Some("   "), DEFAULT_PROXY).is_err());
        assert!(parse("PROXY_LISTEN", Some("3000"), DEFAULT_PROXY).is_err());
        assert!(parse("PROXY_LISTEN", Some("not-an-addr"), DEFAULT_PROXY).is_err());
        assert!(parse("TLS_LISTEN", Some(":443"), DEFAULT_TLS).is_err());
    }
}
