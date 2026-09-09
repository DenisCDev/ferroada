#![no_main]

use ferroada::proxy::BoundedBodyBuffer;
use ferroada::{shield, waf};
use libfuzzer_sys::fuzz_target;
use once_cell::sync::Lazy;
use std::time::Duration;
use tokio::io::{AsyncWriteExt, DuplexStream};
use tokio::runtime::{Builder, Runtime};

static RUNTIME: Lazy<Runtime> =
    Lazy::new(|| Builder::new_current_thread().enable_all().build().unwrap());

fn inspect_semantics(
    method: &str,
    uri: &str,
    headers: impl Iterator<Item = String>,
    body: &[u8],
    chunk_size: usize,
    limit: usize,
) {
    let header_values: Vec<String> = headers.collect();
    let _ = shield::check_method(method, uri, "127.0.0.1", "");
    let _ = shield::check_uri_length(uri, "127.0.0.1", "");
    let _ = waf::inspect_request(uri, &header_values, "127.0.0.1");

    let mut buffered = BoundedBodyBuffer::new(limit);
    let mut complete = true;
    for chunk in body.chunks(chunk_size.max(1)) {
        if !buffered.push(chunk) {
            complete = false;
            break;
        }
    }
    if complete {
        let _ = waf::inspect_body(
            buffered.as_slice(),
            uri,
            "127.0.0.1",
            Some("application/json"),
        );
    }
}

fn fuzz_h1(data: &[u8]) {
    let Some((&control, wire)) = data.split_first() else {
        return;
    };

    let mut headers = [httparse::EMPTY_HEADER; 100];
    let mut request = httparse::Request::new(&mut headers);
    let Ok(status) = request.parse(wire) else {
        return;
    };
    let httparse::Status::Complete(body_offset) = status else {
        return;
    };

    let method = request.method.unwrap_or("");
    let uri = request.path.unwrap_or("");
    let content_lengths: Vec<&httparse::Header<'_>> = request
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("content-length"))
        .collect();
    let transfer_encoding = request
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("transfer-encoding"))
        .collect::<Vec<_>>();
    let transfer_encoding_count = transfer_encoding.len();
    let transfer_encoding = transfer_encoding
        .first()
        .map(|header| String::from_utf8_lossy(header.value));

    let _ = shield::check_headers(request.headers.len(), body_offset, uri, "127.0.0.1");
    let _ = shield::check_method(method, uri, "127.0.0.1", "");
    let _ = shield::check_uri_length(uri, "127.0.0.1", "");
    let _ = shield::check_smuggling(
        !content_lengths.is_empty(),
        content_lengths.len(),
        transfer_encoding_count,
        transfer_encoding.as_deref(),
        uri,
        "127.0.0.1",
        "",
    );
    let body = &wire[body_offset..];
    let chunk_size = usize::from(control & 0x1f).saturating_add(1);
    let limit = usize::from(control >> 5).saturating_mul(body.len().saturating_add(1)) / 7;
    inspect_semantics(
        method,
        uri,
        request
            .headers
            .iter()
            .map(|header| String::from_utf8_lossy(header.value).into_owned()),
        body,
        chunk_size,
        limit,
    );
}

async fn write_h2_input(mut writer: DuplexStream, data: &[u8]) {
    const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    let _ = writer.write_all(PREFACE).await;
    let _ = writer.write_all(data).await;
    let _ = writer.shutdown().await;
}

fn fuzz_h2(data: &[u8]) {
    let payload = &data[..data.len().min(64 * 1024)];
    RUNTIME.block_on(async {
        let capacity = payload.len().saturating_add(24).max(64);
        let (writer, reader) = tokio::io::duplex(capacity);
        let write = write_h2_input(writer, payload);
        let parse = async {
            let Ok(mut connection) = h2::server::handshake(reader).await else {
                return;
            };
            while let Some(result) = connection.accept().await {
                let Ok((request, _respond)) = result else {
                    break;
                };
                let (parts, mut body) = request.into_parts();
                let mut buffered = BoundedBodyBuffer::new(64 * 1024);
                while let Some(chunk) = body.data().await {
                    let Ok(chunk) = chunk else {
                        break;
                    };
                    if !buffered.push(&chunk) {
                        break;
                    }
                }
                inspect_semantics(
                    parts.method.as_str(),
                    parts.uri.path(),
                    parts
                        .headers
                        .values()
                        .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned()),
                    buffered.as_slice(),
                    7,
                    64 * 1024,
                );
            }
        };
        let _ = tokio::time::timeout(Duration::from_millis(5), async {
            tokio::join!(write, parse);
        })
        .await;
    });
}

fuzz_target!(|data: &[u8]| {
    if data.first().is_some_and(|byte| byte & 1 == 0) {
        fuzz_h1(data);
    } else {
        fuzz_h2(data.get(1..).unwrap_or_default());
    }
});
