#![no_main]

use ferroada::dlp;
use ferroada::proxy::BoundedBodyBuffer;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let content_types = [
        "text/plain",
        "application/json",
        "text/event-stream",
        "application/grpc",
        "application/octet-stream",
    ];
    let encodings = ["identity", "gzip", "deflate", "br"];
    let content_type = content_types[data[0] as usize % content_types.len()];
    let encoding = encodings[data[0] as usize % encodings.len()];
    let body = &data[1..];

    let _ = dlp::can_inspect(Some(content_type), Some(encoding));
    let _ = dlp::sanitize_body(body, Some(content_type));
    let _ = dlp::sanitize_encoded_body(body, Some(content_type), Some(encoding), 256 * 1024);

    let limit = usize::from(data[0]).saturating_mul(body.len().saturating_add(1)) / 255;
    let chunk_size = usize::from(data[0] & 0x1f).saturating_add(1);
    let mut buffered = BoundedBodyBuffer::new(limit);
    let mut complete = true;
    for chunk in body.chunks(chunk_size) {
        if !buffered.push(chunk) {
            complete = false;
            break;
        }
    }
    if complete {
        let _ = dlp::sanitize_encoded_body(
            buffered.as_slice(),
            Some(content_type),
            Some(encoding),
            256 * 1024,
        );
    }
});
