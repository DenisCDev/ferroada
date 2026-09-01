#![no_main]

use ferroada::waf::{inflate_for_inspect, inspect_body, inspect_request};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let headers = vec![text.to_string()];
    let _ = inspect_request(&text, &headers, "127.0.0.1");

    for content_type in [
        None,
        Some("application/json"),
        Some("application/x-www-form-urlencoded"),
        Some("multipart/form-data; boundary=fuzz"),
        Some("application/graphql"),
    ] {
        let _ = inspect_body(data, "/fuzz", "127.0.0.1", content_type);
    }

    for encoding in [None, Some("gzip"), Some("deflate"), Some("br")] {
        let inspected = inflate_for_inspect(data, encoding);
        let _ = inspect_body(
            &inspected.bytes,
            "/fuzz",
            "127.0.0.1",
            Some("application/json"),
        );
    }
});
