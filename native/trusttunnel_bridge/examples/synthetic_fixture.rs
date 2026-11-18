//! Explicit test-only artifact generator. Never accepts real profile input.
use std::{env, fs};
use trusttunnel_deeplink::{encode, DeepLinkConfig, Protocol};

fn main() {
    let destination = env::args().nth(1).expect("output path required");
    let mut entries = Vec::new();
    for (key, protocol, insecure) in [
        ("SYNTHETIC_TT_HTTP2", Protocol::Http2, false),
        ("SYNTHETIC_TT_HTTP3", Protocol::Http3, false),
        ("SYNTHETIC_TT_INSECURE", Protocol::Http2, true),
        ("SYNTHETIC_TT_SERVICE_LOCAL", Protocol::Http2, false),
    ] {
        let config = DeepLinkConfig::builder()
            .name(Some("Тестовый сервер".into()))
            .hostname("node.example.invalid".into())
            .addresses(vec![if key == "SYNTHETIC_TT_SERVICE_LOCAL" {
                "127.0.0.1:9".into()
            } else {
                "192.0.2.1:443".into()
            }])
            .username("SYNTHETIC_NATIVE_USER_261115".into())
            .password("SYNTHETIC_NATIVE_PASSWORD_261115".into())
            .upstream_protocol(protocol)
            .skip_verification(insecure)
            .build()
            .expect("fixed synthetic fixture must build");
        let uri = encode(&config).expect("fixed synthetic fixture must encode");
        // URI alphabet is restricted to base64url, so JSON escaping is trivial.
        assert!(
            uri.starts_with("tt://?")
                && uri[6..]
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
        entries.push(format!("\"{key}\":\"{uri}\""));
    }
    fs::write(destination, format!("{{{}}}", entries.join(","))).expect("write fixture file");
}
