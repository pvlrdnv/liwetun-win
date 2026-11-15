//! Disposable CI fixture only; no production profiles or credentials.
use std::{env, fs, path::Path};
use trusttunnel_deeplink::{encode, DeepLinkConfig, Protocol};

fn main() {
    assert_eq!(env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
    let directory = env::args().nth(1).expect("fixture directory required");
    let directory = Path::new(&directory);
    let dns_host: std::net::Ipv4Addr = fs::read_to_string(directory.join("dns-host.txt"))
        .expect("task private DNS address")
        .trim()
        .parse()
        .expect("task IPv4 DNS address");
    assert!(dns_host.is_private() && !dns_host.is_loopback());
    let certificate = fs::read(directory.join("cert.der")).expect("synthetic certificate");
    let wrong_certificate = fs::read(directory.join("wrong-cert.der")).expect("synthetic wrong CA");
    for (name, protocol, password, cert) in [
        ("http2", Protocol::Http2, "synthetic-password", &certificate),
        ("http3", Protocol::Http3, "synthetic-password", &certificate),
        (
            "wrong-auth",
            Protocol::Http2,
            "wrong-synthetic",
            &certificate,
        ),
        (
            "wrong-ca",
            Protocol::Http2,
            "synthetic-password",
            &wrong_certificate,
        ),
    ] {
        let config = DeepLinkConfig::builder()
            .hostname("localhost".into())
            .addresses(vec!["127.0.0.1:38443".into()])
            .username("synthetic-user".into())
            .password(password.into())
            .upstream_protocol(protocol)
            .has_ipv6(false)
            .certificate(Some(cert.clone()))
            .dns_upstreams(vec![format!("{dns_host}:38553")])
            .build()
            .expect("fixed synthetic fixture");
        fs::write(
            directory.join(format!("{name}.uri")),
            encode(&config).expect("encode fixture"),
        )
        .expect("write fixture");
    }
}
