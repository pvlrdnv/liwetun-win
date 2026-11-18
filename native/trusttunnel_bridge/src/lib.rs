//! A narrow, non-networking boundary around the official TrustTunnel decoder.
//! Never return credentials, decoded config or upstream errors.
//! Presentation metadata is private UI data and must never enter diagnostics.

use std::{panic, slice, str, sync::Once};
use trusttunnel_deeplink::{decode, Protocol};

const MAX_URI_BYTES: usize = 8192;
const OK: i32 = 0;
const MALFORMED: i32 = 1;
const INSECURE: i32 = 2;
const UNSUPPORTED: i32 = 3;
const INTERNAL: i32 = 4;
static QUIET_PANICS: Once = Once::new();

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct LiwetunTtInfo {
    pub abi_version: u32,
    pub transport: u32,
    pub custom_certificate: u32,
    pub has_ipv6: u32,
}

// Separate ABI: service consumers retain the original 16-byte inspection ABI.
#[repr(C)]
pub struct LiwetunTtPresentation {
    pub abi_version: u32,
    pub name: [u8; 1024],
    pub hostname: [u8; 2048],
    pub addresses: [u8; 8192],
}

fn display_text<const N: usize>(value: &str) -> [u8; N] {
    let mut output = [0; N];
    let mut length = 0;
    for ch in value.chars() {
        // Prevent line/control/bidi spoofing while retaining ordinary Unicode.
        let ch = if ch.is_control()
            || matches!(ch, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        {
            ' '
        } else {
            ch
        };
        let mut encoded = [0; 4];
        let bytes = ch.encode_utf8(&mut encoded).as_bytes();
        if length + bytes.len() >= N {
            break;
        }
        output[length..length + bytes.len()].copy_from_slice(bytes);
        length += bytes.len();
    }
    output
}

/// Private presentation only. Never serialize this output into a support report.
///
/// # Safety
/// Same input rules as liwetun_tt_inspect; output must be writable and aligned.
#[no_mangle]
pub unsafe extern "C" fn liwetun_tt_presentation(
    input: *const u8,
    length: usize,
    output: *mut LiwetunTtPresentation,
) -> i32 {
    if output.is_null() {
        return MALFORMED;
    }
    output.write_bytes(0, 1);
    let mut info = LiwetunTtInfo::default();
    let status = liwetun_tt_inspect(input, length, &mut info);
    if status != OK {
        return status;
    }
    let outcome = panic::catch_unwind(|| {
        let uri = str::from_utf8(slice::from_raw_parts(input, length)).map_err(|_| MALFORMED)?;
        let config = decode(uri).map_err(|_| MALFORMED)?;
        Ok::<_, i32>(LiwetunTtPresentation {
            abi_version: 1,
            name: display_text(config.name.as_deref().unwrap_or("")),
            hostname: display_text(config.hostname.as_deref().unwrap_or("")),
            addresses: display_text(&config.addresses.join(", ")),
        })
    });
    match outcome {
        Ok(Ok(presentation)) => {
            output.write(presentation);
            OK
        }
        Ok(Err(reason)) => reason,
        Err(_) => INTERNAL,
    }
}

fn inspect(uri: &str) -> Result<LiwetunTtInfo, i32> {
    if uri.len() > MAX_URI_BYTES || !uri.starts_with("tt://?") || uri.contains('\0') {
        return Err(MALFORMED);
    }
    let config = decode(uri).map_err(|_| MALFORMED)?;
    if config.skip_verification {
        return Err(INSECURE);
    }
    // Version-2 embedded subscription URLs are a separate transport contract.
    // Never silently fetch them or accept them as a static server profile.
    if config.subscription_url.is_some() {
        return Err(UNSUPPORTED);
    }
    if config.hostname.as_deref().is_none_or(str::is_empty)
        || config.username.as_deref().is_none_or(str::is_empty)
        || config.password.as_deref().is_none_or(str::is_empty)
        || config.addresses.is_empty()
    {
        return Err(MALFORMED);
    }
    Ok(LiwetunTtInfo {
        abi_version: 1,
        transport: match config.upstream_protocol {
            Protocol::Http2 => 2,
            Protocol::Http3 => 3,
        },
        custom_certificate: u32::from(config.certificate.is_some()),
        has_ipv6: u32::from(config.has_ipv6),
    })
}

/// Inspect an explicit-length UTF-8 buffer. The output is always zeroed on error.
///
/// # Safety
/// `input` must reference `length` readable bytes, `output` must reference one
/// writable, aligned LiwetunTtInfo. Neither pointer may be concurrently changed.
#[no_mangle]
pub unsafe extern "C" fn liwetun_tt_inspect(
    input: *const u8,
    length: usize,
    output: *mut LiwetunTtInfo,
) -> i32 {
    if output.is_null() {
        return MALFORMED;
    }
    output.write(LiwetunTtInfo::default());
    if input.is_null() || length == 0 || length > MAX_URI_BYTES {
        return MALFORMED;
    }
    // Rust's default panic hook can expose parser input before catch_unwind.
    // This library owns the app's Rust runtime and has no other Rust consumers.
    QUIET_PANICS.call_once(|| panic::set_hook(Box::new(|_| {})));
    let outcome = panic::catch_unwind(|| {
        let bytes = slice::from_raw_parts(input, length);
        let uri = str::from_utf8(bytes).map_err(|_| MALFORMED)?;
        inspect(uri)
    });
    match outcome {
        Ok(Ok(info)) => {
            output.write(info);
            OK
        }
        Ok(Err(reason)) => reason,
        Err(_) => INTERNAL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trusttunnel_deeplink::{encode, DeepLinkConfig};

    fn synthetic(protocol: Protocol) -> DeepLinkConfig {
        DeepLinkConfig::builder()
            .hostname("node.example.invalid".into())
            .addresses(vec!["192.0.2.1:443".into()])
            .username("SYNTHETIC_USER_CANARY_261115".into())
            .password("SYNTHETIC_PASSWORD_CANARY_261115".into())
            .upstream_protocol(protocol)
            .build()
            .expect("synthetic fixture must encode")
    }

    fn inspect_ffi(bytes: &[u8]) -> (i32, LiwetunTtInfo) {
        let mut info = LiwetunTtInfo {
            abi_version: 99,
            ..Default::default()
        };
        let status = unsafe { liwetun_tt_inspect(bytes.as_ptr(), bytes.len(), &mut info) };
        (status, info)
    }

    #[test]
    fn actual_official_http2_http3_roundtrip() {
        for (protocol, expected) in [(Protocol::Http2, 2), (Protocol::Http3, 3)] {
            let uri = encode(&synthetic(protocol)).expect("synthetic encoding");
            let (status, info) = inspect_ffi(uri.as_bytes());
            assert_eq!(status, OK);
            assert_eq!(info.abi_version, 1);
            assert_eq!(info.transport, expected);
            assert_eq!(info.custom_certificate, 0);
        }
    }

    #[test]
    fn private_presentation_roundtrip_and_error_zeroing() {
        let mut config = synthetic(Protocol::Http2);
        config.name = Some("Тестовый сервер 🌍".into());
        config.addresses.push("[2001:db8::1]:8443".into());
        let uri = encode(&config).expect("synthetic encoding");
        let mut output = std::mem::MaybeUninit::<LiwetunTtPresentation>::uninit();
        let status =
            unsafe { liwetun_tt_presentation(uri.as_ptr(), uri.len(), output.as_mut_ptr()) };
        assert_eq!(status, OK);
        let mut output = unsafe { output.assume_init() };
        let text = |bytes: &[u8]| {
            String::from_utf8(bytes.iter().copied().take_while(|b| *b != 0).collect()).unwrap()
        };
        assert_eq!(output.abi_version, 1);
        assert_eq!(text(&output.name), "Тестовый сервер 🌍");
        assert_eq!(text(&output.hostname), "node.example.invalid");
        assert_eq!(text(&output.addresses), "192.0.2.1:443, [2001:db8::1]:8443");
        for bytes in [
            &output.name[..],
            &output.hostname[..],
            &output.addresses[..],
        ] {
            assert!(!text(bytes).contains("CANARY"));
        }
        let status = unsafe { liwetun_tt_presentation(std::ptr::null(), 0, &mut output) };
        assert_eq!(status, MALFORMED);
        assert_eq!(output.abi_version, 0);
        assert!(output
            .name
            .iter()
            .chain(&output.hostname)
            .chain(&output.addresses)
            .all(|b| *b == 0));
        assert_eq!(std::mem::size_of::<LiwetunTtInfo>(), 16);
        assert_eq!(std::mem::size_of::<LiwetunTtPresentation>(), 11268);
    }

    #[test]
    fn presentation_is_bounded_utf8_without_control_or_bidi_spoofing() {
        assert_eq!(&display_text::<9>("🌍🌍🌍"), "🌍🌍\0".as_bytes());
        let output = display_text::<32>("a\n\r\u{202e}b\u{2069}");
        assert_eq!(&output[..7], b"a   b \0");
    }

    #[test]
    fn tls_bypass_is_rejected() {
        let mut config = synthetic(Protocol::Http2);
        config.skip_verification = true;
        let uri = encode(&config).expect("synthetic encoding");
        let (status, info) = inspect_ffi(uri.as_bytes());
        assert_eq!(status, INSECURE);
        assert_eq!(info.abi_version, 0);
    }

    #[test]
    fn embedded_subscription_is_never_silently_fetched() {
        let mut config = synthetic(Protocol::Http2);
        config.subscription_url = Some("https://feed.example.invalid/synthetic".into());
        let uri = encode(&config).expect("synthetic encoding");
        assert_eq!(inspect_ffi(uri.as_bytes()).0, UNSUPPORTED);
    }

    #[test]
    fn malformed_and_secret_containing_inputs_only_return_codes() {
        for bytes in [
            b"tt://?SYNTHETIC_PASSWORD_CANARY_261115".as_slice(),
            b"tt://?\xff\xfe".as_slice(),
            b"tt://?abc\0SYNTHETIC_PASSWORD_CANARY_261115".as_slice(),
            b"https://example.invalid/secret".as_slice(),
            b"".as_slice(),
        ] {
            let (status, info) = inspect_ffi(bytes);
            assert_eq!(status, MALFORMED);
            assert_eq!(info.abi_version, 0);
            assert_eq!(info.transport, 0);
        }
    }

    #[test]
    fn null_and_oversized_inputs_are_rejected_before_dereference() {
        let mut info = LiwetunTtInfo::default();
        unsafe {
            assert_eq!(
                liwetun_tt_inspect(std::ptr::null(), 1, &mut info),
                MALFORMED
            );
            assert_eq!(
                liwetun_tt_inspect(b"x".as_ptr(), MAX_URI_BYTES + 1, &mut info),
                MALFORMED
            );
            assert_eq!(
                liwetun_tt_inspect(b"x".as_ptr(), 1, std::ptr::null_mut()),
                MALFORMED
            );
        }
    }

    #[test]
    fn deterministic_malformed_buffer_corpus_does_not_unwind() {
        for length in 1..1024 {
            let mut input = b"tt://?".to_vec();
            input.extend((0..length).map(|i| ((i * 29 + length) % 255) as u8));
            let (status, info) = inspect_ffi(&input);
            assert_ne!(status, OK);
            assert_eq!(info.abi_version, 0);
        }
    }
}
