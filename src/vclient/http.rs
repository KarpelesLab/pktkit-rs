//! Minimal HTTP/1.1 client over the virtual network.
//!
//! Hand-rolled — no third-party HTTP crate. Supports GET/POST with a request
//! builder, and parses status line, headers, and body (Content-Length and
//! `Transfer-Encoding: chunked`). TLS is out of scope (the virtual network is
//! the security boundary); this is plain HTTP suitable for talking to
//! services reachable through the tunnel.

use super::Client;
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr};

/// A parsed HTTP response.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub reason: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl Response {
    /// Body decoded as UTF-8 (lossy).
    pub fn text(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.body)
    }

    /// Case-insensitive header lookup.
    pub fn header(&self, name: &str) -> Option<&str> {
        let lower = name.to_ascii_lowercase();
        self.headers.get(&lower).map(|s| s.as_str())
    }
}

/// A pending HTTP request.
#[derive(Debug, Clone)]
pub struct Request {
    method: String,
    host: String,
    port: u16,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    /// Start a GET request to `url` (form: `http://host[:port]/path`).
    pub fn get(url: &str) -> io::Result<Request> {
        Self::new("GET", url)
    }

    /// Start a POST request to `url`.
    pub fn post(url: &str, body: impl Into<Vec<u8>>) -> io::Result<Request> {
        let mut r = Self::new("POST", url)?;
        r.body = body.into();
        Ok(r)
    }

    fn new(method: &str, url: &str) -> io::Result<Request> {
        let (host, port, path) = parse_http_url(url)?;
        Ok(Request {
            method: method.to_string(),
            host,
            port,
            path,
            headers: Vec::new(),
            body: Vec::new(),
        })
    }

    /// Add a request header.
    pub fn header(mut self, name: &str, value: &str) -> Request {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    /// Serialize the request line + headers + body into wire bytes.
    fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let _ = write!(out, "{} {} HTTP/1.1\r\n", self.method, self.path);
        let _ = write!(out, "Host: {}\r\n", self.host);
        let mut have_len = false;
        let mut have_conn = false;
        for (k, v) in &self.headers {
            if k.eq_ignore_ascii_case("content-length") {
                have_len = true;
            }
            if k.eq_ignore_ascii_case("connection") {
                have_conn = true;
            }
            let _ = write!(out, "{k}: {v}\r\n");
        }
        if !self.body.is_empty() && !have_len {
            let _ = write!(out, "Content-Length: {}\r\n", self.body.len());
        }
        if !have_conn {
            out.extend_from_slice(b"Connection: close\r\n");
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out
    }
}

impl Client {
    /// Perform an HTTP request over the virtual network, resolving the host
    /// via the configured DNS servers (or using a literal IP).
    pub fn http(&self, req: &Request) -> io::Result<Response> {
        // Resolve host → IP.
        let ip: IpAddr = match req.host.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => *self
                .resolve(&req.host)?
                .first()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address for host"))?,
        };

        let mut conn = self.dial_tcp(SocketAddr::new(ip, req.port))?;
        conn.write_all(&req.serialize())?;

        // Read the whole response (Connection: close → read to EOF).
        let mut raw = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = conn.read(&mut buf)?;
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&buf[..n]);
            // If we already have a full response with known length, stop early.
            if let Some(resp) = try_parse_complete(&raw) {
                return Ok(resp);
            }
        }
        parse_response(&raw)
    }

    /// Convenience: GET `url`.
    pub fn http_get(&self, url: &str) -> io::Result<Response> {
        self.http(&Request::get(url)?)
    }
}

// --- URL + response parsing ------------------------------------------------

fn parse_http_url(url: &str) -> io::Result<(String, u16, String)> {
    let rest = url.strip_prefix("http://").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "only http:// URLs are supported",
        )
    })?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad port"))?,
        ),
        None => (authority.to_string(), 80),
    };
    Ok((host, port, path.to_string()))
}

/// If `raw` contains a complete response (headers + full body per
/// Content-Length / chunked), parse it; otherwise return None.
fn try_parse_complete(raw: &[u8]) -> Option<Response> {
    let header_end = find_subsequence(raw, b"\r\n\r\n")? + 4;
    let head = &raw[..header_end];
    let (status, reason, headers) = parse_head(head).ok()?;

    if let Some(te) = headers.get("transfer-encoding") {
        if te.eq_ignore_ascii_case("chunked") {
            let body = decode_chunked(&raw[header_end..])?;
            return Some(Response {
                status,
                reason,
                headers,
                body,
            });
        }
    }
    if let Some(cl) = headers.get("content-length") {
        let len: usize = cl.trim().parse().ok()?;
        if raw.len() >= header_end + len {
            return Some(Response {
                status,
                reason,
                headers,
                body: raw[header_end..header_end + len].to_vec(),
            });
        }
        return None; // more body to come
    }
    None // no length info — must read to EOF
}

/// Parse a full response buffer (called after EOF for Connection: close).
fn parse_response(raw: &[u8]) -> io::Result<Response> {
    let header_end = find_subsequence(raw, b"\r\n\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no header terminator"))?
        + 4;
    let (status, reason, headers) = parse_head(&raw[..header_end])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let body = if headers
        .get("transfer-encoding")
        .map(|te| te.eq_ignore_ascii_case("chunked"))
        .unwrap_or(false)
    {
        decode_chunked(&raw[header_end..])
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad chunked body"))?
    } else {
        raw[header_end..].to_vec()
    };

    Ok(Response {
        status,
        reason,
        headers,
        body,
    })
}

fn parse_head(head: &[u8]) -> Result<(u16, String, BTreeMap<String, String>), &'static str> {
    let text = std::str::from_utf8(head).map_err(|_| "non-utf8 headers")?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().ok_or("empty response")?;
    // HTTP/1.1 200 OK
    let mut sp = status_line.splitn(3, ' ');
    let _version = sp.next().ok_or("no version")?;
    let status: u16 = sp
        .next()
        .ok_or("no status")?
        .parse()
        .map_err(|_| "bad status")?;
    let reason = sp.next().unwrap_or("").to_string();

    let mut headers = BTreeMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    Ok((status, reason, headers))
}

fn decode_chunked(mut data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let nl = find_subsequence(data, b"\r\n")?;
        let size_str = std::str::from_utf8(&data[..nl]).ok()?;
        // Chunk size may carry extensions after ';'.
        let size_hex = size_str.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16).ok()?;
        data = &data[nl + 2..];
        if size == 0 {
            break;
        }
        if data.len() < size {
            return None;
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size..];
        // Skip trailing CRLF after the chunk data.
        if data.len() >= 2 {
            data = &data[2..];
        }
    }
    Some(out)
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_parsing() {
        assert_eq!(
            parse_http_url("http://example.com/foo").unwrap(),
            ("example.com".into(), 80, "/foo".into())
        );
        assert_eq!(
            parse_http_url("http://10.0.0.1:8080").unwrap(),
            ("10.0.0.1".into(), 8080, "/".into())
        );
        assert!(parse_http_url("https://x/").is_err());
    }

    #[test]
    fn request_serialize_includes_host_and_len() {
        let req = Request::post("http://h/p", b"abc".to_vec()).unwrap();
        let s = String::from_utf8(req.serialize()).unwrap();
        assert!(s.starts_with("POST /p HTTP/1.1\r\n"));
        assert!(s.contains("Host: h\r\n"));
        assert!(s.contains("Content-Length: 3\r\n"));
        assert!(s.ends_with("\r\n\r\nabc"));
    }

    #[test]
    fn parse_content_length_response() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let r = try_parse_complete(raw).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.reason, "OK");
        assert_eq!(r.body, b"hello");
        assert_eq!(r.header("content-length"), Some("5"));
    }

    #[test]
    fn parse_chunked_response() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                    5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let r = try_parse_complete(raw).unwrap();
        assert_eq!(r.body, b"hello world");
    }

    #[test]
    fn incomplete_content_length_returns_none() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort";
        assert!(try_parse_complete(raw).is_none());
    }

    #[test]
    fn parse_to_eof_when_no_length() {
        let raw = b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\nbody-to-eof";
        let r = parse_response(raw).unwrap();
        assert_eq!(r.body, b"body-to-eof");
    }
}
