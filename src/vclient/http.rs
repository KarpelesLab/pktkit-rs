//! Minimal HTTP/1.1 client over the virtual network.
//!
//! Hand-rolled — no third-party HTTP crate. Supports GET/POST with a request
//! builder, and parses status line, headers, and body (Content-Length and
//! `Transfer-Encoding: chunked`). TLS is out of scope (the virtual network is
//! the security boundary); this is plain HTTP suitable for talking to
//! services reachable through the tunnel.

use super::Client;
use crate::time::Instant;
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// A parsed HTTP response.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub reason: String,
    /// Header fields by lowercase name. A field sent more than once maps to
    /// its values joined by `", "`, the list they stand for.
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
    timeout: Duration,
}

/// How long [`Client::http`] waits by default for the connection, the
/// request to go out, and the whole response to arrive.
pub const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(30);

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
            timeout: DEFAULT_HTTP_TIMEOUT,
        })
    }

    /// Bound the whole exchange, from connecting to the last byte of the
    /// response ([`DEFAULT_HTTP_TIMEOUT`] unless set). Name resolution is
    /// bounded separately, by the resolver's own timeout.
    pub fn timeout(mut self, timeout: Duration) -> Request {
        self.timeout = timeout;
        self
    }

    /// Add a request header.
    pub fn header(mut self, name: &str, value: &str) -> Request {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    /// Serialize the request line + headers + body into wire bytes.
    ///
    /// Header names must be tokens and values free of CR, LF and NUL
    /// (RFC 9110 §5.1, §5.5): a line break in either would end the field
    /// early and let the rest pass as fields, or a request, of its own.
    fn serialize(&self) -> io::Result<Vec<u8>> {
        for (k, v) in &self.headers {
            if k.is_empty() || !k.bytes().all(is_tchar) || v.bytes().any(|b| b"\r\n\0".contains(&b))
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid header field {k:?}"),
                ));
            }
        }
        let mut out = Vec::new();
        let _ = write!(out, "{} {} HTTP/1.1\r\n", self.method, self.path);
        let _ = write!(out, "Host: {}\r\n", host_header(&self.host, self.port));
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
        Ok(out)
    }
}

impl Client {
    /// Perform an HTTP request over the virtual network, resolving the host
    /// via the configured DNS servers (or using a literal IP).
    ///
    /// Fails with [`TimedOut`](io::ErrorKind::TimedOut) if the exchange
    /// takes longer than the request's [`timeout`](Request::timeout), so a
    /// server that stalls cannot hold the caller forever.
    pub fn http(&self, req: &Request) -> io::Result<Response> {
        // A request that cannot be sent is refused before any lookup or dial.
        let wire = req.serialize()?;
        let addrs = match req.host.parse::<IpAddr>() {
            Ok(ip) => vec![ip],
            Err(_) => self.resolve(&req.host)?,
        };

        let deadline = Instant::now() + req.timeout;
        let remaining = || {
            deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "HTTP request timed out"))
        };
        // A timed-out read or write reports WouldBlock, as std's do.
        let timed_out = |e: io::Error| {
            if e.kind() == io::ErrorKind::WouldBlock {
                io::Error::new(io::ErrorKind::TimedOut, "HTTP request timed out")
            } else {
                e
            }
        };

        let mut conn = self.dial_any(&addrs, req.port, deadline)?;
        conn.set_write_timeout(Some(remaining()?));
        conn.write_all(&wire).map_err(timed_out)?;

        // Read until the response's own framing says it is complete, or to
        // EOF when it has none (we ask for `Connection: close`).
        let mut reader = ResponseReader::new(req.method.eq_ignore_ascii_case("HEAD"));
        let mut buf = [0u8; 16 * 1024];
        loop {
            conn.set_read_timeout(Some(remaining()?));
            let n = conn.read(&mut buf).map_err(timed_out)?;
            if n == 0 {
                return reader.finish();
            }
            if let Some(resp) = reader.feed(&buf[..n])? {
                return Ok(resp);
            }
        }
    }

    /// Connect to `port` on the first of `addrs` that accepts, in order,
    /// skipping any in a family the client has no address in: a resolver
    /// lists A before AAAA, and an IPv6-only client must still reach a
    /// dual-stack host. Each attempt gets an even share of what is left
    /// before `deadline`, so one blackholed address cannot use it all.
    fn dial_any(
        &self,
        addrs: &[IpAddr],
        port: u16,
        deadline: Instant,
    ) -> io::Result<super::TcpConn> {
        let prefix = crate::L3Device::addr(self);
        let usable: Vec<IpAddr> = addrs
            .iter()
            .copied()
            .filter(|ip| super::tcp::local_ip_for(prefix, *ip).is_some())
            .collect();
        let mut last = io::Error::new(
            io::ErrorKind::NotFound,
            "no address for host in the client's address family",
        );
        for (i, ip) in usable.iter().enumerate() {
            let left = deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "HTTP request timed out"))?;
            let share = left / (usable.len() - i) as u32;
            match self.dial_tcp_timeout(SocketAddr::new(*ip, port), share) {
                Ok(conn) => return Ok(conn),
                Err(e) => last = e,
            }
        }
        Err(last)
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
    let bad = |what: &str| io::Error::new(io::ErrorKind::InvalidInput, format!("bad URL: {what}"));
    // A URI has no spaces or control characters (RFC 3986 §2); here they
    // would land in the request line and the Host field, where a line break
    // starts a field, or a request, the caller never wrote.
    if rest.bytes().any(|b| b <= b' ' || b == 0x7F) {
        return Err(bad("space or control character"));
    }
    // RFC 3986 §3.2: the authority ends at the first '/', '?' or '#'.
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, rest) = rest.split_at(end);
    // The fragment is for the client alone and never goes on the wire.
    let target = rest.split('#').next().unwrap_or("");
    let path = match target {
        "" => "/".to_string(),
        t if t.starts_with('?') => format!("/{t}"),
        t => t.to_string(),
    };
    let authority = authority.rsplit_once('@').map_or(authority, |(_, a)| a);
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        // An IPv6 literal is bracketed so its colons are not read as the port.
        let (host, after) = v6.split_once(']').ok_or_else(|| bad("unclosed '['"))?;
        host.parse::<std::net::Ipv6Addr>()
            .map_err(|_| bad("invalid IPv6 literal"))?;
        let port = match after {
            "" => "",
            p => p.strip_prefix(':').ok_or_else(|| bad("junk after ']'"))?,
        };
        (host, port)
    } else {
        match authority.split_once(':') {
            Some((h, p)) => (h, p),
            None => (authority, ""),
        }
    };
    if host.is_empty() {
        return Err(bad("no host"));
    }
    // An empty port means the default (RFC 3986 §3.2.3).
    let port = match port {
        "" => 80,
        p => p.parse().map_err(|_| bad("invalid port"))?,
    };
    Ok((host.to_string(), port, path))
}

/// A `tchar`, what a token (such as a header name) is made of (RFC 9110
/// §5.6.2).
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// The Host header for `host:port` (RFC 9112 §3.2): the port only when it is
/// not the default, and an IPv6 literal in brackets.
fn host_header(host: &str, port: u16) -> String {
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if port == 80 {
        host
    } else {
        format!("{host}:{port}")
    }
}

/// Largest response head accepted; a peer that never ends its headers must
/// not grow the buffer without bound.
const MAX_HEAD: usize = 64 * 1024;

/// Longest chunk-size or trailer line accepted in a chunked body.
const MAX_CHUNK_LINE: usize = 4096;

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

/// How the body of a response is delimited (RFC 9112 §6.3).
enum Framing {
    /// Exactly this many bytes.
    Length(usize),
    Chunked(Chunked),
    /// Everything until the connection closes.
    ToEof,
}

/// Where a chunked decoder stands.
enum Chunked {
    /// Expecting a chunk-size line.
    Size,
    /// Inside a chunk, with this many data bytes left (then its CRLF).
    Data(usize),
    /// After the last chunk: trailer lines, up to an empty one.
    Trailer,
}

/// An incremental HTTP/1.1 response parser: bytes are fed as they arrive,
/// each one examined a bounded number of times, so reading a large or
/// slowly arriving response costs time linear in its size.
struct ResponseReader {
    head_request: bool,
    buf: Vec<u8>,
    /// Where the header terminator search resumes.
    scan: usize,
    head: Option<(u16, String, BTreeMap<String, String>)>,
    framing: Framing,
    /// Start of the unconsumed body bytes in `buf`.
    pos: usize,
    body: Vec<u8>,
}

impl ResponseReader {
    fn new(head_request: bool) -> ResponseReader {
        ResponseReader {
            head_request,
            buf: Vec::new(),
            scan: 0,
            head: None,
            framing: Framing::ToEof,
            pos: 0,
            body: Vec::new(),
        }
    }

    /// Add received bytes. Returns the response once it is complete.
    fn feed(&mut self, data: &[u8]) -> io::Result<Option<Response>> {
        self.buf.extend_from_slice(data);
        loop {
            if self.head.is_none() && !self.parse_head()? {
                return Ok(None);
            }
            if self.advance_body()? {
                return Ok(Some(self.take()));
            }
            if self.head.is_some() {
                return Ok(None);
            }
            // An interim (1xx) response was skipped; parse the next head.
        }
    }

    /// The connection has closed: the response is complete only if its
    /// framing says so, or if it had none.
    fn finish(mut self) -> io::Result<Response> {
        let eof = |what: &str| io::Error::new(io::ErrorKind::UnexpectedEof, what.to_string());
        if self.head.is_none() {
            return Err(eof("connection closed before the response headers"));
        }
        match self.framing {
            Framing::ToEof => {
                self.body.extend_from_slice(&self.buf[self.pos..]);
                Ok(self.take())
            }
            Framing::Length(_) => Err(eof("connection closed before the whole body arrived")),
            Framing::Chunked(_) => Err(eof("connection closed inside a chunked body")),
        }
    }

    /// Look for the end of the head and parse it. `false` if not there yet.
    fn parse_head(&mut self) -> io::Result<bool> {
        let from = self.scan.saturating_sub(3).max(self.pos);
        let Some(i) = find_subsequence(&self.buf[from..], b"\r\n\r\n") else {
            if self.buf.len() - self.pos > MAX_HEAD {
                return Err(invalid("response headers too large"));
            }
            self.scan = self.buf.len();
            return Ok(false);
        };
        let end = from + i + 4;
        let (status, reason, headers) = parse_head(&self.buf[self.pos..end]).map_err(invalid)?;
        self.pos = end;
        self.scan = end;
        if (100..200).contains(&status) && status != 101 {
            // Interim response (100 Continue, 103 Early Hints): the real one
            // follows.
            return Ok(true);
        }
        let chunked = headers.get("transfer-encoding").is_some_and(|te| {
            te.rsplit(',')
                .next()
                .is_some_and(|last| last.trim().eq_ignore_ascii_case("chunked"))
        });
        self.framing = if self.head_request || status == 204 || status == 304 {
            Framing::Length(0)
        } else if chunked {
            Framing::Chunked(Chunked::Size)
        } else if headers.contains_key("transfer-encoding") {
            Framing::ToEof
        } else if let Some(cl) = headers.get("content-length") {
            Framing::Length(content_length(cl).ok_or_else(|| invalid("bad Content-Length"))?)
        } else {
            Framing::ToEof
        };
        self.head = Some((status, reason, headers));
        Ok(true)
    }

    /// Consume what the framing allows. `true` once the body is complete.
    fn advance_body(&mut self) -> io::Result<bool> {
        if self.head.is_none() {
            return Ok(false); // skipped an interim response
        }
        match &mut self.framing {
            Framing::ToEof => Ok(false),
            Framing::Length(n) => {
                let have = self.buf.len() - self.pos;
                if have < *n {
                    return Ok(false);
                }
                let end = self.pos + *n;
                self.body.extend_from_slice(&self.buf[self.pos..end]);
                self.pos = end;
                Ok(true)
            }
            Framing::Chunked(state) => loop {
                match state {
                    Chunked::Size => {
                        let Some(line) = take_line(&self.buf, &mut self.pos)? else {
                            return Ok(false);
                        };
                        // Chunk extensions follow a ';'.
                        let hex = line.split(|&b| b == b';').next().unwrap_or(&[]);
                        let hex = std::str::from_utf8(hex)
                            .map_err(|_| invalid("bad chunk size"))?
                            .trim();
                        // Hex digits only: from_str_radix would also take a
                        // sign. One that overflows is an error, not a wrap
                        // (RFC 9112 §7.1).
                        if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                            return Err(invalid("bad chunk size"));
                        }
                        let size = usize::from_str_radix(hex, 16)
                            .map_err(|_| invalid("bad chunk size"))?;
                        *state = if size == 0 {
                            Chunked::Trailer
                        } else {
                            Chunked::Data(size)
                        };
                    }
                    Chunked::Data(left) => {
                        let have = self.buf.len() - self.pos;
                        // A size near usize::MAX is legal to announce;
                        // it just never arrives, so saturate.
                        if have < left.saturating_add(2) {
                            // Take what is here so the buffer need not hold
                            // the whole chunk.
                            let take = have.min(*left);
                            self.body
                                .extend_from_slice(&self.buf[self.pos..self.pos + take]);
                            self.pos += take;
                            *left -= take;
                            if *left > 0 || have < 2 + take {
                                self.compact();
                                return Ok(false);
                            }
                        }
                        let end = self.pos + *left;
                        self.body.extend_from_slice(&self.buf[self.pos..end]);
                        if &self.buf[end..end + 2] != b"\r\n" {
                            return Err(invalid("chunk not followed by CRLF"));
                        }
                        self.pos = end + 2;
                        *state = Chunked::Size;
                    }
                    Chunked::Trailer => {
                        let Some(line) = take_line(&self.buf, &mut self.pos)? else {
                            return Ok(false);
                        };
                        if line.is_empty() {
                            return Ok(true);
                        }
                    }
                }
            },
        }
    }

    /// Drop consumed body bytes so a long chunked body does not stay
    /// buffered twice.
    fn compact(&mut self) {
        if self.pos > 64 * 1024 {
            self.buf.drain(..self.pos);
            self.scan = self.scan.saturating_sub(self.pos);
            self.pos = 0;
        }
    }

    fn take(&mut self) -> Response {
        let (status, reason, headers) = self.head.take().expect("head parsed");
        Response {
            status,
            reason,
            headers,
            body: std::mem::take(&mut self.body),
        }
    }
}

/// Take one CRLF-terminated line starting at `*pos`, if it is all there.
fn take_line<'a>(buf: &'a [u8], pos: &mut usize) -> io::Result<Option<&'a [u8]>> {
    let rest = &buf[*pos..];
    match find_subsequence(rest, b"\r\n") {
        Some(i) => {
            *pos += i + 2;
            Ok(Some(&rest[..i]))
        }
        None if rest.len() > MAX_CHUNK_LINE => Err(invalid("chunk line too long")),
        None => Ok(None),
    }
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
            // A repeated field is the list of its values (RFC 9110 §5.3),
            // so a second Content-Length is checked against the first
            // rather than silently replacing it.
            headers
                .entry(k.trim().to_ascii_lowercase())
                .and_modify(|all: &mut String| {
                    all.push_str(", ");
                    all.push_str(v.trim());
                })
                .or_insert_with(|| v.trim().to_string());
        }
    }
    Ok((status, reason, headers))
}

/// The body length a Content-Length value gives (RFC 9112 §6.3): digits
/// only, and a list only when every element is the same length.
fn content_length(value: &str) -> Option<usize> {
    let mut len = None;
    for part in value.split(',') {
        let part = part.trim();
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let n: usize = part.parse().ok()?;
        if len.is_some_and(|l| l != n) {
            return None;
        }
        len = Some(n);
    }
    len
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
    fn url_parsing_ipv6_literals() {
        assert_eq!(
            parse_http_url("http://[::1]/").unwrap(),
            ("::1".into(), 80, "/".into())
        );
        assert_eq!(
            parse_http_url("http://[fd00::1]:8080/x?y=1#frag").unwrap(),
            ("fd00::1".into(), 8080, "/x?y=1".into())
        );
        assert_eq!(
            parse_http_url("http://[::1]").unwrap(),
            ("::1".into(), 80, "/".into())
        );
        assert!(parse_http_url("http://[::1/").is_err());
        assert!(parse_http_url("http://[nope]/").is_err());
        assert!(parse_http_url("http://::1/").is_err());
    }

    #[test]
    fn url_parsing_query_fragment_and_empty_port() {
        assert_eq!(
            parse_http_url("http://h?q").unwrap(),
            ("h".into(), 80, "/?q".into())
        );
        assert_eq!(
            parse_http_url("http://h:/p#f").unwrap(),
            ("h".into(), 80, "/p".into())
        );
        assert!(parse_http_url("http:///p").is_err());
    }

    #[test]
    fn host_header_carries_port_and_brackets() {
        let host = |url: &str| {
            let s = String::from_utf8(Request::get(url).unwrap().serialize().unwrap()).unwrap();
            s.lines()
                .find_map(|l| l.strip_prefix("Host: ").map(str::to_string))
                .unwrap()
        };
        assert_eq!(host("http://h/"), "h");
        assert_eq!(host("http://h:8080/"), "h:8080");
        assert_eq!(host("http://[::1]/"), "[::1]");
        assert_eq!(host("http://[::1]:8080/"), "[::1]:8080");
    }

    #[test]
    fn crlf_cannot_be_smuggled_into_the_request() {
        for url in [
            "http://h/a\r\nX-Evil: 1",
            "http://h/a\nb",
            "http://h/a b",
            "http://h/\0",
            "http://h?q\r\n",
            "http://h\r\nX-Evil: 1/",
        ] {
            assert!(Request::get(url).is_err(), "{url:?}");
        }
        let req = |name: &str, value: &str| Request::get("http://h/").unwrap().header(name, value);
        for (name, value) in [
            ("X-Ok", "a\r\nX-Evil: 1"),
            ("X-Ok", "a\nb"),
            ("X-Ok", "a\rb"),
            ("X-Ok", "a\0b"),
            ("X-Evil: 1\r\nX", "v"),
            ("Bad Name", "v"),
            ("", "v"),
        ] {
            let err = req(name, value).serialize().unwrap_err();
            assert_eq!(
                err.kind(),
                io::ErrorKind::InvalidInput,
                "{name:?}: {value:?}"
            );
        }
        let ok = req("X-Fine", "a\tb; c=\"d\"").serialize().unwrap();
        assert!(
            String::from_utf8(ok)
                .unwrap()
                .contains("X-Fine: a\tb; c=\"d\"\r\n")
        );
    }

    #[test]
    fn request_serialize_includes_host_and_len() {
        let req = Request::post("http://h/p", b"abc".to_vec()).unwrap();
        let s = String::from_utf8(req.serialize().unwrap()).unwrap();
        assert!(s.starts_with("POST /p HTTP/1.1\r\n"));
        assert!(s.contains("Host: h\r\n"));
        assert!(s.contains("Content-Length: 3\r\n"));
        assert!(s.ends_with("\r\n\r\nabc"));
    }

    /// Feed `raw` in pieces of `step` bytes, then close.
    fn read_response(raw: &[u8], step: usize) -> io::Result<Response> {
        let mut r = ResponseReader::new(false);
        for piece in raw.chunks(step) {
            if let Some(resp) = r.feed(piece)? {
                return Ok(resp);
            }
        }
        r.finish()
    }

    #[test]
    fn parse_content_length_response() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        for step in [1, 3, raw.len()] {
            let r = read_response(raw, step).unwrap();
            assert_eq!(r.status, 200);
            assert_eq!(r.reason, "OK");
            assert_eq!(r.body, b"hello");
            assert_eq!(r.header("content-length"), Some("5"));
        }
    }

    #[test]
    fn content_length_is_validated_per_rfc_9112() {
        let with = |cl: &str| {
            let raw = format!("HTTP/1.1 200 OK\r\n{cl}\r\n\r\nhello, world");
            read_response(raw.as_bytes(), raw.len())
        };
        // One value, or a list of identical ones, is a length.
        for ok in [
            "Content-Length: 5",
            "Content-Length: 5, 5",
            "Content-Length: 5\r\nContent-Length: 5",
        ] {
            assert_eq!(with(ok).unwrap().body, b"hello", "{ok:?}");
        }
        // Conflicting values, a sign, or anything but digits is an error.
        for bad in [
            "Content-Length: 5\r\nContent-Length: 12",
            "Content-Length: 5, 12",
            "Content-Length: +5",
            "Content-Length: -5",
            "Content-Length: 0x5",
            "Content-Length: ",
            "Content-Length: 5,",
        ] {
            assert!(with(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn complete_before_eof_when_length_known() {
        let mut r = ResponseReader::new(false);
        let resp = r
            .feed(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
            .unwrap();
        assert_eq!(resp.unwrap().body, b"hi");
    }

    #[test]
    fn parse_chunked_response() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                    5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nTrailer: x\r\n\r\n";
        for step in [1, 2, 7, raw.len()] {
            assert_eq!(read_response(raw, step).unwrap().body, b"hello world");
        }
    }

    #[test]
    fn short_content_length_body_is_an_error() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort";
        let e = read_response(raw, raw.len()).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn incomplete_chunked_body_is_an_error() {
        for raw in [
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel"[..],
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n",
        ] {
            assert!(read_response(raw, raw.len()).is_err());
        }
        let bad = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhiXX0\r\n\r\n";
        assert!(read_response(bad, bad.len()).is_err());
    }

    #[test]
    fn huge_or_signed_chunk_sizes_do_not_overflow() {
        let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        for size in [&b"ffffffffffffffff"[..], b"fffffffffffffffe", b"+5"] {
            let mut raw = head.to_vec();
            raw.extend_from_slice(size);
            raw.extend_from_slice(b"\r\nhello\r\n0\r\n\r\n");
            for step in [1, raw.len()] {
                assert!(read_response(&raw, step).is_err(), "{size:?}");
            }
        }
        // More hex digits than any size can hold.
        let mut raw = head.to_vec();
        raw.extend_from_slice(b"10000000000000000\r\nx\r\n");
        assert!(read_response(&raw, raw.len()).is_err());
    }

    #[test]
    fn eof_before_headers_is_an_error() {
        assert!(read_response(b"HTTP/1.1 200 OK\r\n", 100).is_err());
    }

    #[test]
    fn parse_to_eof_when_no_length() {
        let raw = b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\nbody-to-eof";
        let r = read_response(raw, 4).unwrap();
        assert_eq!(r.body, b"body-to-eof");
    }

    #[test]
    fn interim_and_bodyless_responses() {
        let raw = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n";
        let mut r = ResponseReader::new(false);
        assert_eq!(r.feed(raw).unwrap().unwrap().status, 204);

        let mut r = ResponseReader::new(true);
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n";
        assert!(r.feed(head).unwrap().unwrap().body.is_empty());
    }

    #[test]
    fn large_chunked_body_parses_in_linear_time() {
        let mut raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        let chunk = vec![b'x'; 1000];
        for _ in 0..8000 {
            raw.extend_from_slice(b"3e8\r\n");
            raw.extend_from_slice(&chunk);
            raw.extend_from_slice(b"\r\n");
        }
        raw.extend_from_slice(b"0\r\n\r\n");
        let start = std::time::Instant::now();
        let r = read_response(&raw, 4096).unwrap();
        assert_eq!(r.body.len(), 8_000_000);
        assert!(start.elapsed() < std::time::Duration::from_secs(5));
    }

    /// A server that completes the handshake and then never answers.
    fn silent_server(client: &std::sync::Arc<Client>) {
        use crate::vtcp::{Conn, ConnConfig, segment::Segment};
        use crate::{L3Device, Packet, Protocol};
        use std::net::Ipv4Addr;
        use std::sync::{Arc, Mutex};

        let server: Arc<Mutex<Option<Conn>>> = Arc::new(Mutex::new(None));
        let weak = Arc::downgrade(client);
        client.set_handler(Arc::new(move |pkt: &Packet| {
            let Ok(seg) = Segment::parse(pkt.payload()) else {
                return Ok(());
            };
            let out = {
                let mut srv = server.lock().unwrap();
                match srv.as_mut() {
                    Some(c) => c.handle_segment(&seg),
                    None => {
                        let mut c = Conn::new(
                            ConnConfig::default()
                                .local_port(seg.dst_port)
                                .remote_port(seg.src_port),
                        );
                        let out = c.accept_syn(&seg);
                        *srv = Some(c);
                        out
                    }
                }
            };
            if let Some(client) = weak.upgrade() {
                for s in out {
                    let ip = crate::build::build_ipv4(
                        Ipv4Addr::new(10, 0, 0, 1),
                        Ipv4Addr::new(10, 0, 0, 2),
                        Protocol::TCP,
                        64,
                        &s,
                    );
                    let _ = client.send(Packet::from_slice(&ip));
                }
            }
            Ok(())
        }));
    }

    #[test]
    fn stalled_server_times_out() {
        let client = Client::new(super::super::ClientConfig::default().prefix(
            crate::IpPrefix::new(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)), 24),
        ));
        silent_server(&client);
        let req = Request::get("http://10.0.0.1/")
            .unwrap()
            .timeout(Duration::from_millis(300));
        let start = std::time::Instant::now();
        let err = client.http(&req).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() < Duration::from_secs(3));
    }

    /// Servers listening at `open` complete handshakes; a SYN to any other
    /// address is refused with a RST.
    fn servers_at(client: &std::sync::Arc<Client>, open: Vec<IpAddr>) {
        use crate::vtcp::{Conn, ConnConfig, segment::Segment, segment::flags};
        use crate::{L3Device, Packet, Protocol};
        use std::collections::HashMap;
        use std::sync::{Arc, Mutex};

        let servers: Arc<Mutex<HashMap<IpAddr, Conn>>> = Arc::default();
        let weak = Arc::downgrade(client);
        client.set_handler(Arc::new(move |pkt: &Packet| {
            let (Some(src), Some(dst)) = (pkt.src_addr(), pkt.dst_addr()) else {
                return Ok(());
            };
            let Ok(seg) = Segment::parse(pkt.payload()) else {
                return Ok(());
            };
            let out = if open.contains(&dst) {
                let mut s = servers.lock().unwrap();
                match s.get_mut(&dst) {
                    Some(c) => c.handle_segment(&seg),
                    None => {
                        let mut c = Conn::new(
                            ConnConfig::default()
                                .local_port(seg.dst_port)
                                .remote_port(seg.src_port),
                        );
                        let out = c.accept_syn(&seg);
                        s.insert(dst, c);
                        out
                    }
                }
            } else if seg.has_flag(flags::SYN) {
                let rst = Segment {
                    src_port: seg.dst_port,
                    dst_port: seg.src_port,
                    ack: seg.seq.wrapping_add(1),
                    flags: flags::RST | flags::ACK,
                    ..Default::default()
                };
                vec![rst.marshal()]
            } else {
                Vec::new()
            };
            if let Some(client) = weak.upgrade() {
                for s in out {
                    let ip = crate::build::build_ip(dst, src, Protocol::TCP, 64, &s).unwrap();
                    let _ = client.send(Packet::from_slice(&ip));
                }
            }
            Ok(())
        }));
    }

    #[test]
    fn dials_the_first_reachable_address_of_the_clients_family() {
        let deadline = || Instant::now() + Duration::from_secs(2);
        let v4: IpAddr = "10.0.0.1".parse().unwrap();
        let v6: IpAddr = "fd00::1".parse().unwrap();

        // An IPv6-only client skips the A record listed first.
        let client = Client::new(
            super::super::ClientConfig::default()
                .prefix(crate::IpPrefix::new("fd00::2".parse().unwrap(), 64)),
        );
        servers_at(&client, vec![v4, v6]);
        let conn = client.dial_any(&[v4, v6], 80, deadline()).unwrap();
        assert_eq!(conn.peer_addr().ip(), v6);

        // An address that refuses is followed by the next.
        let client = Client::new(
            super::super::ClientConfig::default()
                .prefix(crate::IpPrefix::new("10.0.0.2".parse().unwrap(), 24)),
        );
        servers_at(&client, vec![v4]);
        let closed: IpAddr = "10.0.0.7".parse().unwrap();
        let conn = client.dial_any(&[closed, v4], 80, deadline()).unwrap();
        assert_eq!(conn.peer_addr().ip(), v4);

        // Nothing in the client's family at all.
        assert!(client.dial_any(&[v6], 80, deadline()).is_err());
    }
}
