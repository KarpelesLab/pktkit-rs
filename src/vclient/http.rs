//! Minimal HTTP/1.1 client over the virtual network.
//!
//! Hand-rolled — no third-party HTTP crate. Supports GET/POST with a request
//! builder, and parses status line, headers, and body (Content-Length and
//! `Transfer-Encoding: chunked`). TLS is out of scope (the virtual network is
//! the security boundary); this is plain HTTP suitable for talking to
//! services reachable through the tunnel. The connection crosses the virtual
//! network, but a host name is resolved first with
//! [`Client::resolve`], from the host's own sockets.

use super::Client;
use crate::time::Instant;
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// A parsed HTTP response.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Response {
    pub status: u16,
    pub reason: String,
    /// Header fields by lowercase name. A field sent more than once maps to
    /// its values joined by `", "`, the list they stand for — except
    /// `set-cookie`, which maps to its last value: see `set_cookies`.
    pub headers: BTreeMap<String, String>,
    /// Every `Set-Cookie` field, in order. Cookies cannot be joined into
    /// one list (their values contain commas, as in `Expires=`), so RFC 9110
    /// §5.3 keeps them apart.
    pub set_cookies: Vec<String>,
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
    max_response_body: usize,
}

/// How long [`Client::http`] waits by default for the connection, the
/// request to go out, and the whole response to arrive.
pub const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// The largest response body [`Client::http`] accepts by default. The body
/// is held in memory whole, so what a server may send has to stop somewhere.
pub const DEFAULT_MAX_RESPONSE_BODY: usize = 64 << 20;

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
            max_response_body: DEFAULT_MAX_RESPONSE_BODY,
        })
    }

    /// Bound the whole exchange, from connecting to the last byte of the
    /// response ([`DEFAULT_HTTP_TIMEOUT`] unless set). Name resolution is
    /// bounded separately, by the resolver's own timeout.
    pub fn timeout(mut self, timeout: Duration) -> Request {
        self.timeout = timeout;
        self
    }

    /// Refuse a response whose body is longer than `max` bytes (after
    /// chunked decoding) with [`InvalidData`](io::ErrorKind::InvalidData)
    /// ([`DEFAULT_MAX_RESPONSE_BODY`] unless set).
    pub fn max_response_body(mut self, max: usize) -> Request {
        self.max_response_body = max;
        self
    }

    /// Add a request header. A `Host` header replaces the one the URL gives.
    ///
    /// The body's framing is the library's: it always sends the body whole,
    /// after a `Content-Length` of its own. A `Content-Length` added here
    /// must therefore be the body's length, and `Transfer-Encoding` cannot
    /// be added at all; the request then fails with
    /// [`InvalidInput`](io::ErrorKind::InvalidInput) when sent, since a
    /// server would read the body some other way than it goes out.
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
        // A caller's own Host replaces ours: a request with two is one a
        // server must reject (RFC 9112 §3.2).
        if !self
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("host"))
        {
            let _ = write!(out, "Host: {}\r\n", host_header(&self.host, self.port));
        }
        let framing = |what: &str| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{what}: the body is sent whole, after its Content-Length"),
            )
        };
        let mut have_len = false;
        let mut have_conn = false;
        for (k, v) in &self.headers {
            // The body goes out as is, so a Transfer-Encoding would have the
            // server decode what was never encoded, and a Content-Length
            // other than the body's would have it take part of the body, or
            // the next request, for this one's (RFC 9112 §6.1, §6.2).
            if k.eq_ignore_ascii_case("transfer-encoding") {
                return Err(framing("Transfer-Encoding cannot be set"));
            }
            if k.eq_ignore_ascii_case("content-length") {
                if content_length(v) != Some(self.body.len()) {
                    return Err(framing("Content-Length is not the body's length"));
                }
                have_len = true;
            }
            if k.eq_ignore_ascii_case("connection") {
                have_conn = true;
            }
            let _ = write!(out, "{k}: {v}\r\n");
        }
        // A method that gives content a meaning gets a Content-Length even
        // for an empty body (RFC 9110 §8.6), so the server knows there is
        // none rather than waiting for it; one that does not, only when
        // there is a body.
        let expects_content = ["POST", "PUT", "PATCH"]
            .iter()
            .any(|m| self.method.eq_ignore_ascii_case(m));
        if !have_len && (!self.body.is_empty() || expects_content) {
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

        // A timeout too long for an Instant to reach (`Duration::MAX`)
        // would panic when added: it is no deadline at all.
        let deadline = Instant::now().checked_add(req.timeout);
        let remaining = || super::time_left(deadline, "HTTP request timed out");
        // A timed-out read or write reports WouldBlock, as std's do.
        let timed_out = |e: io::Error| {
            if e.kind() == io::ErrorKind::WouldBlock {
                io::Error::new(io::ErrorKind::TimedOut, "HTTP request timed out")
            } else {
                e
            }
        };

        let conn = self.dial_any(&addrs, req.port, deadline)?;
        // Not `write_all`: a write that hits its timeout returns what it
        // got out so far, and the next would start a timeout of its own, so
        // a peer that keeps its window just ajar could stretch the send
        // forever. Each write gets only what is left of the deadline.
        let mut sent = 0;
        while sent < wire.len() {
            conn.set_write_timeout(remaining()?);
            match conn.write(&wire[sent..]).map_err(timed_out)? {
                0 => return Err(io::ErrorKind::WriteZero.into()),
                n => sent += n,
            }
        }

        // Read until the response's own framing says it is complete, or to
        // EOF when it has none (we ask for `Connection: close`).
        let mut reader = ResponseReader::new(
            req.method.eq_ignore_ascii_case("HEAD"),
            req.max_response_body,
        );
        let mut buf = [0u8; 16 * 1024];
        loop {
            conn.set_read_timeout(remaining()?);
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
    /// before `deadline`, so one blackholed address cannot use it all;
    /// without one, each waits until its handshake succeeds or gives up.
    fn dial_any(
        &self,
        addrs: &[IpAddr],
        port: u16,
        deadline: Option<Instant>,
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
            let share = match super::time_left(deadline, "HTTP request timed out")? {
                Some(left) => left / (usable.len() - i) as u32,
                None => Duration::MAX,
            };
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

/// Most trailer lines accepted after a chunked body: each is bounded by
/// [`MAX_CHUNK_LINE`], but a peer could otherwise send them forever.
const MAX_TRAILERS: usize = 100;

/// Most interim (1xx) responses accepted before the final one, for the same
/// reason.
const MAX_INTERIM: usize = 16;

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

fn too_large() -> io::Error {
    invalid("response body too large")
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

/// Append `data` to `body`, whose length the caller keeps within `max`.
/// Growth still doubles, for linear time, but stops at `max`: left to
/// `Vec`'s own doubling, a body just past half the limit would take twice
/// the limit in capacity, and the limit is what bounds the memory a
/// server can make the client hold.
fn grow_body(body: &mut Vec<u8>, data: &[u8], max: usize) {
    let need = body.len() + data.len();
    if need > body.capacity() {
        let target = body
            .capacity()
            .saturating_mul(2)
            .max(need)
            .min(max.max(need));
        body.reserve_exact(target - body.len());
    }
    body.extend_from_slice(data);
}

/// An incremental HTTP/1.1 response parser: bytes are fed as they arrive,
/// each one examined a bounded number of times, so reading a large or
/// slowly arriving response costs time linear in its size.
///
/// Consumed bytes are dropped from `buf` after every feed, so it holds only
/// what is not yet complete (a partial head or line); the body is kept once,
/// in `body`, and bounded by `max_body`.
struct ResponseReader {
    head_request: bool,
    max_body: usize,
    /// Interim responses skipped, and trailer lines read.
    interim: usize,
    trailers: usize,
    buf: Vec<u8>,
    /// Where the header terminator search resumes.
    scan: usize,
    head: Option<Head>,
    framing: Framing,
    /// Start of the unconsumed body bytes in `buf`.
    pos: usize,
    body: Vec<u8>,
}

impl ResponseReader {
    fn new(head_request: bool, max_body: usize) -> ResponseReader {
        ResponseReader {
            head_request,
            max_body,
            interim: 0,
            trailers: 0,
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
        let done = self.advance();
        self.compact();
        done
    }

    fn advance(&mut self) -> io::Result<Option<Response>> {
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
            // Every byte has gone into the body as it arrived.
            Framing::ToEof => Ok(self.take()),
            Framing::Length(_) => Err(eof("connection closed before the whole body arrived")),
            Framing::Chunked(_) => Err(eof("connection closed inside a chunked body")),
        }
    }

    /// Look for the end of the head and parse it. `false` if not there yet.
    fn parse_head(&mut self) -> io::Result<bool> {
        // Only line feeds past `scan` are new: whether one ends the head
        // depends on the bytes before it, which have not changed.
        let Some(end) = head_end(&self.buf, self.pos, self.scan.max(self.pos)) else {
            if self.buf.len() - self.pos > MAX_HEAD {
                return Err(invalid("response headers too large"));
            }
            self.scan = self.buf.len();
            return Ok(false);
        };
        // One feed can bring a whole oversized head at once.
        if end - self.pos > MAX_HEAD {
            return Err(invalid("response headers too large"));
        }
        let (status, reason, headers, set_cookies) =
            parse_head(&self.buf[self.pos..end]).map_err(invalid)?;
        self.pos = end;
        self.scan = end;
        if (100..200).contains(&status) && status != 101 {
            // Interim response (100 Continue, 103 Early Hints): the real one
            // follows.
            self.interim += 1;
            if self.interim > MAX_INTERIM {
                return Err(invalid("too many interim responses"));
            }
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
            let len = content_length(cl).ok_or_else(|| invalid("bad Content-Length"))?;
            if len > self.max_body {
                return Err(too_large());
            }
            Framing::Length(len)
        } else {
            Framing::ToEof
        };
        self.head = Some((status, reason, headers, set_cookies));
        Ok(true)
    }

    /// Consume what the framing allows. `true` once the body is complete.
    fn advance_body(&mut self) -> io::Result<bool> {
        if self.head.is_none() {
            return Ok(false); // skipped an interim response
        }
        match &mut self.framing {
            Framing::ToEof => {
                let rest = &self.buf[self.pos..];
                if rest.len() > self.max_body - self.body.len() {
                    return Err(too_large());
                }
                grow_body(&mut self.body, rest, self.max_body);
                self.pos = self.buf.len();
                Ok(false)
            }
            Framing::Length(left) => {
                let take = (self.buf.len() - self.pos).min(*left);
                let data = &self.buf[self.pos..self.pos + take];
                grow_body(&mut self.body, data, self.max_body);
                self.pos += take;
                *left -= take;
                Ok(*left == 0)
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
                        // Refused on the announcement: waiting for the data
                        // would only let it fill memory first.
                        if size > self.max_body - self.body.len() {
                            return Err(too_large());
                        }
                        *state = if size == 0 {
                            Chunked::Trailer
                        } else {
                            Chunked::Data(size)
                        };
                    }
                    Chunked::Data(left) => {
                        // Take what is here so the buffer need not hold the
                        // whole chunk.
                        let take = (self.buf.len() - self.pos).min(*left);
                        let data = &self.buf[self.pos..self.pos + take];
                        grow_body(&mut self.body, data, self.max_body);
                        self.pos += take;
                        *left -= take;
                        if *left > 0 {
                            return Ok(false);
                        }
                        // The line break after the data, CRLF or, as for
                        // every line, a bare LF.
                        match &self.buf[self.pos..] {
                            [b'\n', ..] => self.pos += 1,
                            [b'\r', b'\n', ..] => self.pos += 2,
                            [] | [b'\r'] => return Ok(false),
                            _ => return Err(invalid("chunk not followed by a line break")),
                        }
                        *state = Chunked::Size;
                    }
                    Chunked::Trailer => {
                        let Some(line) = take_line(&self.buf, &mut self.pos)? else {
                            return Ok(false);
                        };
                        if line.is_empty() {
                            return Ok(true);
                        }
                        self.trailers += 1;
                        if self.trailers > MAX_TRAILERS {
                            return Err(invalid("too many trailer fields"));
                        }
                    }
                }
            },
        }
    }

    /// Drop the bytes already consumed, so neither a long body nor a run of
    /// interim heads or trailers stays buffered.
    fn compact(&mut self) {
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.scan = self.scan.saturating_sub(self.pos);
            self.pos = 0;
        }
    }

    fn take(&mut self) -> Response {
        let (status, reason, headers, set_cookies) = self.head.take().expect("head parsed");
        Response {
            status,
            reason,
            headers,
            set_cookies,
            body: std::mem::take(&mut self.body),
        }
    }
}

/// Take one line starting at `*pos`, if it is all there, without its line
/// break (see [`strip_cr`]).
fn take_line<'a>(buf: &'a [u8], pos: &mut usize) -> io::Result<Option<&'a [u8]>> {
    let rest = &buf[*pos..];
    match rest.iter().position(|&b| b == b'\n') {
        Some(i) => {
            *pos += i + 1;
            strip_cr(&rest[..i]).map(Some).map_err(invalid)
        }
        None if rest.len() > MAX_CHUNK_LINE => Err(invalid("chunk line too long")),
        None => Ok(None),
    }
}

/// A line cut at its LF, without the CR before it.
///
/// A line ends in CRLF, and RFC 9112 §2.2 lets a recipient take a bare LF
/// as a line end as well, as servers do send; this does, for every line of
/// a response, head and chunked body alike. A CR anywhere else is a bare
/// CR, which §2.2 makes invalid (or to be replaced by a space): it is
/// refused, as elsewhere the head is read strictly, since agents that
/// split lines at a CR would read another field there.
fn strip_cr(line: &[u8]) -> Result<&[u8], &'static str> {
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    if line.contains(&b'\r') {
        return Err("bare CR in the response");
    }
    Ok(line)
}

/// Where the head starting at `start` ends, just past the line break of its
/// empty last line, looking at line feeds from `from` on. `None` if it has
/// not all arrived.
fn head_end(buf: &[u8], start: usize, from: usize) -> Option<usize> {
    let mut at = from;
    while let Some(i) = buf[at..].iter().position(|&b| b == b'\n') {
        let lf = at + i;
        // The line this LF ends is empty: the previous line ended right
        // before it, with or without a CR.
        let before = &buf[start..lf];
        if before.ends_with(b"\n") || before.ends_with(b"\n\r") {
            return Some(lf + 1);
        }
        at = lf + 1;
    }
    None
}

/// Status, reason, header fields, and the `Set-Cookie` values.
type Head = (u16, String, BTreeMap<String, String>, Vec<String>);

/// Parse a response head. It is bytes, not text: field values and the
/// reason phrase may carry obs-text (RFC 9110 §5.5, RFC 9112 §4), octets
/// above 0x7F in no particular encoding, and one such octet must not cost
/// the whole response. They are decoded as UTF-8 where they are that, and
/// replaced where not.
fn parse_head(head: &[u8]) -> Result<Head, &'static str> {
    let lines: Vec<&[u8]> = head
        .split(|&b| b == b'\n')
        .map(strip_cr)
        .collect::<Result<_, _>>()?;
    let mut lines = lines.into_iter();
    let status_line = lines.next().ok_or("empty response")?;
    // HTTP/1.1 200 OK
    let mut sp = status_line.splitn(3, |&b| b == b' ');
    let _version = sp.next().ok_or("no version")?;
    let status = sp.next().ok_or("no status")?;
    if status.len() != 3 || !status.iter().all(u8::is_ascii_digit) {
        return Err("bad status");
    }
    let status = status
        .iter()
        .fold(0u16, |n, d| n * 10 + u16::from(d - b'0'));
    let reason = String::from_utf8_lossy(sp.next().unwrap_or(b"")).into_owned();

    // Each field line is `name ":" OWS value OWS` (RFC 9112 §5), read
    // strictly: a line taken for a field it is not can carry a
    // Content-Length or Transfer-Encoding the server never sent.
    let mut fields: Vec<(String, Vec<u8>)> = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let [b' ' | b'\t', ..] = line {
            // obs-fold (RFC 9112 §5.2): a line that starts with whitespace
            // continues the field before it, and a user agent replaces the
            // fold with a space. Before the first field there is nothing to
            // continue, and §2.2 lets such a line be rejected.
            let (_, value) = fields
                .last_mut()
                .ok_or("whitespace before the first field")?;
            value.push(b' ');
            value.extend_from_slice(trim_ows(line));
            continue;
        }
        let colon = line
            .iter()
            .position(|&b| b == b':')
            .ok_or("field line without a colon")?;
        // Whitespace between the name and the colon is refused outright
        // (RFC 9112 §5.1): proxies have read such names both ways.
        let name = &line[..colon];
        if name.is_empty() || !name.iter().all(|&b| is_tchar(b)) {
            return Err("bad field name");
        }
        let name = String::from_utf8_lossy(name).to_ascii_lowercase();
        fields.push((name, trim_ows(&line[colon + 1..]).to_vec()));
    }

    let mut headers = BTreeMap::new();
    let mut set_cookies = Vec::new();
    for (k, v) in fields {
        let v = String::from_utf8_lossy(trim_ows(&v)).into_owned();
        if k == "set-cookie" {
            set_cookies.push(v.clone());
            headers.insert(k, v);
            continue;
        }
        // A repeated field is the list of its values (RFC 9110 §5.3), so a
        // second Content-Length is checked against the first rather than
        // silently replacing it.
        headers
            .entry(k)
            .and_modify(|all: &mut String| {
                all.push_str(", ");
                all.push_str(&v);
            })
            .or_insert(v);
    }
    Ok((status, reason, headers, set_cookies))
}

/// `s` without the optional whitespace (SP, HTAB) around it (RFC 9110
/// §5.6.3).
fn trim_ows(mut s: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = s {
        s = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = s {
        s = rest;
    }
    s
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
    fn callers_host_header_replaces_the_default() {
        let req = Request::get("http://10.0.0.1:8080/")
            .unwrap()
            .header("hOsT", "example.test");
        let s = String::from_utf8(req.serialize().unwrap()).unwrap();
        let hosts: Vec<&str> = s
            .lines()
            .filter(|l| l.to_ascii_lowercase().starts_with("host:"))
            .collect();
        assert_eq!(hosts, ["hOsT: example.test"]);
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

    #[test]
    fn body_framing_is_consistent() {
        let wire = |req: Request| req.serialize().map(|w| String::from_utf8(w).unwrap());
        let lengths = |s: &str| {
            s.lines()
                .filter(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                .count()
        };
        // An empty POST still says so; a GET without a body says nothing.
        let s = wire(Request::post("http://h/", Vec::new()).unwrap()).unwrap();
        assert!(s.contains("Content-Length: 0\r\n"), "{s:?}");
        let s = wire(Request::get("http://h/").unwrap()).unwrap();
        assert_eq!(lengths(&s), 0);

        // The caller's own Content-Length, if right, is the only one.
        let post = || Request::post("http://h/", b"abc".to_vec()).unwrap();
        let s = wire(post().header("content-length", "3")).unwrap();
        assert_eq!(lengths(&s), 1);
        // Anything that frames the body otherwise than it is sent is refused.
        for (k, v) in [
            ("Content-Length", "2"),
            ("Content-Length", "x"),
            ("Transfer-Encoding", "chunked"),
            ("transfer-encoding", "gzip"),
        ] {
            let err = wire(post().header(k, v)).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{k}: {v}");
        }
    }

    /// The body limit bounds the memory the body takes, not just its length:
    /// `Vec` doubling would otherwise take a body just past half the limit
    /// to twice the limit in capacity.
    #[test]
    fn body_capacity_stays_within_the_limit() {
        const MAX: usize = 1_000_000;
        for head in [
            "HTTP/1.1 200 OK\r\n\r\n".to_string(),
            format!("HTTP/1.1 200 OK\r\nContent-Length: {MAX}\r\n\r\n"),
        ] {
            let mut r = ResponseReader::new(false, MAX);
            assert!(r.feed(head.as_bytes()).unwrap().is_none());
            let chunk = [b'x'; 1000];
            for _ in 0..MAX / 1000 - 1 {
                assert!(r.feed(&chunk).unwrap().is_none());
                assert!(r.body.capacity() <= MAX, "{}", r.body.capacity());
            }
            let done = r.feed(&chunk).unwrap();
            let cap = done.map_or(r.body.capacity(), |resp| resp.body.capacity());
            assert!(cap <= MAX, "{cap}");
        }
    }

    /// Feed `raw` in pieces of `step` bytes, then close.
    fn read_response(raw: &[u8], step: usize) -> io::Result<Response> {
        let mut r = ResponseReader::new(false, DEFAULT_MAX_RESPONSE_BODY);
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
        let mut r = ResponseReader::new(false, DEFAULT_MAX_RESPONSE_BODY);
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

    /// A bare LF ends a line anywhere a CRLF does (RFC 9112 §2.2), and a
    /// bare CR is refused.
    #[test]
    fn bare_lf_ends_lines_and_bare_cr_is_refused() {
        let lf = b"HTTP/1.1 200 OK\nContent-Length: 2\nX-A: a\n\nhi";
        let mixed = b"HTTP/1.1 200 OK\r\nContent-Length: 2\nX-A: a\r\n\nhi";
        let chunked = b"HTTP/1.1 200 OK\nTransfer-Encoding: chunked\n\n\
                        5\nhello\n6;e=1\r\n world\n0\nT: x\n\n";
        for raw in [&lf[..], mixed, chunked] {
            for step in [1, 2, 5, raw.len()] {
                let r = read_response(raw, step).unwrap();
                assert!(r.body == b"hi" || r.body == b"hello world", "{raw:?}");
            }
        }
        let r = read_response(lf, lf.len()).unwrap();
        assert_eq!((r.header("x-a"), r.reason.as_str()), (Some("a"), "OK"));

        for raw in [
            &b"HTTP/1.1 200 OK\r\nX-A: a\rContent-Length: 0\r\n\r\n"[..],
            b"HTTP/1.1 200 O\rK\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\r\nx\r\n0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nT: \rx\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\rx0\r\n\r\n",
        ] {
            let err = read_response(raw, raw.len()).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{raw:?}");
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
        let mut r = ResponseReader::new(false, DEFAULT_MAX_RESPONSE_BODY);
        assert_eq!(r.feed(raw).unwrap().unwrap().status, 204);

        let mut r = ResponseReader::new(true, DEFAULT_MAX_RESPONSE_BODY);
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

    /// Only what is not yet parsed stays buffered: consumed body bytes,
    /// interim heads and trailers are dropped, whatever the framing.
    #[test]
    fn consumed_bytes_do_not_stay_buffered() {
        let body = vec![b'x'; 1 << 20];
        let mut interim = Vec::new();
        for _ in 0..MAX_INTERIM {
            interim.extend_from_slice(b"HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n");
        }
        let mut chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        for c in body.chunks(1000) {
            chunked.extend_from_slice(format!("{:x}\r\n", c.len()).as_bytes());
            chunked.extend_from_slice(c);
            chunked.extend_from_slice(b"\r\n");
        }
        chunked.extend_from_slice(b"0\r\n");
        for _ in 0..MAX_TRAILERS {
            chunked.extend_from_slice(b"X-Trailer: 1\r\n");
        }
        chunked.extend_from_slice(b"\r\n");
        let with_length = [
            &interim[..],
            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes(),
            &body,
        ]
        .concat();
        let to_eof = [&interim[..], b"HTTP/1.1 200 OK\r\n\r\n", &body].concat();

        for raw in [&with_length, &chunked, &to_eof] {
            let mut r = ResponseReader::new(false, DEFAULT_MAX_RESPONSE_BODY);
            let mut resp = None;
            for piece in raw.chunks(16 * 1024) {
                resp = r.feed(piece).unwrap();
                assert!(r.buf.len() <= MAX_HEAD, "{} bytes buffered", r.buf.len());
                if resp.is_some() {
                    break;
                }
            }
            let resp = match resp {
                Some(resp) => resp,
                None => r.finish().unwrap(),
            };
            assert_eq!(resp.body, body);
        }
    }

    #[test]
    fn response_limits_are_enforced() {
        let limited = |raw: &[u8], max: usize| {
            let mut r = ResponseReader::new(false, max);
            for piece in raw.chunks(7) {
                if let Some(resp) = r.feed(piece)? {
                    return Ok(resp);
                }
            }
            r.finish()
        };
        let is_invalid =
            |res: io::Result<Response>| res.is_err_and(|e| e.kind() == io::ErrorKind::InvalidData);
        // A body of exactly the limit is fine; one byte over is not, however
        // it is framed.
        for (raw, len) in [
            (&b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"[..], 5),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nhel\r\n2\r\nlo\r\n0\r\n\r\n",
                5,
            ),
            (b"HTTP/1.1 200 OK\r\n\r\nhello", 5),
        ] {
            assert_eq!(limited(raw, len).unwrap().body, b"hello");
            assert!(is_invalid(limited(raw, len - 1)), "{raw:?}");
        }

        let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n";
        let mut raw = head.to_vec();
        for _ in 0..=MAX_TRAILERS {
            raw.extend_from_slice(b"X: 1\r\n");
        }
        raw.extend_from_slice(b"\r\n");
        assert!(is_invalid(limited(&raw, 100)));

        let mut raw = Vec::new();
        for _ in 0..=MAX_INTERIM {
            raw.extend_from_slice(b"HTTP/1.1 100 Continue\r\n\r\n");
        }
        raw.extend_from_slice(b"HTTP/1.1 204 No Content\r\n\r\n");
        assert!(is_invalid(limited(&raw, 100)));

        // A head over the limit that arrives in one piece.
        let mut raw = b"HTTP/1.1 200 OK\r\nX: ".to_vec();
        raw.resize(MAX_HEAD + 100, b'a');
        raw.extend_from_slice(b"\r\nContent-Length: 0\r\n\r\n");
        let mut r = ResponseReader::new(false, 100);
        assert!(is_invalid(r.feed(&raw).map(|_| unreachable!())));
    }

    /// A server that completes the handshake and then never answers.
    fn silent_server(client: &std::sync::Arc<Client>) {
        use crate::vtcp::{Conn, ConnConfig, segment::Segment};
        use crate::{L3Device, Packet, Protocol};
        use std::net::Ipv4Addr;
        use std::sync::{Arc, Mutex};

        let server: Arc<Mutex<Option<Conn>>> = Arc::new(Mutex::new(None));
        // Packets waiting to be sent, and whether a call is sending them.
        let outbox: Arc<Mutex<(std::collections::VecDeque<Vec<u8>>, bool)>> = Arc::default();
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
            // Replies go out from the outermost call only: each ACK lets the
            // client send more, synchronously, and answering from inside
            // that would recurse once per segment of a large transfer.
            let mut q = outbox.lock().unwrap();
            q.0.extend(out.into_iter().map(|s| {
                let mut ip = crate::build::build_ipv4(
                    Ipv4Addr::new(10, 0, 0, 1),
                    Ipv4Addr::new(10, 0, 0, 2),
                    Protocol::TCP,
                    64,
                    &s,
                );
                Packet::from_mut(&mut ip).recompute_transport_checksum();
                ip
            }));
            if q.1 {
                return Ok(());
            }
            q.1 = true;
            while let Some(ip) = q.0.pop_front() {
                drop(q);
                if let Some(client) = weak.upgrade() {
                    let _ = client.send(Packet::from_slice(&ip));
                }
                q = outbox.lock().unwrap();
            }
            q.1 = false;
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

    /// A server that never reads fills its window, then the client's send
    /// buffer: sending stalls, and must give up when the request's timeout
    /// runs out, not a timeout later for each partial write.
    #[test]
    fn stalled_send_times_out_on_the_request_deadline() {
        let client = Client::new(super::super::ClientConfig::default().prefix(
            crate::IpPrefix::new(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)), 24),
        ));
        silent_server(&client);
        let timeout = Duration::from_millis(1000);
        // More than the peer's receive buffer and our send buffer together.
        let body = vec![b'x'; 4 << 20];
        let req = Request::post("http://10.0.0.1/", body)
            .unwrap()
            .timeout(timeout);
        let start = std::time::Instant::now();
        let err = client.http(&req).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        let took = start.elapsed();
        assert!(took < timeout * 3 / 2, "took {took:?}");
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
                    let mut ip = crate::build::build_ip(dst, src, Protocol::TCP, 64, &s).unwrap();
                    Packet::from_mut(&mut ip).recompute_transport_checksum();
                    let _ = client.send(Packet::from_slice(&ip));
                }
            }
            Ok(())
        }));
    }

    #[test]
    fn dials_the_first_reachable_address_of_the_clients_family() {
        let deadline = || Some(Instant::now() + Duration::from_secs(2));
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

    #[test]
    fn a_huge_timeout_means_no_deadline() {
        let client = Client::new(
            super::super::ClientConfig::default()
                .prefix(crate::IpPrefix::new("10.0.0.2".parse().unwrap(), 24)),
        );
        servers_at(&client, Vec::new());
        let req = Request::get("http://10.0.0.1/")
            .unwrap()
            .timeout(Duration::MAX);
        let err = client.http(&req).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
    }

    /// A folded line continues the field before it (RFC 9112 §5.2): it is
    /// never a field of its own.
    #[test]
    fn obs_fold_continues_the_previous_field() {
        let raw = b"HTTP/1.1 200 OK\r\nX-A: a\r\n Content-Length: 3\r\n\tb \r\nContent-Length: 2\r\n\r\nokk";
        let r = read_response(raw, raw.len()).unwrap();
        assert_eq!(r.header("x-a"), Some("a Content-Length: 3 b"));
        assert_eq!(r.header("content-length"), Some("2"));
        assert_eq!(r.body, b"ok");
        // Nothing to continue before the first field.
        assert!(parse_head(b"HTTP/1.1 200 OK\r\n Content-Length: 3\r\n\r\n").is_err());
    }

    /// A field line must be a name, a colon, then the value (RFC 9112 §5.1).
    #[test]
    fn malformed_field_lines_reject_the_response() {
        for bad in [
            "Content-Length : 3",
            "Content-Length\t: 3",
            "Transfer-Encoding chunked",
            ": x",
            "Bad Name: x",
            "X-\u{e9}: x",
        ] {
            let raw = format!("HTTP/1.1 200 OK\r\n{bad}\r\n\r\nabc");
            let e = read_response(raw.as_bytes(), raw.len()).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{bad:?}");
        }
    }

    /// Octets above 0x7F (obs-text) in a field value or the reason phrase
    /// are decoded, lossily where they are not UTF-8, not refused.
    #[test]
    fn obs_text_does_not_reject_the_response() {
        let raw = b"HTTP/1.1 200 D\xe9j\xe0 vu\r\nX-Latin: caf\xe9\r\nX-Utf8: caf\xc3\xa9\r\nContent-Length: 2\r\n\r\nok";
        let r = read_response(raw, raw.len()).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.reason, "D\u{fffd}j\u{fffd} vu");
        assert_eq!(r.header("x-latin"), Some("caf\u{fffd}"));
        assert_eq!(r.header("x-utf8"), Some("caf\u{e9}"));
        assert_eq!(r.body, b"ok");
    }

    #[test]
    fn status_code_is_three_digits() {
        for bad in ["+20", "2000", "20", "abc", ""] {
            let raw = format!("HTTP/1.1 {bad} OK\r\n\r\n");
            assert!(parse_head(raw.as_bytes()).is_err(), "{bad:?}");
        }
        assert_eq!(parse_head(b"HTTP/1.1 404\r\n\r\n").unwrap().0, 404);
    }

    /// Cookies stay whole: RFC 9110 §5.3 does not let `Set-Cookie` fields
    /// be joined, and their `Expires=` dates contain commas.
    #[test]
    fn set_cookie_fields_are_kept_apart() {
        let raw = b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT\r\nX-Y: 1\r\nSet-Cookie: b=2\r\nX-Y: 2\r\n\r\n";
        let (_, _, headers, cookies) = parse_head(raw).unwrap();
        assert_eq!(
            cookies,
            vec!["a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT", "b=2"]
        );
        assert_eq!(headers["set-cookie"], "b=2");
        assert_eq!(headers["x-y"], "1, 2", "other repeated fields still join");
    }
}
