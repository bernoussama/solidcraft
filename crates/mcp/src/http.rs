//! Streamable HTTP transport for MCP (JSON-RPC over `POST /mcp`).
//!
//! Loopback only: binds `127.0.0.1`, requires `Authorization: Bearer`, checks `Host` and
//! `Origin` against DNS rebinding, caps the body and the number of sessions. No tokio: a
//! listening thread plus one thread per connection. Wasm never compiles this module.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Sender};
use std::thread::JoinHandle;
use std::time::Duration;

use serde_json::{Value, json};
use solidcraft_engine::control_auth;
use solidcraft_engine::io::vfs::PathScope;
use solidcraft_engine::recovery;

use crate::agent_scope;
use crate::backend::Backend;
use crate::server::Server;

/// Longest POST body accepted (hostile clients).
const MAX_BODY: usize = 1 << 20;
/// Longest HTTP header block.
const MAX_HEADERS: usize = 64 << 10;
/// Sessions kept at once (one [`Server`] each).
const MAX_SESSIONS: usize = 32;
/// Connections served at once.
const MAX_CONNECTIONS: usize = 16;

/// Build a new [`Server`] for each MCP session (each client `initialize`).
pub type BackendFactory = Arc<dyn Fn() -> Box<dyn Backend> + Send + Sync>;

/// Running listener. Drop or [`Handle::stop`] closes the socket so the port is free again.
pub struct Handle {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    work: Sender<Work>,
    listen: Option<JoinHandle<()>>,
    worker: Option<JoinHandle<()>>,
}

impl Handle {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Stop accepting and join the listener. In-flight connections finish or hit a closed socket.
    pub fn stop(mut self) {
        self.signal_stop();
        if let Some(t) = self.listen.take() {
            let _ = t.join();
        }
        if let Some(t) = self.worker.take() {
            let _ = t.join();
        }
    }

    fn signal_stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = self.work.send(Work::Stop);
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(200));
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        if self.listen.is_some() || self.worker.is_some() {
            self.signal_stop();
            if let Some(t) = self.listen.take() {
                let _ = t.join();
            }
            if let Some(t) = self.worker.take() {
                let _ = t.join();
            }
        }
    }
}

/// Work for the session thread. `Server`/`Backend` are not `Send`, so they live on one thread.
enum Work {
    Post { session: Option<String>, body: String, reply: Sender<PostOut> },
    Delete { session: Option<String>, reply: Sender<()> },
    Stop,
}

struct PostOut {
    status: u16,
    session: Option<String>,
    /// `None` → HTTP 202 (notification).
    json: Option<String>,
}

/// Streamable HTTP MCP server on loopback.
pub struct HttpServer;

impl HttpServer {
    /// Listen on `addr` (must resolve to `127.0.0.1`; port 0 picks a free one). `token` is the
    /// Bearer secret. `backend` is called once per session.
    pub fn start(
        addr: impl ToSocketAddrs,
        token: impl Into<String>,
        backend: impl Fn() -> Box<dyn Backend> + Send + Sync + 'static,
    ) -> std::io::Result<Handle> {
        start_factory(addr, token, Arc::new(backend) as BackendFactory, Some(agent_scope([])))
    }

    /// [`start`] with the path scope `solidcraft-cli mcp` uses (`None`: any path).
    pub fn start_with_scope(
        addr: impl ToSocketAddrs,
        token: impl Into<String>,
        backend: impl Fn() -> Box<dyn Backend> + Send + Sync + 'static,
        scope: Option<PathScope>,
    ) -> std::io::Result<Handle> {
        start_factory(addr, token, Arc::new(backend) as BackendFactory, scope)
    }
}

fn start_factory(addr: impl ToSocketAddrs, token: impl Into<String>, backend: BackendFactory, scope: Option<PathScope>) -> std::io::Result<Handle> {
    let token = token.into();
    if token.len() < control_auth::MIN_TOKEN_LEN {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "MCP HTTP token is too short"));
    }
    let mut last = None;
    for sa in addr.to_socket_addrs()? {
        if sa.ip() != Ipv4Addr::LOCALHOST {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("MCP HTTP binds 127.0.0.1 only, not {sa}")));
        }
        last = Some(sa);
    }
    let bind_addr = last.ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "MCP HTTP address did not resolve"))?;
    let listener = TcpListener::bind(bind_addr)?;
    let addr = listener.local_addr()?;
    if addr.ip() != Ipv4Addr::LOCALHOST {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "MCP HTTP bound a non-loopback address"));
    }
    let stop = Arc::new(AtomicBool::new(false));
    let (work_tx, work_rx) = mpsc::channel();
    let worker = std::thread::Builder::new().name("solidcraft-mcp-http-sessions".into()).spawn({
        let work_rx = work_rx;
        move || session_loop(work_rx, backend, scope)
    })?;
    let state = Arc::new(State { token, work: work_tx.clone(), open: AtomicUsize::new(0), bound: addr, stop: stop.clone() });
    let listen = std::thread::Builder::new().name("solidcraft-mcp-http".into()).spawn({
        let state = state.clone();
        move || listen_loop(listener, state)
    })?;
    Ok(Handle { addr, stop, work: work_tx, listen: Some(listen), worker: Some(worker) })
}

struct State {
    token: String,
    work: Sender<Work>,
    open: AtomicUsize,
    bound: SocketAddr,
    stop: Arc<AtomicBool>,
}

fn session_loop(rx: mpsc::Receiver<Work>, backend: BackendFactory, scope: Option<PathScope>) {
    let mut sessions: HashMap<String, Server> = HashMap::new();
    while let Ok(job) = rx.recv() {
        match job {
            Work::Stop => break,
            Work::Delete { session, reply } => {
                if let Some(id) = session {
                    sessions.remove(&id);
                }
                let _ = reply.send(());
            }
            Work::Post { session, body, reply } => {
                let out = handle_post(&mut sessions, &backend, scope.clone(), session, &body);
                let _ = reply.send(out);
            }
        }
    }
}

fn handle_post(
    sessions: &mut HashMap<String, Server>,
    backend: &BackendFactory,
    scope: Option<PathScope>,
    incoming: Option<String>,
    body: &str,
) -> PostOut {
    let value: Value = match serde_json::from_str(body.trim()) {
        Ok(v) => v,
        Err(e) => {
            return PostOut {
                status: 200,
                session: None,
                json: Some(json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":format!("parse error: {e}")}}).to_string()),
            };
        }
    };
    let needs_new = is_initialize(&value);
    let (id, server) = if needs_new {
        if sessions.len() >= MAX_SESSIONS {
            return PostOut { status: 429, session: None, json: None };
        }
        let id = new_session_id();
        sessions.insert(id.clone(), Server::new(backend()).with_path_scope(scope));
        let Some(server) = sessions.get_mut(&id) else {
            return PostOut { status: 500, session: None, json: None };
        };
        (id, server)
    } else {
        let Some(id) = incoming else {
            return PostOut { status: 400, session: None, json: None };
        };
        let Some(server) = sessions.get_mut(&id) else {
            return PostOut { status: 404, session: None, json: None };
        };
        (id, server)
    };
    PostOut { status: 200, session: Some(id), json: server.handle_line(body.trim()) }
}

fn listen_loop(listener: TcpListener, state: Arc<State>) {
    for incoming in listener.incoming() {
        if state.stop.load(Ordering::SeqCst) {
            break;
        }
        let stream = match incoming {
            Ok(s) => s,
            Err(_) => {
                if state.stop.load(Ordering::SeqCst) {
                    break;
                }
                continue;
            }
        };
        if state.stop.load(Ordering::SeqCst) {
            break;
        }
        if state.open.fetch_add(1, Ordering::Relaxed) >= MAX_CONNECTIONS {
            state.open.fetch_sub(1, Ordering::Relaxed);
            let _ = write_response(&stream, 503, &[], b"too many connections");
            continue;
        }
        let state = state.clone();
        let _ = std::thread::Builder::new().name("solidcraft-mcp-http-conn".into()).spawn(move || {
            serve_conn(stream, &state);
            state.open.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

fn serve_conn(stream: TcpStream, state: &State) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
    let Ok(read) = stream.try_clone() else { return };
    let mut reader = BufReader::new(read);
    match handle_request(&mut reader, &stream, state) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
            let _ = write_response(&stream, 400, &[], e.to_string().as_bytes());
        }
        Err(_) => {}
    }
}

fn handle_request(reader: &mut BufReader<TcpStream>, writer: &TcpStream, state: &State) -> std::io::Result<()> {
    let (method, path, headers) = read_headers(reader)?;
    if let Some(status) = check_host_origin(&headers, state.bound.port()) {
        let msg: &[u8] = if status == 403 { b"forbidden origin" } else { b"forbidden host" };
        return write_response(writer, status, &[], msg);
    }
    if !bearer_ok(&headers, &state.token) {
        return write_response(writer, 401, &[("WWW-Authenticate", "Bearer")], b"unauthorized");
    }
    let path = path.split('?').next().unwrap_or(path.as_str());
    if path != "/mcp" {
        return write_response(writer, 404, &[], b"not found");
    }
    match method.as_str() {
        "GET" => write_response(writer, 405, &[("Allow", "POST, DELETE")], b"method not allowed"),
        "DELETE" => {
            let session = header(&headers, "mcp-session-id").map(str::to_string);
            let (tx, rx) = mpsc::channel();
            if state.work.send(Work::Delete { session, reply: tx }).is_err() {
                return write_response(writer, 500, &[], b"server stopping");
            }
            let _ = rx.recv_timeout(Duration::from_secs(5));
            write_response(writer, 200, &[], b"")
        }
        "POST" => {
            let len = content_length(&headers)?;
            if len > MAX_BODY {
                return write_response(writer, 413, &[], b"request too large");
            }
            let mut body = vec![0u8; len];
            reader.read_exact(&mut body)?;
            let text = String::from_utf8(body).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "body is not UTF-8"))?;
            post_mcp(writer, state, &headers, text)
        }
        _ => write_response(writer, 405, &[("Allow", "POST, DELETE")], b"method not allowed"),
    }
}

fn post_mcp(writer: &TcpStream, state: &State, headers: &[(String, String)], body: String) -> std::io::Result<()> {
    let session = header(headers, "mcp-session-id").map(str::to_string);
    let (tx, rx) = mpsc::channel();
    if state.work.send(Work::Post { session, body, reply: tx }).is_err() {
        return write_response(writer, 500, &[], b"server stopping");
    }
    let out = match rx.recv_timeout(Duration::from_secs(300)) {
        Ok(o) => o,
        Err(_) => return write_response(writer, 504, &[], b"timeout"),
    };
    let extra = out.session.as_deref().map(|id| ("Mcp-Session-Id", id));
    let headers: Vec<(&str, &str)> = extra.into_iter().collect();
    if out.status == 429 {
        return write_response(writer, 429, &[], b"too many sessions");
    }
    if out.status == 400 {
        return write_response(writer, 400, &[], b"missing Mcp-Session-Id");
    }
    if out.status == 404 {
        return write_response(writer, 404, &[], b"unknown session");
    }
    if out.status != 200 {
        return write_response(writer, out.status, &[], b"error");
    }
    match out.json {
        None => write_response(writer, 202, &headers, b""),
        Some(text) => write_json_text(writer, 200, out.session.as_deref(), &text),
    }
}

fn is_initialize(v: &Value) -> bool {
    match v {
        Value::Object(o) => o.get("method").and_then(Value::as_str) == Some("initialize"),
        Value::Array(a) => a.iter().any(is_initialize),
        _ => false,
    }
}

fn new_session_id() -> String {
    let mut bytes = [0u8; 16];
    if getrandom::fill(&mut bytes).is_err() {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        static N: AtomicU64 = AtomicU64::new(1);
        let mix = nanos ^ u128::from(N.fetch_add(1, Ordering::Relaxed));
        bytes.copy_from_slice(&mix.to_le_bytes());
    }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn bearer_ok(headers: &[(String, String)], token: &str) -> bool {
    let Some(value) = header(headers, "authorization") else { return false };
    let Some(rest) = value.strip_prefix("Bearer ").or_else(|| value.strip_prefix("bearer ")) else { return false };
    control_auth::tokens_match(rest.trim(), token)
}

/// `None` = allowed. 403 = bad Origin, 400 = bad Host.
fn check_host_origin(headers: &[(String, String)], port: u16) -> Option<u16> {
    let host = header(headers, "host").unwrap_or("");
    if !host_ok(host, port) {
        return Some(400);
    }
    if let Some(origin) = header(headers, "origin")
        && !origin_ok(origin, port)
    {
        return Some(403);
    }
    None
}

fn host_ok(host: &str, port: u16) -> bool {
    let host = host.trim();
    let host = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    let (name, host_port) = split_host_port(host);
    let name_ok = matches!(name, "127.0.0.1" | "localhost" | "::1");
    let port_ok = host_port.is_none_or(|p| p == port);
    name_ok && port_ok
}

fn origin_ok(origin: &str, port: u16) -> bool {
    let origin = origin.trim();
    if origin.eq_ignore_ascii_case("null") {
        return false;
    }
    let Some(rest) = origin.strip_prefix("http://").or_else(|| origin.strip_prefix("https://")) else {
        return false;
    };
    let host = rest.split('/').next().unwrap_or(rest);
    host_ok(host, port)
}

fn split_host_port(host: &str) -> (&str, Option<u16>) {
    if let Some((name, p)) = host.rsplit_once(':')
        && !name.is_empty()
        && let Ok(port) = p.parse::<u16>()
        && !name.contains(':')
    {
        return (name, Some(port));
    }
    (host, None)
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

fn content_length(headers: &[(String, String)]) -> std::io::Result<usize> {
    let Some(v) = header(headers, "content-length") else {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "missing Content-Length"));
    };
    v.trim().parse::<usize>().map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad Content-Length"))
}

fn read_headers(reader: &mut impl BufRead) -> std::io::Result<(String, String, Vec<(String, String)>)> {
    let mut buf = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "connection closed"));
        }
        if let Some(at) = {
            let mut tmp = buf.clone();
            tmp.extend_from_slice(available);
            find_header_end(&tmp)
        } {
            let need = at.saturating_sub(buf.len());
            buf.extend_from_slice(available.get(..need).unwrap_or(&[]));
            reader.consume(need);
            return parse_head(buf.get(..at).unwrap_or(&buf));
        }
        buf.extend_from_slice(available);
        let n = available.len();
        reader.consume(n);
        if buf.len() > MAX_HEADERS {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "headers too large"));
        }
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn parse_head(head: &[u8]) -> std::io::Result<(String, String, Vec<(String, String)>)> {
    let text = std::str::from_utf8(head).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "headers are not UTF-8"))?;
    let mut lines = text.split("\r\n");
    let request = lines.next().unwrap_or("");
    let mut parts = request.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    if method.is_empty() || path.is_empty() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "bad request line"));
    }
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((k, v)) = line.split_once(':') else { continue };
        headers.push((k.trim().to_string(), v.trim().to_string()));
        if headers.len() > 64 {
            break;
        }
    }
    Ok((method, path, headers))
}

fn write_json_text(writer: &TcpStream, status: u16, session: Option<&str>, text: &str) -> std::io::Result<()> {
    let extra = session.map(|id| ("Mcp-Session-Id", id));
    let headers: Vec<(&str, &str)> = extra.into_iter().collect();
    write_response(writer, status, &headers, text.as_bytes())
}

fn write_response(mut writer: &TcpStream, status: u16, extra: &[(&str, &str)], body: &[u8]) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Error",
    };
    let json = status == 200 && body.first().is_some_and(|b| *b == b'{' || *b == b'[');
    let ctype = if json { "application/json" } else { "text/plain; charset=utf-8" };
    let mut out = format!("HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n", body.len());
    for (k, v) in extra {
        out.push_str(k);
        out.push_str(": ");
        out.push_str(v);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    writer.write_all(out.as_bytes())?;
    writer.write_all(body)?;
    writer.flush()
}

/// Token file of the server listening on `port`: `<data folder>/mcp/<port>.token`
/// (`SOLIDCRAFT_MCP_DIR` replaces the folder).
pub fn token_path(port: u16) -> Option<std::path::PathBuf> {
    let dir = match solidcraft_engine::geom::env::var_os("MCP_DIR").filter(|d| !d.is_empty()) {
        Some(d) => std::path::PathBuf::from(d),
        None => recovery::data_dir()?.join("mcp"),
    };
    Some(dir.join(format!("{port}.token")))
}

/// Write `token` with mode 0600 (same rules as the control-channel token file).
pub fn write_token_file(port: u16, token: &str) -> std::io::Result<std::path::PathBuf> {
    let path = token_path(port).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no data folder for the MCP token"))?;
    control_auth::write_token_file(&path, token)?;
    Ok(path)
}

/// A 32-byte hex token, or `None` when the OS has no random bytes.
pub fn new_token() -> Option<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).ok()?;
    Some(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Client config JSON for a local Streamable HTTP server (Preferences copy button, docs).
pub fn client_config_json(url: &str, token: &str) -> String {
    json!({
        "mcpServers": {
            "solidcraft": {
                "url": url,
                "headers": { "Authorization": format!("Bearer {token}") }
            }
        }
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Headless;
    use serde_json::Value;
    use std::io::Write;

    fn token() -> String {
        "0123456789abcdef0123456789abcdef".to_string()
    }

    fn start() -> Handle {
        HttpServer::start("127.0.0.1:0", token(), || Box::new(Headless::default())).expect("listen")
    }

    struct Reply {
        status: u16,
        headers: Vec<(String, String)>,
        body: String,
    }

    fn request(addr: SocketAddr, method: &str, extra: &[(&str, &str)], body: &str) -> Reply {
        request_raw(addr, method, extra, body, &token())
    }

    fn request_raw(addr: SocketAddr, method: &str, extra: &[(&str, &str)], body: &str, bearer: &str) -> Reply {
        let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
        let mut headers = format!(
            "{method} /mcp HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {bearer}\r\nContent-Length: {}\r\nConnection: close\r\n",
            addr.port(),
            body.len()
        );
        for (k, v) in extra {
            headers.push_str(&format!("{k}: {v}\r\n"));
        }
        headers.push_str("\r\n");
        stream.write_all(headers.as_bytes()).unwrap();
        stream.write_all(body.as_bytes()).unwrap();
        stream.flush().unwrap();
        let mut reader = BufReader::new(stream);
        let mut status_line = String::new();
        reader.read_line(&mut status_line).unwrap();
        let status = status_line.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let mut headers = Vec::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" || line == "\n" || line.is_empty() {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                headers.push((k.trim().to_string(), v.trim().to_string()));
            }
        }
        let len = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-length")).and_then(|(_, v)| v.parse::<usize>().ok()).unwrap_or(0);
        let mut buf = vec![0u8; len];
        if len > 0 {
            reader.read_exact(&mut buf).unwrap();
        }
        Reply { status, headers, body: String::from_utf8_lossy(&buf).into_owned() }
    }

    fn header_ci<'a>(r: &'a Reply, name: &str) -> Option<&'a str> {
        r.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    fn initialize(addr: SocketAddr) -> (String, Value) {
        let body = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}).to_string();
        let r = request(addr, "POST", &[], &body);
        assert_eq!(r.status, 200, "{}", r.body);
        let sid = header_ci(&r, "Mcp-Session-Id").expect("session").to_string();
        assert!(!sid.is_empty());
        let v: Value = serde_json::from_str(&r.body).unwrap();
        (sid, v)
    }

    #[test]
    fn initialize_returns_a_session_id_and_tools_list_works() {
        let h = start();
        let addr = h.addr();
        let (sid, init) = initialize(addr);
        assert_eq!(init["result"]["serverInfo"]["name"], "solidcraft");
        let body = json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}).to_string();
        let r = request(addr, "POST", &[("Mcp-Session-Id", sid.as_str())], &body);
        assert_eq!(r.status, 200, "{}", r.body);
        let v: Value = serde_json::from_str(&r.body).unwrap();
        assert!(v["result"]["tools"].as_array().is_some_and(|t| !t.is_empty()), "{v}");
        h.stop();
    }

    #[test]
    fn a_bad_token_gets_401() {
        let h = start();
        let r = request_raw(h.addr(), "POST", &[], "{}", "not-the-token-not-the-token-not");
        assert_eq!(r.status, 401, "{}", r.body);
        h.stop();
    }

    #[test]
    fn a_foreign_origin_gets_403() {
        let h = start();
        let r = request(h.addr(), "POST", &[("Origin", "https://evil.example")], "{}");
        assert_eq!(r.status, 403, "{}", r.body);
        h.stop();
    }

    #[test]
    fn a_notification_gets_202() {
        let h = start();
        let addr = h.addr();
        let (sid, _) = initialize(addr);
        let body = json!({"jsonrpc":"2.0","method":"notifications/initialized"}).to_string();
        let r = request(addr, "POST", &[("Mcp-Session-Id", sid.as_str())], &body);
        assert_eq!(r.status, 202, "{}", r.body);
        h.stop();
    }

    #[test]
    fn get_gets_405() {
        let h = start();
        let r = request(h.addr(), "GET", &[], "");
        assert_eq!(r.status, 405, "{}", r.body);
        h.stop();
    }

    #[test]
    fn stop_frees_the_port() {
        let h = start();
        let addr = h.addr();
        h.stop();
        HttpServer::start(addr, token(), || Box::new(Headless::default())).expect("port is free again").stop();
    }
}
