//! `mcp --http 127.0.0.1:PORT`: Streamable HTTP instead of stdio. Modeled on `mcp_connect.rs`.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

fn unused_port() -> u16 {
    (0..512u32)
        .find_map(|offset| {
            let port = 18000 + (std::process::id() + offset) % 16000;
            TcpListener::bind(("127.0.0.1", port as u16)).ok().map(|listener| listener.local_addr().unwrap().port())
        })
        .expect("an unused non-ephemeral test port")
}

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

fn http(addr: SocketAddr, method: &str, extra: &[(&str, &str)], body: &str, token: &str) -> Reply {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
    let mut headers = format!(
        "{method} /mcp HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {token}\r\nContent-Length: {}\r\nConnection: close\r\n",
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

fn header<'a>(r: &'a Reply, name: &str) -> Option<&'a str> {
    r.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

#[test]
fn mcp_http_initializes_and_lists_tools() {
    let port = unused_port();
    let addr = format!("127.0.0.1:{port}");
    let mcp_dir = std::env::temp_dir().join(format!("solidcraft-mcp-http-{}-{port}", std::process::id()));
    std::fs::create_dir_all(&mcp_dir).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_solidcraft-cli"))
        .args(["mcp", "--http", &addr, "--allow-any-path"])
        .env("SOLIDCRAFT_MCP_DIR", &mcp_dir)
        .env_remove("SOLIDCRAFT_MCP_TOKEN")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let token_path = mcp_dir.join(format!("{port}.token"));
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline && !token_path.exists() {
        std::thread::sleep(Duration::from_millis(20));
    }
    let token = std::fs::read_to_string(&token_path).unwrap_or_default().trim().to_string();
    assert!(token.len() >= 32, "token file {}: {token:?}", token_path.display());
    let sa: SocketAddr = addr.parse().unwrap();
    let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}).to_string();
    let r = http(sa, "POST", &[], &init, &token);
    assert_eq!(r.status, 200, "{}", r.body);
    let sid = header(&r, "Mcp-Session-Id").expect("session").to_string();
    let v: Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(v["result"]["serverInfo"]["name"], "solidcraft");
    let list = json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}).to_string();
    let r = http(sa, "POST", &[("Mcp-Session-Id", sid.as_str())], &list, &token);
    assert_eq!(r.status, 200, "{}", r.body);
    let v: Value = serde_json::from_str(&r.body).unwrap();
    assert!(v["result"]["tools"].as_array().is_some_and(|t| !t.is_empty()), "{v}");

    drop(child.stdin.take());
    assert!(child.wait().unwrap().success());
    std::fs::remove_dir_all(&mcp_dir).ok();
}

#[test]
fn mcp_http_without_a_loopback_port_is_refused_at_start() {
    for addr in ["localhost:7879", "0.0.0.0:7879", "127.0.0.1"] {
        let output = Command::new(env!("CARGO_BIN_EXE_solidcraft-cli")).args(["mcp", "--http", addr]).stdin(Stdio::null()).output().unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{addr}: {stderr}");
        assert!(stderr.contains("127.0.0.1"), "{addr}: {stderr}");
    }
}
