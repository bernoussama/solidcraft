//! In-process Streamable HTTP MCP server, started from Preferences.
//!
//! A private control endpoint (same pattern as [`crate::control_server::listen_agent`]) receives
//! tool calls; each MCP session is `Server::new(Remote::new(127.0.0.1:<port>, token))` with the
//! usual agent path scope. The HTTP Bearer token is written to
//! `~/.local/share/solidcraft/mcp/<PORT>.token` (mode 0600) and removed on stop.

use std::sync::mpsc::{Receiver, Sender, channel};

use solidcraft_mcp::{HttpHandle, HttpServer, Remote, agent_scope, client_config_json, new_token, write_token_file};
use solidcraft_ui_egui::{ControlRequest, McpHttpStatus, SolveApp};

use crate::control_server;

pub struct Service {
    ctx: egui::Context,
    control_tx: Sender<ControlRequest>,
    control_rx: Receiver<ControlRequest>,
    control: Option<(u16, String)>,
    http: Option<Running>,
    /// Last `(enabled, port)` we tried, so a bind error is not retried every frame.
    last: Option<(bool, u16)>,
    last_status: McpHttpStatus,
}

struct Running {
    port: u16,
    token: String,
    token_path: std::path::PathBuf,
    handle: HttpHandle,
}

impl Service {
    pub fn new(ctx: egui::Context) -> Self {
        let (control_tx, control_rx) = channel();
        Self { ctx, control_tx, control_rx, control: None, http: None, last: None, last_status: McpHttpStatus::default() }
    }

    pub fn pump(&mut self, app: &mut SolveApp) {
        for req in self.control_rx.try_iter().take(64) {
            app.push_control(req);
        }
    }

    pub fn sync(&mut self, enabled: bool, port: u16) -> McpHttpStatus {
        if !enabled {
            self.stop_http();
            self.last = Some((false, port));
            self.last_status = McpHttpStatus::default();
            return self.last_status.clone();
        }
        if port == 0 {
            self.stop_http();
            self.last = Some((true, 0));
            self.last_status = McpHttpStatus { error: Some("port must be 1–65535".into()), ..McpHttpStatus::default() };
            return self.last_status.clone();
        }
        if let Some(run) = &self.http
            && run.port == port
        {
            self.last = Some((true, port));
            self.last_status = status_of(run);
            return self.last_status.clone();
        }
        if self.last == Some((true, port)) {
            return self.last_status.clone();
        }
        self.stop_http();
        self.last = Some((true, port));
        self.last_status = match self.start_http(port) {
            Ok(()) => self
                .http
                .as_ref()
                .map(status_of)
                .unwrap_or_else(|| McpHttpStatus { error: Some("server did not start".into()), ..McpHttpStatus::default() }),
            Err(e) => McpHttpStatus { error: Some(e), ..McpHttpStatus::default() },
        };
        self.last_status.clone()
    }

    pub fn shutdown(&mut self) {
        self.stop_http();
    }

    fn ensure_control(&mut self) -> Result<(u16, String), String> {
        if let Some(c) = &self.control {
            return Ok(c.clone());
        }
        let Some((port, token)) = control_server::listen_private(self.control_tx.clone(), self.ctx.clone()) else {
            return Err("could not start a private control endpoint".into());
        };
        self.control = Some((port, token.clone()));
        Ok((port, token))
    }

    fn start_http(&mut self, port: u16) -> Result<(), String> {
        let (control_port, control_token) = self.ensure_control()?;
        let http_token = new_token().ok_or_else(|| "no random token available".to_string())?;
        let addr = format!("127.0.0.1:{control_port}");
        let token = control_token.clone();
        let handle = HttpServer::start_with_scope(
            ("127.0.0.1", port),
            http_token.clone(),
            move || Box::new(Remote::new(&addr, Some(&token))) as Box<dyn solidcraft_mcp::Backend>,
            Some(agent_scope([])),
        )
        .map_err(|e| e.to_string())?;
        let bound = handle.addr().port();
        let token_path = write_token_file(bound, &http_token).map_err(|e| e.to_string())?;
        eprintln!("solidcraft: MCP HTTP listening on http://127.0.0.1:{bound}/mcp (token in {})", token_path.display());
        self.http = Some(Running { port: bound, token: http_token, token_path, handle });
        Ok(())
    }

    fn stop_http(&mut self) {
        if let Some(run) = self.http.take() {
            let _ = std::fs::remove_file(&run.token_path);
            run.handle.stop();
        }
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        self.stop_http();
    }
}

fn status_of(run: &Running) -> McpHttpStatus {
    let url = format!("http://127.0.0.1:{}/mcp", run.port);
    McpHttpStatus { client_config: Some(client_config_json(&url, &run.token)), url: Some(url), error: None }
}
