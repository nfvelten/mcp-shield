use super::Transport;
use crate::{
    config::TlsConfig,
    gateway::McpGateway,
    jwt::JwtValidator,
    live_config::LiveConfig,
    metrics::GatewayMetrics,
};
use async_trait::async_trait;
use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use axum::response::sse::{Event, KeepAlive, Sse};
use futures_util::StreamExt;
use serde_json::Value;
use std::{collections::HashMap, convert::Infallible, net::SocketAddr, sync::Arc, time::Instant};
use tokio::sync::{watch, Mutex};
use uuid::Uuid;

// ── Session store ────────────────────────────────────────────────────────────

struct SessionStore {
    /// session_id → (agent_id, created_at)
    sessions: Mutex<HashMap<String, (String, Instant)>>,
    ttl_secs: u64,
}

impl SessionStore {
    fn new(ttl_secs: u64) -> Self {
        Self { sessions: Mutex::new(HashMap::new()), ttl_secs }
    }

    async fn create(&self, agent_id: String) -> String {
        let id = Uuid::new_v4().to_string();
        let mut sessions = self.sessions.lock().await;
        let now = Instant::now();
        let ttl = self.ttl_secs;
        sessions.retain(|_, (_, created)| now.duration_since(*created).as_secs() < ttl);
        sessions.insert(id.clone(), (agent_id, now));
        id
    }

    async fn resolve(&self, session_id: &str) -> Option<String> {
        let sessions = self.sessions.lock().await;
        sessions.get(session_id).and_then(|(agent_id, created)| {
            let expired = Instant::now().duration_since(*created).as_secs() >= self.ttl_secs;
            if expired { None } else { Some(agent_id.clone()) }
        })
    }

    async fn invalidate(&self, session_id: &str) -> bool {
        let mut sessions = self.sessions.lock().await;
        sessions.remove(session_id).is_some()
    }
}

// ── Transport ────────────────────────────────────────────────────────────────

pub struct HttpTransport {
    addr: String,
    session_ttl_secs: u64,
    tls: Option<TlsConfig>,
    metrics: Arc<GatewayMetrics>,
    config: watch::Receiver<Arc<LiveConfig>>,
    jwt: Option<Arc<JwtValidator>>,
    /// Path to the SQLite audit DB for the /dashboard endpoint.
    /// None when audit is not SQLite or dashboard is disabled.
    audit_db: Option<String>,
}

impl HttpTransport {
    pub fn new(
        addr: impl Into<String>,
        session_ttl_secs: u64,
        tls: Option<TlsConfig>,
        metrics: Arc<GatewayMetrics>,
        config: watch::Receiver<Arc<LiveConfig>>,
        jwt: Option<Arc<JwtValidator>>,
        audit_db: Option<String>,
    ) -> Self {
        Self { addr: addr.into(), session_ttl_secs, tls, metrics, config, jwt, audit_db }
    }
}

struct HttpState {
    gateway: Arc<McpGateway>,
    sessions: Arc<SessionStore>,
    metrics: Arc<GatewayMetrics>,
    config: watch::Receiver<Arc<LiveConfig>>,
    /// Optional JWT validator — present when `auth.jwt` is configured.
    jwt: Option<Arc<JwtValidator>>,
    audit_db: Option<String>,
}

const MAX_AGENT_ID_LEN: usize = 128;

#[async_trait]
impl Transport for HttpTransport {
    async fn serve(&self, gateway: Arc<McpGateway>) -> anyhow::Result<()> {
        let state = Arc::new(HttpState {
            gateway,
            sessions: Arc::new(SessionStore::new(self.session_ttl_secs)),
            metrics: Arc::clone(&self.metrics),
            config: self.config.clone(),
            jwt: self.jwt.clone(),
            audit_db: self.audit_db.clone(),
        });

        let app = Router::new()
            .route("/mcp", post(handle_mcp))
            .route("/mcp", get(handle_sse))
            .route("/mcp", delete(handle_delete_session))
            .route("/metrics", get(handle_metrics))
            .route("/health", get(handle_health))
            .route("/dashboard", get(handle_dashboard))
            .with_state(state);

        if let Some(tls) = &self.tls {
            tracing::info!(addr = %self.addr, "HTTPS mode listening");
            serve_tls(app, &self.addr, &tls.cert, &tls.key).await
        } else {
            tracing::info!(addr = %self.addr, "HTTP mode listening");
            let listener = tokio::net::TcpListener::bind(&self.addr).await?;
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(shutdown_signal())
            .await?;
            Ok(())
        }
    }
}

// ── TLS ───────────────────────────────────────────────────────────────────────

async fn serve_tls(app: Router, addr: &str, cert: &str, key: &str) -> anyhow::Result<()> {
    use axum_server::tls_rustls::RustlsConfig;

    let tls_config = RustlsConfig::from_pem_file(cert, key).await?;
    let addr: std::net::SocketAddr = addr.parse()?;

    let handle = axum_server::Handle::new();
    let h = handle.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        h.graceful_shutdown(Some(std::time::Duration::from_secs(30)));
    });

    axum_server::bind_rustls(addr, tls_config)
        .handle(handle)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;
    Ok(())
}

// ── Shutdown signal ───────────────────────────────────────────────────────────

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = sigterm.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.ok();
    }
    tracing::info!("shutdown signal received, draining audit");
}

// ── Handlers ─────────────────────────────────────────────────────────────────

async fn handle_mcp(
    State(state): State<Arc<HttpState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(msg): Json<Value>,
) -> impl IntoResponse {
    let client_ip = Some(peer.ip().to_string());
    let method = msg["method"].as_str().unwrap_or("");

    // initialize: resolve agent identity, validate api_key, create session
    if method == "initialize" {
        let claimed_name = msg["params"]["clientInfo"]["name"]
            .as_str()
            .unwrap_or("unknown");

        if claimed_name.len() > MAX_AGENT_ID_LEN {
            return StatusCode::BAD_REQUEST.into_response();
        }

        // JWT auth: if a JwtValidator is configured and the request carries
        // Authorization: Bearer <token>, validate it and use the token's claim
        // as the agent identity. api_key and clientInfo.name are both ignored.
        if let Some(validator) = &state.jwt {
            if let Some(bearer) = headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
            {
                match validator.validate(bearer).await {
                    Ok(agent_name) => {
                        let session_id = state.sessions.create(agent_name.clone()).await;
                        tracing::info!(session_id, agent = agent_name, "JWT session created");
                        return match state.gateway.handle(&agent_name, msg, client_ip).await {
                            Some(response) => {
                                let mut res = Json(response).into_response();
                                if let Ok(val) = HeaderValue::from_str(&session_id) {
                                    res.headers_mut().insert("mcp-session-id", val);
                                }
                                res
                            }
                            None => StatusCode::ACCEPTED.into_response(),
                        };
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "JWT validation failed");
                        return StatusCode::UNAUTHORIZED.into_response();
                    }
                }
            }
        }

        // Key-based identity: if X-Api-Key is provided, the key IS the identity.
        // The key maps to an agent name — clientInfo.name is ignored.
        // If no key is provided but the agent requires one → 401.
        let agent_name = {
            let cfg = state.config.borrow();
            if let Some(provided_key) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
                match cfg.api_keys.get(provided_key) {
                    Some(name) => name.clone(),
                    None => {
                        tracing::warn!("unknown api_key");
                        return StatusCode::UNAUTHORIZED.into_response();
                    }
                }
            } else {
                // No key: use claimed name, but reject if the agent requires a key
                if let Some(policy) = cfg.agents.get(claimed_name) {
                    if policy.api_key.is_some() {
                        tracing::warn!(agent = claimed_name, "api_key required but not provided");
                        return StatusCode::UNAUTHORIZED.into_response();
                    }
                }
                claimed_name.to_string()
            }
        };
        let session_id = state.sessions.create(agent_name.clone()).await;
        tracing::info!(session_id, agent = agent_name, "session created");

        return match state.gateway.handle(&agent_name, msg, client_ip).await {
            Some(response) => {
                let mut res = Json(response).into_response();
                if let Ok(val) = HeaderValue::from_str(&session_id) {
                    res.headers_mut().insert("mcp-session-id", val);
                }
                res
            }
            None => StatusCode::ACCEPTED.into_response(),
        };
    }

    match resolve_agent(&state.sessions, &headers).await {
        Ok(agent_id) => match state.gateway.handle(&agent_id, msg, client_ip).await {
            Some(response) => Json(response).into_response(),
            None => StatusCode::ACCEPTED.into_response(),
        },
        Err(status) => status.into_response(),
    }
}

async fn handle_delete_session(
    State(state): State<Arc<HttpState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let sid = match headers.get("mcp-session-id").and_then(|v| v.to_str().ok()) {
        Some(s) => s.to_string(),
        None => return StatusCode::BAD_REQUEST.into_response(),
    };
    if state.sessions.invalidate(&sid).await {
        tracing::info!(session_id = sid, "session invalidated");
        StatusCode::NO_CONTENT.into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

async fn handle_health() -> impl IntoResponse {
    use axum::http::StatusCode;
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "ok",
            "version": env!("CARGO_PKG_VERSION")
        })),
    )
}

async fn handle_metrics(State(state): State<Arc<HttpState>>) -> impl IntoResponse {
    let body = state.metrics.render();
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
}

// ── Dashboard ─────────────────────────────────────────────────────────────────

async fn handle_dashboard(State(state): State<Arc<HttpState>>) -> impl IntoResponse {
    use axum::http::header::CONTENT_TYPE;

    let Some(db_path) = &state.audit_db else {
        return (
            StatusCode::NOT_FOUND,
            [(CONTENT_TYPE, "text/plain")],
            "dashboard requires a sqlite audit backend".to_string(),
        )
            .into_response();
    };

    let db_path = db_path.clone();
    let rows: Vec<(i64, String, String, Option<String>, String, Option<String>)> =
        tokio::task::spawn_blocking(move || {
            let conn = rusqlite::Connection::open(&db_path)?;
            let mut stmt = conn.prepare(
                "SELECT ts, agent_id, method, tool, outcome, reason \
                 FROM audit_log ORDER BY id DESC LIMIT 200",
            )?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Option<String>>(5)?,
                    ))
                })?
                .filter_map(|r| r.ok())
                .collect();
            anyhow::Ok(rows)
        })
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or_default();

    let mut table_rows = String::new();
    for (ts, agent, method, tool, outcome, reason) in &rows {
        let dt = chrono_ts(*ts);
        let badge = match outcome.as_str() {
            "allowed" => r#"<span class="badge allowed">allowed</span>"#,
            "blocked" => r#"<span class="badge blocked">blocked</span>"#,
            _ => r#"<span class="badge forwarded">forwarded</span>"#,
        };
        let tool_str = html_escape(tool.as_deref().unwrap_or("—"));
        let reason_str = html_escape(reason.as_deref().unwrap_or(""));
        table_rows.push_str(&format!(
            "<tr><td>{dt}</td><td>{}</td><td>{}</td><td>{tool_str}</td><td>{badge}</td><td>{reason_str}</td></tr>\n",
            html_escape(agent),
            html_escape(method),
        ));
    }

    let total = rows.len();
    let html = format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>mcp-gateway — audit dashboard</title>
<style>
  body {{ font-family: system-ui, sans-serif; margin: 0; background: #f5f5f5; color: #222; }}
  header {{ background: #1a1a2e; color: #fff; padding: 1rem 2rem; display: flex; align-items: center; gap: 1rem; }}
  header h1 {{ margin: 0; font-size: 1.2rem; font-weight: 600; }}
  header span {{ font-size: .85rem; opacity: .7; }}
  main {{ padding: 1.5rem 2rem; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 4px rgba(0,0,0,.1); }}
  th {{ background: #eee; text-align: left; padding: .6rem 1rem; font-size: .8rem; text-transform: uppercase; letter-spacing: .05em; }}
  td {{ padding: .55rem 1rem; border-top: 1px solid #eee; font-size: .88rem; }}
  tr:hover td {{ background: #fafafa; }}
  .badge {{ display: inline-block; padding: .15rem .5rem; border-radius: 4px; font-size: .75rem; font-weight: 600; }}
  .allowed {{ background: #d4edda; color: #155724; }}
  .blocked {{ background: #f8d7da; color: #721c24; }}
  .forwarded {{ background: #cce5ff; color: #004085; }}
  .meta {{ margin-bottom: 1rem; font-size: .85rem; color: #666; }}
</style>
</head>
<body>
<header>
  <h1>mcp-gateway</h1>
  <span>audit dashboard — last {total} entries</span>
</header>
<main>
<p class="meta">Showing the most recent {total} audit entries (newest first). Refresh the page for live data.</p>
<table>
<thead><tr><th>Time</th><th>Agent</th><th>Method</th><th>Tool</th><th>Outcome</th><th>Reason</th></tr></thead>
<tbody>
{table_rows}</tbody>
</table>
</main>
</body>
</html>"#
    );

    (StatusCode::OK, [(CONTENT_TYPE, "text/html; charset=utf-8")], html).into_response()
}

fn chrono_ts(ts: i64) -> String {
    use std::time::{Duration, UNIX_EPOCH};
    let d = UNIX_EPOCH + Duration::from_secs(ts as u64);
    let secs = ts % 86400;
    let h = (secs / 3600) % 24;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    // Days since epoch → approximate date (good enough for display)
    let days = ts / 86400;
    let epoch_year = 1970i64;
    let mut year = epoch_year;
    let mut rem = days;
    loop {
        let dy = if is_leap(year) { 366 } else { 365 };
        if rem < dy { break; }
        rem -= dy;
        year += 1;
    }
    let months = if is_leap(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 1i64;
    for &days_in_month in &months {
        if rem < days_in_month { break; }
        rem -= days_in_month;
        month += 1;
    }
    let day = rem + 1;
    format!("{year}-{month:02}-{day:02} {h:02}:{m:02}:{s:02}")
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

// ── SSE proxy ─────────────────────────────────────────────────────────────────

/// GET /mcp — MCP SSE transport.
///
/// With a valid `Mcp-Session-Id`: proxies the upstream SSE stream for that agent,
/// applying response filtering to each event.
///
/// Without a session (legacy HTTP+SSE transport): sends an `endpoint` event that
/// tells the client where to POST `initialize`.
async fn handle_sse(
    State(state): State<Arc<HttpState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    match resolve_agent(&state.sessions, &headers).await {
        Ok(agent_id) => {
            let upstream_url = state.gateway.upstream_url_for(&agent_id);
            if upstream_url.is_empty() {
                // Upstream is stdio — SSE proxy not supported in stdio mode
                return StatusCode::NOT_IMPLEMENTED.into_response();
            }
            let config_rx = state.config.clone();
            sse_proxy(upstream_url, config_rx).await.into_response()
        }
        Err(_) => {
            // Legacy HTTP+SSE: no session yet — send endpoint event
            let stream = futures_util::stream::once(async {
                Ok::<Event, Infallible>(
                    Event::default().event("endpoint").data("/mcp"),
                )
            });
            Sse::new(stream).into_response()
        }
    }
}

/// Connects to the upstream SSE endpoint and proxies events downstream,
/// filtering each event's data through the live block_patterns.
async fn sse_proxy(
    upstream_url: String,
    config_rx: watch::Receiver<Arc<LiveConfig>>,
) -> impl IntoResponse {
    let client = reqwest::Client::new();
    let resp = client
        .get(&upstream_url)
        .header("Accept", "text/event-stream")
        .send()
        .await;

    let resp = match resp {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => {
            tracing::warn!(status = %r.status(), "SSE upstream returned error");
            return StatusCode::BAD_GATEWAY.into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "SSE upstream connection failed");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Event, Infallible>>(32);

    tokio::spawn(async move {
        let mut byte_stream = resp.bytes_stream();
        let mut buf = String::new();

        while let Some(chunk) = byte_stream.next().await {
            let Ok(bytes) = chunk else { break };
            buf.push_str(&String::from_utf8_lossy(&bytes));

            // SSE events are separated by blank lines (\n\n)
            while let Some(pos) = buf.find("\n\n") {
                let raw = buf[..pos].to_string();
                buf = buf[pos + 2..].to_string();

                if let Some(event) = parse_and_filter_sse(&raw, &config_rx) {
                    if tx.send(Ok(event)).await.is_err() {
                        return; // client disconnected
                    }
                }
            }
        }
    });

    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    Sse::new(stream).keep_alive(KeepAlive::default()).into_response()
}

/// Parse a raw SSE event block, apply response filtering, return an axum `Event`.
/// Returns `None` if the event is dropped by the filter.
fn parse_and_filter_sse(
    raw: &str,
    config_rx: &watch::Receiver<Arc<LiveConfig>>,
) -> Option<Event> {
    let mut event_type = "message".to_string();
    let mut data_parts: Vec<&str> = Vec::new();
    let mut comment: Option<&str> = None;

    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("event: ") {
            event_type = rest.to_string();
        } else if let Some(rest) = line.strip_prefix("data: ") {
            data_parts.push(rest);
        } else if let Some(rest) = line.strip_prefix(": ") {
            comment = Some(rest);
        }
    }

    // SSE comment (keepalive) — pass through
    if data_parts.is_empty() {
        return comment.map(|_| Event::default().comment(""));
    }

    let data = data_parts.join("\n");

    // Apply block patterns to the event data — replace matches with [REDACTED]
    let data = {
        let cfg = config_rx.borrow();
        let mut out = data;
        for pattern in &cfg.block_patterns {
            if pattern.is_match(&out) {
                tracing::info!(pattern = pattern.as_str(), "sensitive data redacted from SSE event");
                out = pattern.replace_all(&out, "[REDACTED]").into_owned();
            }
        }
        out
    };

    Some(Event::default().event(event_type).data(data))
}

/// Resolve agent_id from Mcp-Session-Id (MCP spec).
/// Falls back to x-agent-id header for clients that skip session management.
/// Returns 404 if Mcp-Session-Id is present but unknown or expired.
async fn resolve_agent(
    sessions: &SessionStore,
    headers: &HeaderMap,
) -> Result<String, StatusCode> {
    if let Some(sid) = headers.get("mcp-session-id").and_then(|v| v.to_str().ok()) {
        return sessions.resolve(sid).await.ok_or(StatusCode::NOT_FOUND);
    }
    Ok(headers
        .get("x-agent-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string())
}
