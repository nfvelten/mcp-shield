use super::Transport;
use crate::{config::TlsConfig, gateway::McpGateway, metrics::GatewayMetrics};
use async_trait::async_trait;
use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use serde_json::Value;
use std::{collections::HashMap, sync::Arc, time::Instant};
use tokio::sync::Mutex;
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
        // Purge expired sessions on every creation to bound memory usage
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
}

impl HttpTransport {
    pub fn new(
        addr: impl Into<String>,
        session_ttl_secs: u64,
        tls: Option<TlsConfig>,
        metrics: Arc<GatewayMetrics>,
    ) -> Self {
        Self { addr: addr.into(), session_ttl_secs, tls, metrics }
    }
}

struct HttpState {
    gateway: Arc<McpGateway>,
    sessions: Arc<SessionStore>,
    metrics: Arc<GatewayMetrics>,
}

const MAX_AGENT_ID_LEN: usize = 128;

#[async_trait]
impl Transport for HttpTransport {
    async fn serve(&self, gateway: Arc<McpGateway>) -> anyhow::Result<()> {
        let state = Arc::new(HttpState {
            gateway,
            sessions: Arc::new(SessionStore::new(self.session_ttl_secs)),
            metrics: Arc::clone(&self.metrics),
        });

        let app = Router::new()
            .route("/mcp", post(handle_mcp))
            .route("/mcp", delete(handle_delete_session))
            .route("/metrics", get(handle_metrics))
            .with_state(state);

        if let Some(tls) = &self.tls {
            eprintln!("[GATEWAY] HTTPS mode listening on https://{}", self.addr);
            serve_tls(app, &self.addr, &tls.cert, &tls.key).await
        } else {
            eprintln!("[GATEWAY] HTTP mode listening on http://{}", self.addr);
            let listener = tokio::net::TcpListener::bind(&self.addr).await?;
            axum::serve(listener, app)
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
        .serve(app.into_make_service())
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
    eprintln!("[GATEWAY] shutdown signal received, draining audit...");
}

// ── Handlers ─────────────────────────────────────────────────────────────────

async fn handle_mcp(
    State(state): State<Arc<HttpState>>,
    headers: HeaderMap,
    Json(msg): Json<Value>,
) -> impl IntoResponse {
    let method = msg["method"].as_str().unwrap_or("");

    // initialize: create session and inject Mcp-Session-Id into response
    if method == "initialize" {
        let agent_name = msg["params"]["clientInfo"]["name"]
            .as_str()
            .unwrap_or("unknown");

        if agent_name.len() > MAX_AGENT_ID_LEN {
            return StatusCode::BAD_REQUEST.into_response();
        }

        let agent_name = agent_name.to_string();
        let session_id = state.sessions.create(agent_name.clone()).await;
        eprintln!("[SESSION] created id={session_id} agent={agent_name}");

        return match state.gateway.handle(&agent_name, msg).await {
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

    // All subsequent requests must carry a valid Mcp-Session-Id.
    // Per MCP spec, an unknown or expired session returns 404.
    match resolve_agent(&state.sessions, &headers).await {
        Ok(agent_id) => match state.gateway.handle(&agent_id, msg).await {
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
        eprintln!("[SESSION] invalidated id={sid}");
        StatusCode::NO_CONTENT.into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
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
