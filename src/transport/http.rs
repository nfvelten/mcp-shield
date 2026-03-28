use super::Transport;
use crate::gateway::McpGateway;
use async_trait::async_trait;
use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use serde_json::Value;
use std::{collections::HashMap, sync::Arc, time::Instant};
use tokio::sync::Mutex;
use uuid::Uuid;

const SESSION_MAX_AGE_SECS: u64 = 3600; // 1 hour
const MAX_AGENT_ID_LEN: usize = 128;

// ── Session store ────────────────────────────────────────────────────────────

struct SessionStore {
    /// session_id → (agent_id, created_at)
    sessions: Mutex<HashMap<String, (String, Instant)>>,
}

impl SessionStore {
    fn new() -> Self {
        Self { sessions: Mutex::new(HashMap::new()) }
    }

    async fn create(&self, agent_id: String) -> String {
        let id = Uuid::new_v4().to_string();
        let mut sessions = self.sessions.lock().await;
        // Purge expired sessions on every creation to bound memory usage
        let now = Instant::now();
        sessions.retain(|_, (_, created)| {
            now.duration_since(*created).as_secs() < SESSION_MAX_AGE_SECS
        });
        sessions.insert(id.clone(), (agent_id, now));
        id
    }

    async fn resolve(&self, session_id: &str) -> Option<String> {
        let sessions = self.sessions.lock().await;
        sessions.get(session_id).and_then(|(agent_id, created)| {
            let expired = Instant::now().duration_since(*created).as_secs() >= SESSION_MAX_AGE_SECS;
            if expired { None } else { Some(agent_id.clone()) }
        })
    }
}

// ── Transport ────────────────────────────────────────────────────────────────

pub struct HttpTransport {
    addr: String,
}

impl HttpTransport {
    pub fn new(addr: impl Into<String>) -> Self {
        Self { addr: addr.into() }
    }
}

struct HttpState {
    gateway: Arc<McpGateway>,
    sessions: Arc<SessionStore>,
}

#[async_trait]
impl Transport for HttpTransport {
    async fn serve(&self, gateway: Arc<McpGateway>) -> anyhow::Result<()> {
        let state = Arc::new(HttpState {
            gateway,
            sessions: Arc::new(SessionStore::new()),
        });

        let app = Router::new()
            .route("/mcp", post(handle_mcp))
            .with_state(state);

        eprintln!("[GATEWAY] HTTP mode listening on http://{}", self.addr);
        let listener = tokio::net::TcpListener::bind(&self.addr).await?;
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await?;
        Ok(())
    }
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

// ── Handler ──────────────────────────────────────────────────────────────────

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

        // Reject oversized or malformed agent IDs before they touch any data structure
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
