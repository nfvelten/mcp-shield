use super::McpUpstream;
use async_trait::async_trait;
use reqwest::{Client, ClientBuilder};
use serde_json::{Value, json};
use std::{
    sync::Arc,
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

// ── Circuit breaker ───────────────────────────────────────────────────────────

enum CbState {
    Closed,
    Open { until: Instant },
    HalfOpen,
}

struct CircuitBreaker {
    state: Mutex<CbState>,
    failure_count: AtomicUsize,
    threshold: usize,
    recovery_secs: u64,
}

impl CircuitBreaker {
    fn new(threshold: usize, recovery_secs: u64) -> Self {
        Self {
            state: Mutex::new(CbState::Closed),
            failure_count: AtomicUsize::new(0),
            threshold,
            recovery_secs,
        }
    }

    /// Returns true if the circuit is open (requests should be rejected immediately).
    async fn is_open(&self) -> bool {
        let mut state = self.state.lock().await;
        match &*state {
            CbState::Closed | CbState::HalfOpen => false,
            CbState::Open { until } => {
                if Instant::now() >= *until {
                    *state = CbState::HalfOpen;
                    tracing::info!("circuit entering half-open, probing upstream");
                    false
                } else {
                    true
                }
            }
        }
    }

    async fn on_success(&self) {
        let prev = self.failure_count.swap(0, Ordering::Relaxed);
        let mut state = self.state.lock().await;
        if !matches!(*state, CbState::Closed) {
            tracing::info!(
                previous_failures = prev,
                "upstream recovered, circuit closed"
            );
            *state = CbState::Closed;
        }
    }

    async fn on_failure(&self) {
        let count = self.failure_count.fetch_add(1, Ordering::Relaxed) + 1;
        if count >= self.threshold {
            let mut state = self.state.lock().await;
            let until = Instant::now() + Duration::from_secs(self.recovery_secs);
            *state = CbState::Open { until };
            self.failure_count.store(0, Ordering::Relaxed);
            tracing::warn!(
                failures = count,
                recovery_secs = self.recovery_secs,
                "circuit opened"
            );
        }
    }
}

// ── HttpUpstream ──────────────────────────────────────────────────────────────

pub struct HttpUpstream {
    url: String,
    client: Client,
    cb: Arc<CircuitBreaker>,
}

impl HttpUpstream {
    pub fn new(url: impl Into<String>) -> Self {
        Self::with_circuit_breaker(url, 5, 30)
    }

    pub fn with_circuit_breaker(
        url: impl Into<String>,
        threshold: usize,
        recovery_secs: u64,
    ) -> Self {
        let client = ClientBuilder::new()
            .timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(10)
            .build()
            .expect("failed to build HTTP client");
        Self {
            url: url.into(),
            client,
            cb: Arc::new(CircuitBreaker::new(threshold, recovery_secs)),
        }
    }
}

#[async_trait]
impl McpUpstream for HttpUpstream {
    async fn forward(&self, msg: &Value) -> Option<Value> {
        if self.cb.is_open().await {
            tracing::warn!("circuit open, rejecting request");
            return Some(json!({
                "jsonrpc": "2.0",
                "error": { "code": -32603, "message": "service unavailable (circuit open)" }
            }));
        }

        match self.client.post(&self.url).json(msg).send().await {
            Ok(resp) => {
                self.cb.on_success().await;
                if resp.status() == reqwest::StatusCode::ACCEPTED {
                    return None; // notification — no body
                }
                match resp.json::<Value>().await {
                    Ok(body) => Some(body),
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to parse upstream response");
                        Some(json!({
                            "jsonrpc": "2.0",
                            "error": { "code": -32603, "message": "internal error" }
                        }))
                    }
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "upstream request failed");
                self.cb.on_failure().await;
                Some(json!({
                    "jsonrpc": "2.0",
                    "error": { "code": -32603, "message": "service unavailable" }
                }))
            }
        }
    }

    fn base_url(&self) -> &str {
        &self.url
    }

    async fn is_healthy(&self) -> bool {
        !self.cb.is_open().await
    }
}
