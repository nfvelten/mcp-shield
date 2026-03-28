use super::McpUpstream;
use async_trait::async_trait;
use reqwest::{Client, ClientBuilder};
use serde_json::{json, Value};
use std::time::Duration;

pub struct HttpUpstream {
    url: String,
    client: Client,
}

impl HttpUpstream {
    pub fn new(url: impl Into<String>) -> Self {
        let client = ClientBuilder::new()
            .timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(10)
            .build()
            .expect("failed to build HTTP client");
        Self { url: url.into(), client }
    }
}

#[async_trait]
impl McpUpstream for HttpUpstream {
    async fn forward(&self, msg: &Value) -> Option<Value> {
        match self.client.post(&self.url).json(msg).send().await {
            Ok(resp) => {
                if resp.status() == reqwest::StatusCode::ACCEPTED {
                    return None; // notification — no body
                }
                match resp.json::<Value>().await {
                    Ok(body) => Some(body),
                    Err(e) => {
                        eprintln!("[UPSTREAM] failed to parse response: {e}");
                        Some(json!({
                            "jsonrpc": "2.0",
                            "error": { "code": -32603, "message": "internal error" }
                        }))
                    }
                }
            }
            Err(e) => {
                eprintln!("[UPSTREAM] request failed: {e}");
                Some(json!({
                    "jsonrpc": "2.0",
                    "error": { "code": -32603, "message": "service unavailable" }
                }))
            }
        }
    }
}
