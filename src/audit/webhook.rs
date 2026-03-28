use super::{AuditEntry, AuditLog, Outcome};
use async_trait::async_trait;
use reqwest::Client;
use serde_json::json;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tokio::sync::mpsc;

pub struct WebhookAudit {
    tx: Arc<Mutex<Option<mpsc::UnboundedSender<AuditEntry>>>>,
    handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl WebhookAudit {
    pub fn new(url: impl Into<String>, token: Option<String>) -> Self {
        let url = url.into();
        let client = Client::new();
        let (tx, mut rx) = mpsc::unbounded_channel::<AuditEntry>();

        let handle = tokio::spawn(async move {
            while let Some(entry) = rx.recv().await {
                let ts = entry
                    .ts
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                let (outcome_str, reason) = match &entry.outcome {
                    Outcome::Allowed => ("allowed", None),
                    Outcome::Blocked(r) => ("blocked", Some(r.as_str())),
                    Outcome::Forwarded => ("forwarded", None),
                };

                let body = json!({
                    "ts": ts,
                    "agent_id": entry.agent_id,
                    "method": entry.method,
                    "tool": entry.tool,
                    "outcome": outcome_str,
                    "reason": reason,
                });

                let mut req = client.post(&url).json(&body);
                if let Some(tok) = &token {
                    req = req.header("Authorization", format!("Bearer {tok}"));
                }

                if let Err(e) = req.send().await {
                    eprintln!("[WEBHOOK] delivery failed: {e}");
                }
            }
        });

        Self {
            tx: Arc::new(Mutex::new(Some(tx))),
            handle: Arc::new(Mutex::new(Some(handle))),
        }
    }
}

#[async_trait]
impl AuditLog for WebhookAudit {
    fn record(&self, entry: AuditEntry) {
        if let Ok(guard) = self.tx.lock() {
            if let Some(tx) = guard.as_ref() {
                let _ = tx.send(entry);
            }
        }
    }

    async fn flush(&self) {
        {
            let mut guard = self.tx.lock().unwrap();
            *guard = None;
        }
        let handle = {
            let mut guard = self.handle.lock().unwrap();
            guard.take()
        };
        if let Some(h) = handle {
            let _ = h.await;
        }
    }
}
