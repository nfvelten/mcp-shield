pub mod sqlite;
pub mod stdout;
pub mod webhook;

use async_trait::async_trait;
use std::time::SystemTime;

pub struct AuditEntry {
    pub ts: SystemTime,
    pub agent_id: String,
    pub method: String,
    pub tool: Option<String>,
    pub outcome: Outcome,
}

pub enum Outcome {
    Allowed,
    Blocked(String),
    Forwarded,
}

/// Pluggable audit log — swap SQLite, file, or external service
/// without changing anything in the gateway core.
#[async_trait]
pub trait AuditLog: Send + Sync {
    fn record(&self, entry: AuditEntry);
    /// Flush all pending writes. Called on graceful shutdown.
    async fn flush(&self) {}
}
