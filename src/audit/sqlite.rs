use super::{AuditEntry, AuditLog, Outcome};
use async_trait::async_trait;
use rusqlite::{params, Connection};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tokio::sync::mpsc;

pub struct SqliteAudit {
    tx: Arc<Mutex<Option<mpsc::UnboundedSender<Arc<AuditEntry>>>>>,
    handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl SqliteAudit {
    pub fn new(path: &str) -> anyhow::Result<Self> {
        Self::with_rotation(path, None, None)
    }

    pub fn with_rotation(
        path: &str,
        max_entries: Option<usize>,
        max_age_days: Option<u64>,
    ) -> anyhow::Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS audit_log (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                ts        INTEGER NOT NULL,
                agent_id  TEXT    NOT NULL,
                method    TEXT    NOT NULL,
                tool      TEXT,
                outcome   TEXT    NOT NULL,
                reason    TEXT
            );",
        )?;
        let conn = Arc::new(Mutex::new(conn));
        let (tx, mut rx) = mpsc::unbounded_channel::<Arc<AuditEntry>>();

        let handle = tokio::spawn(async move {
            while let Some(entry) = rx.recv().await {
                let ts = entry
                    .ts
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;

                let (outcome_str, reason) = match &entry.outcome {
                    Outcome::Allowed => ("allowed".to_string(), None),
                    Outcome::Blocked(r) => ("blocked".to_string(), Some(r.clone())),
                    Outcome::Forwarded => ("forwarded".to_string(), None),
                };

                // Emit structured log for every persisted entry
                match &entry.outcome {
                    Outcome::Allowed => tracing::info!(
                        outcome = "allowed",
                        agent = %entry.agent_id,
                        method = %entry.method,
                        tool = entry.tool.as_deref().unwrap_or("-"),
                    ),
                    Outcome::Blocked(r) => tracing::info!(
                        outcome = "blocked",
                        agent = %entry.agent_id,
                        method = %entry.method,
                        tool = entry.tool.as_deref().unwrap_or("-"),
                        reason = %r,
                    ),
                    Outcome::Forwarded => tracing::info!(
                        outcome = "forwarded",
                        agent = %entry.agent_id,
                        method = %entry.method,
                    ),
                }

                let conn = conn.clone();
                tokio::task::spawn_blocking(move || {
                    if let Ok(c) = conn.lock() {
                        if let Err(e) = c.execute(
                            "INSERT INTO audit_log (ts, agent_id, method, tool, outcome, reason)
                             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                            params![
                                ts,
                                entry.agent_id,
                                entry.method,
                                entry.tool,
                                outcome_str,
                                reason
                            ],
                        ) {
                            tracing::error!(
                                error = %e,
                                agent = %entry.agent_id,
                                "audit insert failed"
                            );
                        }

                        // Rotate by entry count — keep only the newest N rows
                        if let Some(max) = max_entries
                            && let Err(e) = c.execute(
                                "DELETE FROM audit_log WHERE id NOT IN \
                                 (SELECT id FROM audit_log ORDER BY id DESC LIMIT ?1)",
                                params![max as i64],
                            )
                        {
                            tracing::warn!(error = %e, "audit rotation (max_entries) failed");
                        }
                        // Rotate by age — purge entries older than max_age_days
                        if let Some(days) = max_age_days {
                            let cutoff = SystemTime::now()
                                .duration_since(SystemTime::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs() as i64
                                - (days as i64 * 86400);
                            if let Err(e) = c.execute(
                                "DELETE FROM audit_log WHERE ts < ?1",
                                params![cutoff],
                            ) {
                                tracing::warn!(error = %e, "audit rotation (max_age_days) failed");
                            }
                        }
                    }
                })
                .await
                .ok();
            }
        });

        Ok(Self {
            tx: Arc::new(Mutex::new(Some(tx))),
            handle: Arc::new(Mutex::new(Some(handle))),
        })
    }
}

#[async_trait]
impl AuditLog for SqliteAudit {
    fn record(&self, entry: Arc<AuditEntry>) {
        if let Ok(guard) = self.tx.lock() {
            if let Some(tx) = guard.as_ref() {
                let _ = tx.send(entry);
            }
        }
    }

    async fn flush(&self) {
        // Drop sender to signal EOF to the worker task
        {
            let mut guard = self.tx.lock().unwrap();
            *guard = None;
        }
        // Await the worker to finish processing all queued entries
        let handle = {
            let mut guard = self.handle.lock().unwrap();
            guard.take()
        };
        if let Some(h) = handle {
            let _ = h.await;
        }
    }
}
