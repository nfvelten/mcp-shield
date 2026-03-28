use super::{AuditEntry, AuditLog, Outcome};
use async_trait::async_trait;

pub struct StdoutAudit;

#[async_trait]
impl AuditLog for StdoutAudit {
    fn record(&self, entry: AuditEntry) {
        let tool = entry.tool.as_deref().unwrap_or("-");
        match entry.outcome {
            Outcome::Allowed => {
                println!("[ALLOWED] agent={} method={} tool={}", entry.agent_id, entry.method, tool);
            }
            Outcome::Blocked(ref reason) => {
                println!(
                    "[BLOCKED] agent={} method={} tool={} reason={}",
                    entry.agent_id, entry.method, tool, reason
                );
            }
            Outcome::Forwarded => {
                println!("[PASS]    agent={} method={}", entry.agent_id, entry.method);
            }
        }
    }
}
