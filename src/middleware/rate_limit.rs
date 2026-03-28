use super::{Decision, McpContext, Middleware};
use crate::config::AgentPolicy;
use async_trait::async_trait;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

pub struct RateLimitMiddleware {
    /// Per-agent limit (calls/min)
    limits: HashMap<String, usize>,
    /// Timestamps of calls within the 60s sliding window
    counts: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
}

impl RateLimitMiddleware {
    pub fn new(agents: &HashMap<String, AgentPolicy>) -> Self {
        Self {
            limits: agents.iter().map(|(k, v)| (k.clone(), v.rate_limit)).collect(),
            counts: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl Middleware for RateLimitMiddleware {
    fn name(&self) -> &'static str {
        "rate_limit"
    }

    async fn check(&self, ctx: &McpContext) -> Decision {
        if ctx.method != "tools/call" {
            return Decision::Allow;
        }

        // Unknown agents are already blocked by AuthMiddleware
        let Some(&limit) = self.limits.get(&ctx.agent_id) else {
            return Decision::Allow;
        };

        let now = Instant::now();
        let window = Duration::from_secs(60);

        let mut counts = self.counts.lock().await;
        let ts = counts.entry(ctx.agent_id.clone()).or_default();
        ts.retain(|t| now.duration_since(*t) < window);

        if ts.len() >= limit {
            return Decision::Block {
                reason: format!("rate limit exceeded ({limit}/min)"),
            };
        }
        ts.push(now);

        // Remove the entry entirely when the window is empty to bound memory growth
        if ts.is_empty() {
            counts.remove(&ctx.agent_id);
        }

        Decision::Allow
    }
}
