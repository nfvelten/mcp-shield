use super::{Decision, McpContext, Middleware};
use crate::live_config::LiveConfig;
use async_trait::async_trait;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{watch, Mutex};

pub struct RateLimitMiddleware {
    config: watch::Receiver<Arc<LiveConfig>>,
    /// Per-agent sliding window counters — keyed by agent_id.
    counts: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
    /// Per-(agent, tool) sliding window counters for tool_rate_limits.
    tool_counts: Arc<Mutex<HashMap<(String, String), Vec<Instant>>>>,
    /// Per-IP sliding window counters (HTTP mode). Keyed by client IP string.
    ip_counts: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
}

impl RateLimitMiddleware {
    pub fn new(config: watch::Receiver<Arc<LiveConfig>>) -> Self {
        Self {
            config,
            counts: Arc::new(Mutex::new(HashMap::new())),
            tool_counts: Arc::new(Mutex::new(HashMap::new())),
            ip_counts: Arc::new(Mutex::new(HashMap::new())),
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

        let (global_limit, tool_limit, ip_limit) = {
            let cfg = self.config.borrow();
            let Some(policy) = cfg.agents.get(&ctx.agent_id) else {
                return Decision::Allow; // unknown agents are blocked by AuthMiddleware
            };
            let tool_limit = ctx
                .tool_name
                .as_ref()
                .and_then(|t| policy.tool_rate_limits.get(t).copied());
            (policy.rate_limit, tool_limit, cfg.ip_rate_limit)
        };

        let now = Instant::now();
        let window = Duration::from_secs(60);

        // ── IP rate limit (checked first — cheapest rejection) ─────────────────
        if let (Some(limit), Some(ip)) = (ip_limit, ctx.client_ip.as_ref()) {
            let mut ip_counts = self.ip_counts.lock().await;
            let ts = ip_counts.entry(ip.clone()).or_default();
            ts.retain(|t| now.duration_since(*t) < window);
            if ts.len() >= limit {
                return Decision::Block {
                    reason: format!("IP rate limit exceeded ({limit}/min)"),
                };
            }
            ts.push(now);
        }

        // ── Global agent rate limit ────────────────────────────────────────────
        {
            let mut counts = self.counts.lock().await;
            let ts = counts.entry(ctx.agent_id.clone()).or_default();
            ts.retain(|t| now.duration_since(*t) < window);

            if ts.len() >= global_limit {
                return Decision::Block {
                    reason: format!("rate limit exceeded ({global_limit}/min)"),
                };
            }
            ts.push(now);
            if ts.is_empty() {
                counts.remove(&ctx.agent_id);
            }
        }

        // ── Per-tool rate limit ────────────────────────────────────────────────
        if let (Some(limit), Some(tool)) = (tool_limit, ctx.tool_name.as_ref()) {
            let key = (ctx.agent_id.clone(), tool.clone());
            let mut tool_counts = self.tool_counts.lock().await;
            let ts = tool_counts.entry(key.clone()).or_default();
            ts.retain(|t| now.duration_since(*t) < window);

            if ts.len() >= limit {
                return Decision::Block {
                    reason: format!("tool '{tool}' rate limit exceeded ({limit}/min)"),
                };
            }
            ts.push(now);
            if ts.is_empty() {
                tool_counts.remove(&key);
            }
        }

        Decision::Allow
    }
}
