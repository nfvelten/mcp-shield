use super::{Decision, McpContext, Middleware};
use crate::live_config::LiveConfig;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::watch;

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;
    use serde_json::json;
    use std::collections::HashMap;

    fn make_mw(patterns: Vec<Regex>) -> PayloadFilterMiddleware {
        let live = Arc::new(LiveConfig::new(HashMap::new(), patterns, None));
        let (_, rx) = watch::channel(live);
        PayloadFilterMiddleware::new(rx)
    }

    fn ctx_call(tool: &str, args: serde_json::Value) -> McpContext {
        McpContext {
            agent_id: "agent".to_string(),
            method: "tools/call".to_string(),
            tool_name: Some(tool.to_string()),
            arguments: Some(args),
            client_ip: None,
        }
    }

    #[tokio::test]
    async fn non_tools_call_skipped() {
        let re = Regex::new("secret").unwrap();
        let mw = make_mw(vec![re]);
        let ctx = McpContext {
            agent_id: "a".to_string(),
            method: "initialize".to_string(),
            tool_name: None,
            arguments: Some(json!({"secret": "value"})),
            client_ip: None,
        };
        assert!(matches!(mw.check(&ctx).await, Decision::Allow));
    }

    #[tokio::test]
    async fn no_arguments_allowed() {
        let re = Regex::new("secret").unwrap();
        let mw = make_mw(vec![re]);
        let ctx = McpContext {
            agent_id: "a".to_string(),
            method: "tools/call".to_string(),
            tool_name: Some("echo".to_string()),
            arguments: None,
            client_ip: None,
        };
        assert!(matches!(mw.check(&ctx).await, Decision::Allow));
    }

    #[tokio::test]
    async fn no_patterns_always_allowed() {
        let mw = make_mw(vec![]);
        let ctx = ctx_call("echo", json!({"secret_password": "hunter2"}));
        assert!(matches!(mw.check(&ctx).await, Decision::Allow));
    }

    #[tokio::test]
    async fn matching_pattern_blocks() {
        let re = Regex::new("private_key").unwrap();
        let mw = make_mw(vec![re]);
        let ctx = ctx_call("echo", json!({"input": "private_key=AAABBB"}));
        assert!(matches!(mw.check(&ctx).await, Decision::Block { .. }));
    }

    #[tokio::test]
    async fn non_matching_pattern_allows() {
        let re = Regex::new("private_key").unwrap();
        let mw = make_mw(vec![re]);
        let ctx = ctx_call("echo", json!({"input": "harmless text"}));
        assert!(matches!(mw.check(&ctx).await, Decision::Allow));
    }

    #[tokio::test]
    async fn block_reason_contains_pattern() {
        let re = Regex::new("secret").unwrap();
        let mw = make_mw(vec![re]);
        let ctx = ctx_call("echo", json!({"msg": "my secret value"}));
        if let Decision::Block { reason } = mw.check(&ctx).await {
            assert!(reason.contains("secret"));
        } else {
            panic!("expected Block");
        }
    }
}

pub struct PayloadFilterMiddleware {
    config: watch::Receiver<Arc<LiveConfig>>,
}

impl PayloadFilterMiddleware {
    pub fn new(config: watch::Receiver<Arc<LiveConfig>>) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Middleware for PayloadFilterMiddleware {
    fn name(&self) -> &'static str {
        "payload_filter"
    }

    async fn check(&self, ctx: &McpContext) -> Decision {
        if ctx.method != "tools/call" {
            return Decision::Allow;
        }

        let args = match &ctx.arguments {
            Some(v) => v,
            None => return Decision::Allow,
        };

        // Snapshot patterns — Arc clone is O(1); no per-Regex allocation
        let patterns = {
            let cfg = self.config.borrow();
            if cfg.block_patterns.is_empty() {
                return Decision::Allow;
            }
            Arc::clone(&cfg.block_patterns)
        };

        let text = args.to_string();
        for pattern in patterns.as_ref() {
            if pattern.is_match(&text) {
                return Decision::Block {
                    reason: format!("sensitive data detected (pattern: {})", pattern.as_str()),
                };
            }
        }

        Decision::Allow
    }
}
