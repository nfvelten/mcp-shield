use super::{Decision, McpContext, Middleware};
use async_trait::async_trait;
use regex::Regex;

pub struct PayloadFilterMiddleware {
    patterns: Vec<Regex>,
}

impl PayloadFilterMiddleware {
    pub fn new(patterns: Vec<Regex>) -> Self {
        Self { patterns }
    }
}

#[async_trait]
impl Middleware for PayloadFilterMiddleware {
    fn name(&self) -> &'static str {
        "payload_filter"
    }

    async fn check(&self, ctx: &McpContext) -> Decision {
        if ctx.method != "tools/call" || self.patterns.is_empty() {
            return Decision::Allow;
        }

        let args = match &ctx.arguments {
            Some(v) => v,
            None => return Decision::Allow,
        };

        // Serialize once, reuse for all pattern checks
        let text = args.to_string();

        for pattern in &self.patterns {
            if pattern.is_match(&text) {
                return Decision::Block {
                    reason: format!("sensitive data detected (pattern: {})", pattern.as_str()),
                };
            }
        }

        Decision::Allow
    }
}
