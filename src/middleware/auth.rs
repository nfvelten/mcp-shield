use super::{Decision, McpContext, Middleware};
use crate::config::AgentPolicy;
use async_trait::async_trait;
use std::{collections::HashMap, sync::Arc};

pub struct AuthMiddleware {
    agents: Arc<HashMap<String, AgentPolicy>>,
}

impl AuthMiddleware {
    pub fn new(agents: Arc<HashMap<String, AgentPolicy>>) -> Self {
        Self { agents }
    }
}

#[async_trait]
impl Middleware for AuthMiddleware {
    fn name(&self) -> &'static str {
        "auth"
    }

    async fn check(&self, ctx: &McpContext) -> Decision {
        if ctx.method != "tools/call" {
            return Decision::Allow;
        }

        let tool = ctx.tool_name.as_deref().unwrap_or("");

        let Some(policy) = self.agents.get(&ctx.agent_id) else {
            return Decision::Block {
                reason: format!("unknown agent '{}'", ctx.agent_id),
            };
        };

        if policy.denied_tools.iter().any(|t| t == tool) {
            return Decision::Block {
                reason: format!("tool '{tool}' explicitly denied"),
            };
        }

        if let Some(allowed) = &policy.allowed_tools {
            if !allowed.iter().any(|t| t == tool) {
                return Decision::Block {
                    reason: format!("tool '{tool}' not in allowlist"),
                };
            }
        }

        Decision::Allow
    }
}
