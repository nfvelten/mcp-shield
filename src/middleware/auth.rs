use super::{Decision, McpContext, Middleware};
use crate::{config::tool_matches, live_config::LiveConfig};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::watch;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{FilterMode, make_agent};
    use std::collections::HashMap;

    fn make_mw(agents: HashMap<String, crate::config::AgentPolicy>) -> AuthMiddleware {
        let live = Arc::new(LiveConfig::new(
            agents,
            vec![],
            vec![],
            None,
            FilterMode::Block,
            None,
        ));
        let (_, rx) = watch::channel(live);
        AuthMiddleware::new(rx)
    }

    fn ctx(agent: &str, method: &str, tool: Option<&str>) -> McpContext {
        McpContext {
            agent_id: agent.to_string(),
            method: method.to_string(),
            tool_name: tool.map(String::from),
            arguments: None,
            client_ip: None,
        }
    }

    #[tokio::test]
    async fn non_tools_call_always_allowed() {
        let mw = make_mw(HashMap::new()); // unknown agent but method != tools/call
        assert!(matches!(
            mw.check(&ctx("nobody", "initialize", None)).await,
            Decision::Allow { rl: None }
        ));
        assert!(matches!(
            mw.check(&ctx("nobody", "notifications/initialized", None))
                .await,
            Decision::Allow { rl: None }
        ));
    }

    #[tokio::test]
    async fn unknown_agent_blocked_on_tools_call() {
        let mw = make_mw(HashMap::new());
        assert!(matches!(
            mw.check(&ctx("ghost", "tools/call", Some("echo"))).await,
            Decision::Block { .. }
        ));
    }

    #[tokio::test]
    async fn denied_tool_blocked() {
        let mut agents = HashMap::new();
        agents.insert(
            "cursor".to_string(),
            make_agent(None, vec!["write_file"], 60),
        );
        let mw = make_mw(agents);
        assert!(matches!(
            mw.check(&ctx("cursor", "tools/call", Some("write_file")))
                .await,
            Decision::Block { .. }
        ));
    }

    #[tokio::test]
    async fn non_denied_tool_allowed_without_allowlist() {
        let mut agents = HashMap::new();
        agents.insert(
            "cursor".to_string(),
            make_agent(None, vec!["write_file"], 60),
        );
        let mw = make_mw(agents);
        assert!(matches!(
            mw.check(&ctx("cursor", "tools/call", Some("read_file")))
                .await,
            Decision::Allow { rl: None }
        ));
    }

    #[tokio::test]
    async fn allowlist_permits_listed_tool() {
        let mut agents = HashMap::new();
        agents.insert(
            "claude".to_string(),
            make_agent(Some(vec!["read_file"]), vec![], 60),
        );
        let mw = make_mw(agents);
        assert!(matches!(
            mw.check(&ctx("claude", "tools/call", Some("read_file")))
                .await,
            Decision::Allow { rl: None }
        ));
    }

    #[tokio::test]
    async fn allowlist_blocks_unlisted_tool() {
        let mut agents = HashMap::new();
        agents.insert(
            "claude".to_string(),
            make_agent(Some(vec!["read_file"]), vec![], 60),
        );
        let mw = make_mw(agents);
        assert!(matches!(
            mw.check(&ctx("claude", "tools/call", Some("delete_file")))
                .await,
            Decision::Block { .. }
        ));
    }

    #[tokio::test]
    async fn denied_takes_priority_over_allowlist() {
        let mut agents = HashMap::new();
        agents.insert(
            "cursor".to_string(),
            make_agent(
                Some(vec!["read_file", "write_file"]),
                vec!["write_file"],
                60,
            ),
        );
        let mw = make_mw(agents);
        // Even though write_file is in allowed_tools, denied_tools wins
        assert!(matches!(
            mw.check(&ctx("cursor", "tools/call", Some("write_file")))
                .await,
            Decision::Block { .. }
        ));
    }
}

pub struct AuthMiddleware {
    config: watch::Receiver<Arc<LiveConfig>>,
}

impl AuthMiddleware {
    pub fn new(config: watch::Receiver<Arc<LiveConfig>>) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Middleware for AuthMiddleware {
    fn name(&self) -> &'static str {
        "auth"
    }

    async fn check(&self, ctx: &McpContext) -> Decision {
        if ctx.method != "tools/call" {
            return Decision::Allow { rl: None };
        }

        let tool = ctx.tool_name.as_deref().unwrap_or("");
        let cfg = self.config.borrow();
        let Some(policy) = cfg
            .agents
            .get(&ctx.agent_id)
            .or(cfg.default_policy.as_ref())
        else {
            return Decision::Block {
                reason: format!("unknown agent '{}'", ctx.agent_id),
                rl: None,
            };
        };

        if policy.denied_tools.iter().any(|t| tool_matches(t, tool)) {
            return Decision::Block {
                reason: format!("tool '{tool}' explicitly denied"),
                rl: None,
            };
        }

        if let Some(allowed) = &policy.allowed_tools
            && !allowed.iter().any(|t| tool_matches(t, tool))
        {
            return Decision::Block {
                reason: format!("tool '{tool}' not in allowlist"),
                rl: None,
            };
        }

        Decision::Allow { rl: None }
    }
}
