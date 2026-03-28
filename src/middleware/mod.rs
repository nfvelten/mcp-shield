pub mod auth;
pub mod payload_filter;
pub mod rate_limit;

use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;

/// Immutable context for an MCP request, passed through the entire pipeline.
pub struct McpContext {
    pub agent_id: String,
    pub method: String,
    pub tool_name: Option<String>,
    pub arguments: Option<Value>,
    /// Client IP address — present in HTTP mode, None in stdio mode.
    pub client_ip: Option<String>,
}

/// Middleware decision: continue or block with a reason.
pub enum Decision {
    Allow,
    Block { reason: String },
}

/// Core trait — each middleware implements `check`.
/// Returning `Allow` means "no objection, pass it along".
/// Returning `Block` stops the pipeline immediately.
#[async_trait]
pub trait Middleware: Send + Sync {
    fn name(&self) -> &'static str;
    async fn check(&self, ctx: &McpContext) -> Decision;
}

/// Composable pipeline — middlewares are executed in insertion order.
#[derive(Default)]
pub struct Pipeline {
    middlewares: Vec<Arc<dyn Middleware>>,
}

impl Pipeline {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(mut self, mw: Arc<dyn Middleware>) -> Self {
        self.middlewares.push(mw);
        self
    }

    /// Run all middlewares. Stops at the first `Block`.
    pub async fn run(&self, ctx: &McpContext) -> Decision {
        for mw in &self.middlewares {
            match mw.check(ctx).await {
                Decision::Allow => continue,
                block => return block,
            }
        }
        Decision::Allow
    }
}
