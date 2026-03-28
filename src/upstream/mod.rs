pub mod http;

use async_trait::async_trait;
use serde_json::Value;

/// Trait for the MCP upstream — any server that receives JSON-RPC.
/// `None` = no response body (202 for notifications).
#[async_trait]
pub trait McpUpstream: Send + Sync {
    async fn forward(&self, msg: &Value) -> Option<Value>;
}
