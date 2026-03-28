use crate::{
    audit::{AuditEntry, AuditLog, Outcome},
    live_config::LiveConfig,
    metrics::GatewayMetrics,
    middleware::{Decision, McpContext, Pipeline},
    upstream::McpUpstream,
};
use serde_json::{json, Value};
use std::{collections::HashMap, sync::Arc, time::SystemTime};
use tokio::sync::watch;

pub struct McpGateway {
    pipeline: Pipeline,
    /// Default upstream — used when the agent has no named upstream configured.
    default_upstream: Arc<dyn McpUpstream>,
    /// Named upstreams — keyed by the names defined in `config.upstreams`.
    named_upstreams: HashMap<String, Arc<dyn McpUpstream>>,
    audit: Arc<dyn AuditLog>,
    metrics: Arc<GatewayMetrics>,
    config: watch::Receiver<Arc<LiveConfig>>,
}

impl McpGateway {
    pub fn new(
        pipeline: Pipeline,
        default_upstream: Arc<dyn McpUpstream>,
        named_upstreams: HashMap<String, Arc<dyn McpUpstream>>,
        audit: Arc<dyn AuditLog>,
        metrics: Arc<GatewayMetrics>,
        config: watch::Receiver<Arc<LiveConfig>>,
    ) -> Self {
        Self { pipeline, default_upstream, named_upstreams, audit, metrics, config }
    }

    /// Select the upstream for a given agent. Falls back to the default.
    fn upstream_for(&self, agent_id: &str) -> &Arc<dyn McpUpstream> {
        let upstream_name = {
            let cfg = self.config.borrow();
            cfg.agents.get(agent_id).and_then(|p| p.upstream.clone())
        };
        upstream_name
            .as_ref()
            .and_then(|name| self.named_upstreams.get(name))
            .unwrap_or(&self.default_upstream)
    }

    /// Returns the upstream URL for an agent — used by the SSE proxy.
    pub fn upstream_url_for(&self, agent_id: &str) -> String {
        self.upstream_for(agent_id).base_url().to_string()
    }

    /// Check policy without forwarding.
    /// `None` = allowed, `Some(error)` = blocked.
    /// Used by StdioTransport, which manages piping directly.
    pub async fn intercept(&self, agent_id: &str, msg: &Value) -> Option<Value> {
        self.intercept_with_ip(agent_id, msg, None).await
    }

    pub async fn intercept_with_ip(
        &self,
        agent_id: &str,
        msg: &Value,
        client_ip: Option<String>,
    ) -> Option<Value> {
        let method = msg["method"].as_str().unwrap_or("");

        if method != "tools/call" {
            self.audit.record(AuditEntry {
                ts: SystemTime::now(),
                agent_id: agent_id.to_string(),
                method: method.to_string(),
                tool: None,
                outcome: Outcome::Forwarded,
            });
            self.metrics.record(agent_id, "forwarded");
            return None;
        }

        let id = msg["id"].clone();
        let tool_name = msg["params"]["name"].as_str().map(String::from);
        let arguments = Some(msg["params"]["arguments"].clone());

        let ctx = McpContext {
            agent_id: agent_id.to_string(),
            method: method.to_string(),
            tool_name: tool_name.clone(),
            arguments,
            client_ip,
        };

        match self.pipeline.run(&ctx).await {
            Decision::Allow => {
                self.audit.record(AuditEntry {
                    ts: SystemTime::now(),
                    agent_id: agent_id.to_string(),
                    method: method.to_string(),
                    tool: tool_name,
                    outcome: Outcome::Allowed,
                });
                self.metrics.record(agent_id, "allowed");
                None
            }
            Decision::Block { reason } => {
                self.audit.record(AuditEntry {
                    ts: SystemTime::now(),
                    agent_id: agent_id.to_string(),
                    method: method.to_string(),
                    tool: tool_name,
                    outcome: Outcome::Blocked(reason.clone()),
                });
                self.metrics.record(agent_id, "blocked");
                Some(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": -32603, "message": format!("blocked: {reason}") }
                }))
            }
        }
    }

    /// Policy check + upstream forwarding + response filtering.
    /// Used by HttpTransport.
    pub async fn handle(&self, agent_id: &str, msg: Value, client_ip: Option<String>) -> Option<Value> {
        let method = msg["method"].as_str().unwrap_or("").to_string();

        match self.intercept_with_ip(agent_id, &msg, client_ip).await {
            Some(err) => Some(err),
            None => {
                let response = self.upstream_for(agent_id).forward(&msg).await;
                let response = if method == "tools/list" {
                    response.map(|r| self.filter_tools_response(agent_id, r))
                } else {
                    response
                };
                // Apply response filtering — block responses containing sensitive data
                response.map(|r| self.filter_response(r))
            }
        }
    }

    /// Filters the tools list in a `tools/list` response according to agent policy.
    /// Called by both HttpTransport and StdioTransport.
    pub fn filter_tools_response(&self, agent_id: &str, mut response: Value) -> Value {
        let cfg = self.config.borrow();
        let Some(policy) = cfg.agents.get(agent_id) else {
            return response;
        };

        if let Some(tools) = response["result"]["tools"].as_array_mut() {
            tools.retain(|tool| {
                let name = tool["name"].as_str().unwrap_or("");
                if policy.denied_tools.iter().any(|t| t == name) {
                    return false;
                }
                if let Some(allowed) = &policy.allowed_tools {
                    return allowed.iter().any(|t| t == name);
                }
                true
            });
        }

        response
    }

    /// Applies block_patterns to an upstream response.
    /// Any JSON string value that contains a match is replaced entirely with `"[REDACTED]"`,
    /// so the surrounding structure (keys, types, array indices) is preserved but the
    /// sensitive value is not forwarded to the caller.
    /// Called by both HttpTransport (via `handle`) and StdioTransport (directly).
    pub fn filter_response(&self, response: Value) -> Value {
        let patterns = {
            let cfg = self.config.borrow();
            if cfg.block_patterns.is_empty() {
                return response;
            }
            cfg.block_patterns.iter().cloned().collect::<Vec<_>>()
        };

        let (filtered, redacted) = redact_value(response, &patterns);
        if redacted {
            tracing::info!("sensitive data redacted from response");
        }
        filtered
    }
}

/// Recursively walk a JSON value. Any `String` leaf that matches a block pattern
/// is replaced with the literal string `"[REDACTED]"`. Returns the filtered value
/// and a flag indicating whether anything was redacted.
fn redact_value(val: Value, patterns: &[regex::Regex]) -> (Value, bool) {
    match val {
        Value::String(s) => {
            if patterns.iter().any(|p| p.is_match(&s)) {
                (Value::String("[REDACTED]".to_string()), true)
            } else {
                (Value::String(s), false)
            }
        }
        Value::Array(arr) => {
            let mut any = false;
            let new_arr = arr
                .into_iter()
                .map(|v| {
                    let (v, r) = redact_value(v, patterns);
                    any |= r;
                    v
                })
                .collect();
            (Value::Array(new_arr), any)
        }
        Value::Object(obj) => {
            let mut any = false;
            let new_obj = obj
                .into_iter()
                .map(|(k, v)| {
                    let (v, r) = redact_value(v, patterns);
                    any |= r;
                    (k, v)
                })
                .collect();
            (Value::Object(new_obj), any)
        }
        other => (other, false),
    }
}
