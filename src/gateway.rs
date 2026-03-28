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
            self.audit.record(Arc::new(AuditEntry {
                ts: SystemTime::now(),
                agent_id: agent_id.to_string(),
                method: method.to_string(),
                tool: None,
                outcome: Outcome::Forwarded,
            }));
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
                self.audit.record(Arc::new(AuditEntry {
                    ts: SystemTime::now(),
                    agent_id: agent_id.to_string(),
                    method: method.to_string(),
                    tool: tool_name,
                    outcome: Outcome::Allowed,
                }));
                self.metrics.record(agent_id, "allowed");
                None
            }
            Decision::Block { reason } => {
                self.audit.record(Arc::new(AuditEntry {
                    ts: SystemTime::now(),
                    agent_id: agent_id.to_string(),
                    method: method.to_string(),
                    tool: tool_name,
                    outcome: Outcome::Blocked(reason.clone()),
                }));
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
            Arc::clone(&cfg.block_patterns)
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
pub(crate) fn redact_value(val: Value, patterns: &[regex::Regex]) -> (Value, bool) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        audit::{AuditEntry, AuditLog},
        config::{AgentPolicy, make_agent},
        live_config::LiveConfig,
        metrics::GatewayMetrics,
        middleware::Pipeline,
        upstream::McpUpstream,
    };
    use regex::Regex;
    use serde_json::json;
    use std::collections::HashMap;
    use tokio::sync::watch;

    // ── Minimal stubs ────────────────────────────────────────────────────────

    struct NoopUpstream;
    #[async_trait::async_trait]
    impl McpUpstream for NoopUpstream {
        async fn forward(&self, _: &Value) -> Option<Value> {
            None
        }
    }

    struct NoopAudit;
    impl AuditLog for NoopAudit {
        fn record(&self, _: Arc<AuditEntry>) {}
    }

    fn make_gw(agents: HashMap<String, AgentPolicy>, patterns: Vec<Regex>) -> McpGateway {
        let live = Arc::new(LiveConfig::new(agents, patterns, None));
        let (_, rx) = watch::channel(live);
        McpGateway::new(
            Pipeline::new(),
            Arc::new(NoopUpstream),
            HashMap::new(),
            Arc::new(NoopAudit),
            Arc::new(GatewayMetrics::new().unwrap()),
            rx,
        )
    }

    // ── redact_value ─────────────────────────────────────────────────────────

    #[test]
    fn no_patterns_no_redaction() {
        let val = json!({"key": "value", "num": 42});
        let (out, changed) = redact_value(val.clone(), &[]);
        assert!(!changed);
        assert_eq!(out, val);
    }

    #[test]
    fn matching_string_leaf_replaced() {
        let re = Regex::new("secret").unwrap();
        let (out, changed) = redact_value(json!("my secret key"), &[re]);
        assert!(changed);
        assert_eq!(out, json!("[REDACTED]"));
    }

    #[test]
    fn non_matching_string_left_alone() {
        let re = Regex::new("secret").unwrap();
        let (out, changed) = redact_value(json!("harmless value"), &[re]);
        assert!(!changed);
        assert_eq!(out, json!("harmless value"));
    }

    #[test]
    fn nested_object_string_redacted() {
        let re = Regex::new("private_key").unwrap();
        let val = json!({
            "result": {
                "content": [{"text": "private_key=AAABBB"}]
            }
        });
        let (out, changed) = redact_value(val, &[re]);
        assert!(changed);
        assert_eq!(out["result"]["content"][0]["text"], json!("[REDACTED]"));
    }

    #[test]
    fn non_string_values_not_redacted() {
        let re = Regex::new("42").unwrap();
        let val = json!({"num": 42, "flag": true, "nil": null});
        let (out, changed) = redact_value(val.clone(), &[re]);
        // numbers/booleans/null are not strings → never redacted
        assert!(!changed);
        assert_eq!(out["num"], json!(42));
        assert_eq!(out["flag"], json!(true));
    }

    #[test]
    fn array_element_redacted() {
        let re = Regex::new("token").unwrap();
        let val = json!(["safe", "my token here", "also safe"]);
        let (out, changed) = redact_value(val, &[re]);
        assert!(changed);
        assert_eq!(out[0], json!("safe"));
        assert_eq!(out[1], json!("[REDACTED]"));
        assert_eq!(out[2], json!("also safe"));
    }

    // ── filter_tools_response ────────────────────────────────────────────────

    fn tools_response(names: &[&str]) -> Value {
        let tools: Vec<Value> = names.iter().map(|n| json!({"name": n})).collect();
        json!({"result": {"tools": tools}})
    }

    #[test]
    fn filter_tools_response_no_policy_unchanged() {
        let gw = make_gw(HashMap::new(), vec![]);
        let resp = tools_response(&["read_file", "write_file"]);
        let out = gw.filter_tools_response("unknown", resp.clone());
        assert_eq!(out, resp);
    }

    #[test]
    fn filter_tools_response_denylist_removes_tool() {
        let mut agents = HashMap::new();
        agents.insert("agent".to_string(), make_agent(None, vec!["write_file"], 60));
        let gw = make_gw(agents, vec![]);
        let resp = tools_response(&["read_file", "write_file", "list_dir"]);
        let out = gw.filter_tools_response("agent", resp);
        let names: Vec<_> = out["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["read_file", "list_dir"]);
    }

    #[test]
    fn filter_tools_response_allowlist_keeps_only_permitted() {
        let mut agents = HashMap::new();
        agents.insert("agent".to_string(), make_agent(Some(vec!["read_file"]), vec![], 60));
        let gw = make_gw(agents, vec![]);
        let resp = tools_response(&["read_file", "write_file", "delete_file"]);
        let out = gw.filter_tools_response("agent", resp);
        let names: Vec<_> = out["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["read_file"]);
    }
}
