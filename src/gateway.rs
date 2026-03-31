use crate::{
    audit::{AuditEntry, AuditLog, Outcome},
    config::{FilterMode, tool_matches},
    decode::matches_any_variant,
    live_config::LiveConfig,
    metrics::GatewayMetrics,
    middleware::{Decision, McpContext, Pipeline, RateLimitInfo},
    schema_cache::SchemaCache,
    upstream::McpUpstream,
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::sync::{RwLock, watch};
use uuid::Uuid;

/// Per-agent federation routing table: display_name → (upstream_name, real_tool_name).
/// Populated on every federated `tools/list` response; consulted on `tools/call`.
type FederationRoutes = Arc<RwLock<HashMap<String, HashMap<String, (String, String)>>>>;

pub struct McpGateway {
    pipeline: Pipeline,
    /// Default upstream — used when the agent has no named upstream configured.
    default_upstream: Arc<dyn McpUpstream>,
    /// Named upstreams — keyed by the names defined in `config.upstreams`.
    named_upstreams: HashMap<String, Arc<dyn McpUpstream>>,
    audit: Arc<dyn AuditLog>,
    metrics: Arc<GatewayMetrics>,
    config: watch::Receiver<Arc<LiveConfig>>,
    /// Shared with SchemaValidationMiddleware — populated on every tools/list response.
    schema_cache: SchemaCache,
    /// Federation routing table — only relevant when `AgentPolicy::federate` is true.
    federation_routes: FederationRoutes,
}

impl McpGateway {
    pub fn new(
        pipeline: Pipeline,
        default_upstream: Arc<dyn McpUpstream>,
        named_upstreams: HashMap<String, Arc<dyn McpUpstream>>,
        audit: Arc<dyn AuditLog>,
        metrics: Arc<GatewayMetrics>,
        config: watch::Receiver<Arc<LiveConfig>>,
        schema_cache: SchemaCache,
    ) -> Self {
        Self {
            pipeline,
            default_upstream,
            named_upstreams,
            audit,
            metrics,
            config,
            schema_cache,
            federation_routes: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Select the upstream for a given agent. Falls back to `default_policy`, then the default upstream.
    fn upstream_for(&self, agent_id: &str) -> &Arc<dyn McpUpstream> {
        let upstream_name = {
            let cfg = self.config.borrow();
            cfg.agents
                .get(agent_id)
                .or(cfg.default_policy.as_ref())
                .and_then(|p| p.upstream.clone())
        };
        upstream_name
            .as_ref()
            .and_then(|name| self.named_upstreams.get(name))
            .unwrap_or(&self.default_upstream)
    }

    /// Returns health status for all configured upstreams.
    pub async fn upstreams_health(&self) -> HashMap<String, bool> {
        let mut map = HashMap::new();
        map.insert(
            "default".to_string(),
            self.default_upstream.is_healthy().await,
        );
        for (name, up) in &self.named_upstreams {
            map.insert(name.clone(), up.is_healthy().await);
        }
        map
    }

    /// Returns the upstream URL for an agent — used by the SSE proxy.
    pub fn upstream_url_for(&self, agent_id: &str) -> String {
        self.upstream_for(agent_id).base_url().to_string()
    }

    /// Check policy without forwarding. Returns `None` = allowed, `Some(error)` = blocked.
    /// Used by StdioTransport, which manages piping directly and doesn't need rate limit headers.
    pub async fn intercept(&self, agent_id: &str, msg: &Value) -> Option<Value> {
        let request_id = Uuid::new_v4().to_string();
        self.intercept_with_ip(agent_id, msg, None, &request_id)
            .await
            .0
    }

    /// Returns `(error_response, rate_limit_info, request_id)`.
    /// - `error_response`: `Some` = blocked (JSON-RPC error), `None` = allowed
    /// - `rate_limit_info`: present when a rate-limit check was performed (HTTP transport
    ///   uses this to populate `X-RateLimit-*` headers)
    /// - `request_id`: unique ID for this request, forwarded as `X-Request-Id` header
    #[tracing::instrument(skip(self, msg), fields(method, tool, request_id))]
    pub async fn intercept_with_ip(
        &self,
        agent_id: &str,
        msg: &Value,
        client_ip: Option<String>,
        request_id: &str,
    ) -> (Option<Value>, Option<RateLimitInfo>) {
        let method = msg["method"].as_str().unwrap_or("");
        tracing::Span::current().record("method", method);
        tracing::Span::current().record("request_id", request_id);

        if method != "tools/call" {
            self.audit.record(Arc::new(AuditEntry {
                ts: SystemTime::now(),
                agent_id: agent_id.to_string(),
                method: method.to_string(),
                tool: None,
                arguments: None,
                outcome: Outcome::Forwarded,
                request_id: request_id.to_string(),
            }));
            self.metrics.record(agent_id, "forwarded");
            return (None, None);
        }

        let id = msg["id"].clone();
        let tool_name = msg["params"]["name"].as_str().map(String::from);
        if let Some(t) = &tool_name {
            tracing::Span::current().record("tool", t.as_str());
        }
        let arguments = Some(msg["params"]["arguments"].clone());

        let ctx = McpContext {
            agent_id: agent_id.to_string(),
            method: method.to_string(),
            tool_name: tool_name.clone(),
            arguments: arguments.clone(),
            client_ip,
        };

        match self.pipeline.run(&ctx).await {
            Decision::Allow { rl } => {
                self.audit.record(Arc::new(AuditEntry {
                    ts: SystemTime::now(),
                    agent_id: agent_id.to_string(),
                    method: method.to_string(),
                    tool: tool_name,
                    arguments: arguments.clone(),
                    outcome: Outcome::Allowed,
                    request_id: request_id.to_string(),
                }));
                self.metrics.record(agent_id, "allowed");
                (None, rl)
            }
            Decision::Block { reason, rl } => {
                self.audit.record(Arc::new(AuditEntry {
                    ts: SystemTime::now(),
                    agent_id: agent_id.to_string(),
                    method: method.to_string(),
                    tool: tool_name,
                    arguments,
                    outcome: Outcome::Blocked(reason.clone()),
                    request_id: request_id.to_string(),
                }));
                self.metrics.record(agent_id, "blocked");
                (
                    Some(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": { "code": -32603, "message": format!("blocked: {reason}") }
                    })),
                    rl,
                )
            }
        }
    }

    /// Queries all named upstreams for their tool lists, merges the results, and stores
    /// a routing table so subsequent `tools/call` requests can be routed correctly.
    /// Colliding tool names (same name from ≥2 upstreams) are prefixed `<upstream>__name`.
    async fn federated_tools_list(&self, agent_id: &str, request_id: &Value) -> Value {
        use futures_util::future::join_all;

        let futures: Vec<_> = self
            .named_upstreams
            .iter()
            .map(|(name, upstream)| {
                let name = name.clone();
                let upstream = Arc::clone(upstream);
                async move {
                    let list_req = json!({
                        "jsonrpc": "2.0", "id": 1,
                        "method": "tools/list", "params": {}
                    });
                    let resp = upstream.forward(&list_req).await;
                    (name, resp)
                }
            })
            .collect();

        let results = join_all(futures).await;

        // Collect (upstream_name, tool_json)
        let mut all_tools: Vec<(String, Value)> = Vec::new();
        for (upstream_name, resp) in results {
            if let Some(r) = resp {
                if let Some(tools) = r["result"]["tools"].as_array() {
                    for tool in tools {
                        all_tools.push((upstream_name.clone(), tool.clone()));
                    }
                }
            }
        }

        // Count name occurrences to detect collisions
        let mut name_count: HashMap<String, usize> = HashMap::new();
        for (_, tool) in &all_tools {
            let name = tool["name"].as_str().unwrap_or("").to_string();
            *name_count.entry(name).or_insert(0) += 1;
        }

        // Build merged list and routing table
        let mut merged: Vec<Value> = Vec::new();
        let mut routes: HashMap<String, (String, String)> = HashMap::new();

        for (upstream_name, mut tool) in all_tools {
            let real_name = tool["name"].as_str().unwrap_or("").to_string();
            let display_name = if name_count.get(&real_name).copied().unwrap_or(0) > 1 {
                format!("{}__{}", upstream_name, real_name)
            } else {
                real_name.clone()
            };
            if let Some(obj) = tool.as_object_mut() {
                obj.insert("name".to_string(), Value::String(display_name.clone()));
            }
            routes.insert(display_name, (upstream_name, real_name));
            merged.push(tool);
        }

        // Store routing table for this agent
        self.federation_routes
            .write()
            .await
            .insert(agent_id.to_string(), routes);

        json!({
            "jsonrpc": "2.0",
            "id": request_id,
            "result": { "tools": merged }
        })
    }

    /// Policy check + upstream forwarding + response filtering.
    /// Returns `(response, rate_limit_info, request_id)` for the HTTP transport.
    #[tracing::instrument(skip(self, msg))]
    pub async fn handle(
        &self,
        agent_id: &str,
        msg: Value,
        client_ip: Option<String>,
    ) -> (Option<Value>, Option<RateLimitInfo>, String) {
        let request_id = Uuid::new_v4().to_string();
        let method = msg["method"].as_str().unwrap_or("").to_string();

        let (err, rl) = self
            .intercept_with_ip(agent_id, &msg, client_ip, &request_id)
            .await;
        if let Some(err) = err {
            return (Some(err), rl, request_id);
        }

        // ── Shadow mode ───────────────────────────────────────────────────────
        // If the tool is in shadow_tools, return a mock response without forwarding.
        if method == "tools/call" {
            let tool_name = msg["params"]["name"].as_str().map(String::from);
            let is_shadowed = {
                let cfg = self.config.borrow();
                cfg.agents
                    .get(agent_id)
                    .or(cfg.default_policy.as_ref())
                    .is_some_and(|p| {
                        tool_name
                            .as_deref()
                            .is_some_and(|t| p.shadow_tools.iter().any(|pat| tool_matches(pat, t)))
                    })
            };
            if is_shadowed {
                let id = msg["id"].clone();
                tracing::info!(
                    agent = agent_id,
                    tool = tool_name.as_deref().unwrap_or("-"),
                    "shadow mode: intercepted, not forwarded"
                );
                self.audit.record(Arc::new(AuditEntry {
                    ts: SystemTime::now(),
                    agent_id: agent_id.to_string(),
                    method: method.clone(),
                    tool: tool_name,
                    arguments: Some(msg["params"]["arguments"].clone()),
                    outcome: Outcome::Shadowed,
                    request_id: request_id.clone(),
                }));
                self.metrics.record(agent_id, "shadowed");
                let mock = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "content": [{"type": "text", "text": "[shadow] call intercepted — not forwarded to upstream"}]
                    }
                });
                return (Some(mock), rl, request_id);
            }
        }

        // In Redact mode, scrub block_patterns from the request arguments before forwarding.
        // Injection patterns are always blocked upstream — if we reach here they didn't match.
        let msg = {
            let (patterns, filter_mode) = {
                let cfg = self.config.borrow();
                (Arc::clone(&cfg.block_patterns), cfg.filter_mode)
            };
            if filter_mode == FilterMode::Redact && !patterns.is_empty() {
                scrub_request_args(msg, &patterns)
            } else {
                msg
            }
        };

        // Per-agent timeout — overrides the default 30s client timeout.
        let timeout = {
            let cfg = self.config.borrow();
            cfg.agents
                .get(agent_id)
                .or(cfg.default_policy.as_ref())
                .and_then(|p| p.timeout_secs)
        };

        // ── Federation mode ───────────────────────────────────────────────────
        let is_federated = {
            let cfg = self.config.borrow();
            cfg.agents
                .get(agent_id)
                .or(cfg.default_policy.as_ref())
                .map(|p| p.federate)
                .unwrap_or(false)
        };

        if is_federated {
            if method == "tools/list" {
                let federated = self.federated_tools_list(agent_id, &msg["id"]).await;
                let filtered = self.filter_tools_response(agent_id, federated);
                self.schema_cache.populate(agent_id, &filtered);
                let filtered = self.filter_response(filtered);
                return (Some(filtered), rl, request_id);
            }

            if method == "tools/call" {
                if let Some(tool_name) = msg["params"]["name"].as_str().map(str::to_string) {
                    let routes_guard = self.federation_routes.read().await;
                    if let Some(agent_routes) = routes_guard.get(agent_id) {
                        if let Some((upstream_name, real_name)) = agent_routes.get(&tool_name) {
                            let mut rewritten = msg.clone();
                            rewritten["params"]["name"] = Value::String(real_name.clone());
                            let upstream = self
                                .named_upstreams
                                .get(upstream_name)
                                .unwrap_or(&self.default_upstream);
                            let forward_fut = upstream.forward(&rewritten);
                            let raw_response = if let Some(secs) = timeout {
                                match tokio::time::timeout(
                                    Duration::from_secs(secs),
                                    forward_fut,
                                )
                                .await
                                {
                                    Ok(r) => r,
                                    Err(_) => {
                                        tracing::warn!(
                                            agent = agent_id,
                                            timeout_secs = secs,
                                            "upstream timeout (federated)"
                                        );
                                        Some(json!({
                                            "jsonrpc": "2.0",
                                            "id": msg["id"],
                                            "error": { "code": -32603, "message": "upstream timeout" }
                                        }))
                                    }
                                }
                            } else {
                                forward_fut.await
                            };
                            let response = raw_response.map(|r| self.filter_response(r));
                            return (response, rl, request_id);
                        }
                    }
                }
            }
        }

        let upstream = self.upstream_for(agent_id);
        let forward_fut = upstream.forward(&msg);
        let raw_response = if let Some(secs) = timeout {
            match tokio::time::timeout(Duration::from_secs(secs), forward_fut).await {
                Ok(r) => r,
                Err(_) => {
                    tracing::warn!(agent = agent_id, timeout_secs = secs, "upstream timeout");
                    Some(json!({
                        "jsonrpc": "2.0",
                        "id": msg["id"],
                        "error": { "code": -32603, "message": "upstream timeout" }
                    }))
                }
            }
        } else {
            forward_fut.await
        };

        let response = if method == "tools/list" {
            raw_response.map(|r| {
                let filtered = self.filter_tools_response(agent_id, r);
                self.schema_cache.populate(agent_id, &filtered);
                filtered
            })
        } else {
            raw_response
        };
        let response = response.map(|r| self.filter_response(r));
        (response, rl, request_id)
    }

    /// Filters the tools list in a `tools/list` response according to agent policy.
    /// Called by both HttpTransport and StdioTransport.
    pub fn filter_tools_response(&self, agent_id: &str, mut response: Value) -> Value {
        let cfg = self.config.borrow();
        let Some(policy) = cfg.agents.get(agent_id).or(cfg.default_policy.as_ref()) else {
            return response;
        };

        if let Some(tools) = response["result"]["tools"].as_array_mut() {
            tools.retain(|tool| {
                let name = tool["name"].as_str().unwrap_or("");
                if policy.denied_tools.iter().any(|t| tool_matches(t, name)) {
                    return false;
                }
                if let Some(allowed) = &policy.allowed_tools {
                    return allowed.iter().any(|t| tool_matches(t, name));
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

/// In Redact mode, scrub block_patterns from `params.arguments` before forwarding.
/// Returns the message with sensitive argument values replaced by `"[REDACTED]"`.
fn scrub_request_args(mut msg: Value, patterns: &[regex::Regex]) -> Value {
    if let Some(args) = msg.pointer("/params/arguments").cloned() {
        let (redacted, changed) = redact_value(args, patterns);
        if changed {
            tracing::info!("sensitive data scrubbed from request arguments (redact mode)");
            if let Some(target) = msg.pointer_mut("/params/arguments") {
                *target = redacted;
            }
        }
    }
    msg
}

/// Recursively walk a JSON value. Any `String` leaf that matches a block pattern
/// is replaced with the literal string `"[REDACTED]"`. Returns the filtered value
/// and a flag indicating whether anything was redacted.
pub fn redact_value(val: Value, patterns: &[regex::Regex]) -> (Value, bool) {
    match val {
        Value::String(s) => {
            if matches_any_variant(&s, patterns) {
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
        config::{AgentPolicy, FilterMode, make_agent},
        live_config::LiveConfig,
        metrics::GatewayMetrics,
        middleware::Pipeline,
        schema_cache::SchemaCache,
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
        let live = Arc::new(LiveConfig::new(
            agents,
            patterns,
            vec![],
            None,
            FilterMode::Block,
            None,
        ));
        let (_, rx) = watch::channel(live);
        McpGateway::new(
            Pipeline::new(),
            Arc::new(NoopUpstream),
            HashMap::new(),
            Arc::new(NoopAudit),
            Arc::new(GatewayMetrics::new().unwrap()),
            rx,
            SchemaCache::new(),
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
        agents.insert(
            "agent".to_string(),
            make_agent(None, vec!["write_file"], 60),
        );
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
        agents.insert(
            "agent".to_string(),
            make_agent(Some(vec!["read_file"]), vec![], 60),
        );
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

    // ── scrub_request_args ────────────────────────────────────────────────────

    #[test]
    fn scrub_request_args_replaces_matching_value() {
        let re = Regex::new("secret").unwrap();
        let msg = json!({
            "method": "tools/call",
            "params": {"name": "echo", "arguments": {"input": "my secret key"}}
        });
        let out = scrub_request_args(msg, &[re]);
        assert_eq!(out["params"]["arguments"]["input"], json!("[REDACTED]"));
    }

    #[test]
    fn scrub_request_args_leaves_non_matching_values() {
        let re = Regex::new("secret").unwrap();
        let msg = json!({
            "method": "tools/call",
            "params": {"name": "echo", "arguments": {"input": "harmless"}}
        });
        let out = scrub_request_args(msg.clone(), &[re]);
        assert_eq!(out["params"]["arguments"]["input"], json!("harmless"));
    }

    #[test]
    fn scrub_request_args_no_arguments_unchanged() {
        let re = Regex::new("secret").unwrap();
        let msg = json!({"method": "tools/call", "params": {"name": "echo"}});
        let out = scrub_request_args(msg.clone(), &[re]);
        assert_eq!(out, msg);
    }

    #[test]
    fn scrub_request_args_nested_object_scrubbed() {
        let re = Regex::new("password").unwrap();
        let msg = json!({
            "method": "tools/call",
            "params": {
                "name": "login",
                "arguments": {"user": "alice", "creds": "password=hunter2"}
            }
        });
        let out = scrub_request_args(msg, &[re]);
        assert_eq!(out["params"]["arguments"]["user"], json!("alice"));
        assert_eq!(out["params"]["arguments"]["creds"], json!("[REDACTED]"));
    }

    // ── P6: Encoding-aware response filtering ─────────────────────────────────

    #[test]
    fn redact_value_base64_encoded_secret() {
        use base64::Engine;
        let re = Regex::new("private_key").unwrap();
        // Upstream returns a Base64-encoded value containing "private_key=..."
        let encoded = base64::engine::general_purpose::STANDARD.encode("private_key=AAAABBBBCCCC");
        let val = json!({"result": {"content": [{"text": encoded}]}});
        let (out, changed) = redact_value(val, &[re]);
        assert!(changed);
        assert_eq!(out["result"]["content"][0]["text"], json!("[REDACTED]"));
    }

    #[test]
    fn redact_value_url_encoded_secret() {
        let re = Regex::new("private_key").unwrap();
        let val = json!({"output": "private%5Fkey%3DAAAABBBBCCCC"});
        let (out, changed) = redact_value(val, &[re]);
        assert!(changed);
        assert_eq!(out["output"], json!("[REDACTED]"));
    }

    #[test]
    fn redact_value_double_url_encoded_secret() {
        let re = Regex::new("private_key").unwrap();
        // %255F = double-encoded underscore → %5F → _
        let val = json!({"output": "private%255Fkey%253DAAAABBBBCCCC"});
        let (out, changed) = redact_value(val, &[re]);
        assert!(changed);
        assert_eq!(out["output"], json!("[REDACTED]"));
    }

    #[test]
    fn redact_value_url_safe_base64_encoded_secret() {
        use base64::Engine;
        let re = Regex::new("secret_token").unwrap();
        let encoded =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("secret_token=xyz123");
        let val = json!({"blob": encoded});
        let (out, changed) = redact_value(val, &[re]);
        assert!(changed);
        assert_eq!(out["blob"], json!("[REDACTED]"));
    }

    #[test]
    fn redact_value_clean_response_untouched() {
        let re = Regex::new("private_key").unwrap();
        let val = json!({"result": "Hello, World!"});
        let (out, changed) = redact_value(val.clone(), &[re]);
        assert!(!changed);
        assert_eq!(out, val);
    }

    #[test]
    fn scrub_request_args_base64_encoded_secret_scrubbed() {
        use base64::Engine;
        let re = Regex::new("secret").unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode("my secret key");
        let msg = json!({
            "method": "tools/call",
            "params": {"name": "send", "arguments": {"payload": encoded}}
        });
        let out = scrub_request_args(msg, &[re]);
        assert_eq!(out["params"]["arguments"]["payload"], json!("[REDACTED]"));
    }

    // ── P9: Unicode evasion in responses ─────────────────────────────────────

    #[test]
    fn redact_value_fullwidth_unicode_secret() {
        let re = Regex::new(r"(?i)secret").unwrap();
        // "secret" in fullwidth Unicode: ｓｅｃｒｅｔ
        let fullwidth = "\u{FF53}\u{FF45}\u{FF43}\u{FF52}\u{FF45}\u{FF54}";
        let val = json!({"output": fullwidth});
        let (out, changed) = redact_value(val, &[re]);
        assert!(changed, "fullwidth 'secret' should be redacted");
        assert_eq!(out["output"], json!("[REDACTED]"));
    }

    #[test]
    fn redact_value_zero_width_obfuscated_secret() {
        let re = Regex::new(r"(?i)secret").unwrap();
        let zws = "\u{200B}";
        let obfuscated = format!("s{zws}e{zws}c{zws}r{zws}e{zws}t");
        let val = json!({"output": obfuscated});
        let (out, changed) = redact_value(val, &[re]);
        assert!(changed, "zero-width obfuscated 'secret' should be redacted");
        assert_eq!(out["output"], json!("[REDACTED]"));
    }

    // ── DLP / Encoded Exfiltration ──────────────────────────────────────────────

    #[test]
    fn raw_aws_key_redacted() {
        let re = Regex::new(r"AKIA[0-9A-Z]{16}").unwrap();
        let val = json!({"content": [{"text": "Config loaded: AKIAIOSFODNN7EXAMPLE"}]});
        let (out, changed) = redact_value(val, &[re]);
        assert!(changed);
        assert_eq!(out["content"][0]["text"], json!("[REDACTED]"));
    }

    #[test]
    fn base64_github_token_redacted() {
        let re = Regex::new(r"ghp_[A-Za-z0-9]{36,}").unwrap();
        // base64("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl")
        let encoded = "Z2hwX0FCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaYWJjZGVmZ2hpamts";
        let val = json!({"content": [{"text": encoded}]});
        let (out, changed) = redact_value(val, &[re]);
        assert!(changed);
        assert_eq!(out["content"][0]["text"], json!("[REDACTED]"));
    }

    #[test]
    fn percent_encoded_private_key_header_redacted() {
        let re = Regex::new(r"BEGIN (RSA |EC |)PRIVATE KEY").unwrap();
        // %2D%2D%2D%2D%2DBEGIN%20RSA%20PRIVATE%20KEY%2D%2D%2D%2D%2D
        let val = json!({"text": "%2D%2D%2D%2D%2DBEGIN%20RSA%20PRIVATE%20KEY%2D%2D%2D%2D%2D"});
        let (out, changed) = redact_value(val, &[re]);
        assert!(changed);
        assert_eq!(out["text"], json!("[REDACTED]"));
    }

    #[test]
    fn double_base64_aws_key_redacted() {
        use base64::Engine;
        let re = Regex::new(r"AKIA[0-9A-Z]{16}").unwrap();
        let inner = base64::engine::general_purpose::STANDARD.encode("AKIAIOSFODNN7EXAMPLE");
        let outer = base64::engine::general_purpose::STANDARD.encode(&inner);
        let val = json!({"content": [{"text": outer}]});
        let (out, changed) = redact_value(val, &[re]);
        assert!(changed);
        assert_eq!(out["content"][0]["text"], json!("[REDACTED]"));
    }

    #[test]
    fn jwt_token_redacted() {
        let re = Regex::new(r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+").unwrap();
        let val = json!({"text": "Token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6ImFkbWluIn0.abc123signature"});
        let (out, changed) = redact_value(val, &[re]);
        assert!(changed);
        assert_eq!(out["text"], json!("[REDACTED]"));
    }

    #[test]
    fn db_connection_string_in_error_redacted() {
        let re = Regex::new(r"(postgresql|mysql|mongodb)://[^:]+:[^@]+@").unwrap();
        let val = json!({
            "error": {
                "message": "Connection failed: postgresql://admin:s3cr3t_p4ss@db.internal:5432/production"
            }
        });
        let (out, changed) = redact_value(val, &[re]);
        assert!(changed);
        assert_eq!(out["error"]["message"], json!("[REDACTED]"));
    }

    #[test]
    fn clean_response_not_redacted() {
        let re = Regex::new(r"AKIA[0-9A-Z]{16}").unwrap();
        let val = json!({"content": [{"text": "The file was read successfully. Contents: Hello, World!"}]});
        let (out, changed) = redact_value(val.clone(), &[re]);
        assert!(!changed);
        assert_eq!(out, val);
    }

    // ── Shadow mode ───────────────────────────────────────────────────────────

    fn make_gw_with_shadow(shadow_tools: Vec<String>) -> McpGateway {
        let mut agents = HashMap::new();
        agents.insert(
            "agent".to_string(),
            AgentPolicy {
                allowed_tools: None,
                denied_tools: vec![],
                rate_limit: 100,
                tool_rate_limits: HashMap::new(),
                upstream: None,
                api_key: None,
                timeout_secs: None,
                approval_required: vec![],
                hitl_timeout_secs: 60,
                shadow_tools,
                federate: false,
            },
        );
        make_gw(agents, vec![])
    }

    #[tokio::test]
    async fn shadow_tool_returns_mock_response() {
        let gw = make_gw_with_shadow(vec!["risky_write".to_string()]);
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "risky_write", "arguments": {"path": "/etc/passwd"}}
        });
        let (resp, _rl, _id) = gw.handle("agent", msg, None).await;
        let resp = resp.expect("expected a response");
        assert!(
            resp["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("[shadow]")
        );
        assert!(resp.get("error").is_none());
    }

    #[tokio::test]
    async fn non_shadow_tool_forwarded_normally() {
        let gw = make_gw_with_shadow(vec!["risky_write".to_string()]);
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "/tmp/ok"}}
        });
        // NoopUpstream returns None → response is None (forwarded, no mock)
        let (resp, _rl, _id) = gw.handle("agent", msg, None).await;
        assert!(resp.is_none());
    }

    #[tokio::test]
    async fn shadow_glob_pattern_matches() {
        let gw = make_gw_with_shadow(vec!["write_*".to_string()]);
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "write_file", "arguments": {}}
        });
        let (resp, _rl, _id) = gw.handle("agent", msg, None).await;
        let resp = resp.expect("expected mock response for write_file");
        assert!(
            resp["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("[shadow]")
        );
    }

    // ── upstream_for ──────────────────────────────────────────────────────────

    struct RecordingUpstream {
        name: String,
    }
    #[async_trait::async_trait]
    impl McpUpstream for RecordingUpstream {
        async fn forward(&self, _: &Value) -> Option<Value> {
            Some(json!({"upstream": self.name}))
        }
        fn base_url(&self) -> &str {
            &self.name
        }
    }

    fn make_gw_with_named_upstream(agent: &str, upstream_name: &str) -> McpGateway {
        let mut agents = HashMap::new();
        agents.insert(
            agent.to_string(),
            AgentPolicy {
                allowed_tools: None,
                denied_tools: vec![],
                rate_limit: 100,
                tool_rate_limits: HashMap::new(),
                upstream: Some(upstream_name.to_string()),
                api_key: None,
                timeout_secs: None,
                approval_required: vec![],
                hitl_timeout_secs: 60,
                shadow_tools: vec![],
                federate: false,
            },
        );
        let live = Arc::new(LiveConfig::new(
            agents,
            vec![],
            vec![],
            None,
            FilterMode::Block,
            None,
        ));
        let (_, rx) = watch::channel(live);
        let named: Arc<dyn McpUpstream> = Arc::new(RecordingUpstream {
            name: upstream_name.to_string(),
        });
        let mut named_map = HashMap::new();
        named_map.insert(upstream_name.to_string(), named);
        McpGateway::new(
            Pipeline::new(),
            Arc::new(NoopUpstream),
            named_map,
            Arc::new(NoopAudit),
            Arc::new(GatewayMetrics::new().unwrap()),
            rx,
            SchemaCache::new(),
        )
    }

    #[tokio::test]
    async fn handle_routes_to_named_upstream_when_configured() {
        let gw = make_gw_with_named_upstream("agent", "filesystem");
        let msg = json!({
            "jsonrpc": "2.0", "id": 1,
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {}}
        });
        let (resp, _, _) = gw.handle("agent", msg, None).await;
        let resp = resp.unwrap();
        // RecordingUpstream returns {"upstream": "filesystem"}
        assert_eq!(resp["upstream"], "filesystem");
    }

    #[tokio::test]
    async fn handle_falls_back_to_default_upstream_for_unknown_agent() {
        // NoopUpstream (default) returns None; RecordingUpstream returns Some
        let gw = make_gw_with_named_upstream("known-agent", "filesystem");
        let msg = json!({
            "jsonrpc": "2.0", "id": 1,
            "method": "tools/call",
            "params": {"name": "any_tool", "arguments": {}}
        });
        // "unknown-agent" is not in agents, falls back to default (NoopUpstream → None)
        let (resp, _, _) = gw.handle("unknown-agent", msg, None).await;
        assert!(
            resp.is_none(),
            "unknown agent should use default (Noop) upstream"
        );
    }

    // ── filter_response ───────────────────────────────────────────────────────

    #[test]
    fn filter_response_with_no_patterns_returns_value_unchanged() {
        let gw = make_gw(HashMap::new(), vec![]);
        let val = json!({"result": {"content": [{"text": "private_key=AAABBB"}]}});
        let out = gw.filter_response(val.clone());
        assert_eq!(out, val, "no patterns → value should be unchanged");
    }

    #[test]
    fn filter_response_redacts_matching_string() {
        let re = regex::Regex::new("private_key").unwrap();
        let gw = make_gw(HashMap::new(), vec![re]);
        let val = json!({"text": "private_key=AAABBB"});
        let out = gw.filter_response(val);
        assert_eq!(out["text"], json!("[REDACTED]"));
    }

    // ── handle: non-tools/call forwarded ─────────────────────────────────────

    #[tokio::test]
    async fn handle_non_tools_call_method_is_forwarded_to_upstream() {
        let gw = make_gw(HashMap::new(), vec![]);
        // tools/list — not tools/call → intercept returns None, forwarded to NoopUpstream
        let msg = json!({
            "jsonrpc": "2.0", "id": 1,
            "method": "tools/list"
        });
        let (resp, _, _) = gw.handle("any-agent", msg, None).await;
        // NoopUpstream returns None for everything
        assert!(resp.is_none());
    }

    #[tokio::test]
    async fn handle_initialize_is_forwarded() {
        let gw = make_gw(HashMap::new(), vec![]);
        let msg = json!({
            "jsonrpc": "2.0", "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "test", "version": "1.0"}}
        });
        let (resp, _, _) = gw.handle("any-agent", msg, None).await;
        assert!(resp.is_none()); // NoopUpstream
    }

    // ── federation ────────────────────────────────────────────────────────────

    struct ToolListUpstream {
        tools: Vec<&'static str>,
    }
    #[async_trait::async_trait]
    impl McpUpstream for ToolListUpstream {
        async fn forward(&self, msg: &Value) -> Option<Value> {
            if msg["method"].as_str() == Some("tools/list") {
                let tools: Vec<Value> = self.tools.iter().map(|n| json!({"name": n})).collect();
                Some(json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": tools}}))
            } else if msg["method"].as_str() == Some("tools/call") {
                Some(json!({
                    "jsonrpc": "2.0",
                    "id": msg["id"],
                    "result": {
                        "content": [{"type": "text", "text": msg["params"]["name"]}]
                    }
                }))
            } else {
                None
            }
        }
    }

    fn make_gw_federated(tools_a: Vec<&'static str>, tools_b: Vec<&'static str>) -> McpGateway {
        let mut agents = HashMap::new();
        agents.insert(
            "agent".to_string(),
            AgentPolicy {
                allowed_tools: None,
                denied_tools: vec![],
                rate_limit: 100,
                tool_rate_limits: HashMap::new(),
                upstream: None,
                api_key: None,
                timeout_secs: None,
                approval_required: vec![],
                hitl_timeout_secs: 60,
                shadow_tools: vec![],
                federate: true,
            },
        );
        let live = Arc::new(LiveConfig::new(
            agents,
            vec![],
            vec![],
            None,
            FilterMode::Block,
            None,
        ));
        let (_, rx) = watch::channel(live);
        let mut named: HashMap<String, Arc<dyn McpUpstream>> = HashMap::new();
        named.insert("alpha".to_string(), Arc::new(ToolListUpstream { tools: tools_a }));
        named.insert("beta".to_string(), Arc::new(ToolListUpstream { tools: tools_b }));
        McpGateway::new(
            Pipeline::new(),
            Arc::new(NoopUpstream),
            named,
            Arc::new(NoopAudit),
            Arc::new(GatewayMetrics::new().unwrap()),
            rx,
            SchemaCache::new(),
        )
    }

    #[tokio::test]
    async fn federated_tools_list_merges_no_collision() {
        let gw = make_gw_federated(vec!["read_file"], vec!["query_db"]);
        let msg = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}});
        let (resp, _, _) = gw.handle("agent", msg, None).await;
        let resp = resp.unwrap();
        let tools: Vec<&str> = resp["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        // No collision → original names kept
        assert!(tools.contains(&"read_file"), "missing read_file");
        assert!(tools.contains(&"query_db"), "missing query_db");
        assert_eq!(tools.len(), 2);
    }

    #[tokio::test]
    async fn federated_tools_list_prefixes_collisions() {
        let gw = make_gw_federated(vec!["shared_tool", "only_a"], vec!["shared_tool", "only_b"]);
        let msg = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}});
        let (resp, _, _) = gw.handle("agent", msg, None).await;
        let resp = resp.unwrap();
        let tools: Vec<&str> = resp["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        // Colliding tool gets prefixed
        assert!(
            tools.iter().any(|t| *t == "alpha__shared_tool" || *t == "beta__shared_tool"),
            "colliding tool should be prefixed; got: {tools:?}"
        );
        // Non-colliding tools keep their names
        assert!(tools.contains(&"only_a"), "missing only_a");
        assert!(tools.contains(&"only_b"), "missing only_b");
        assert_eq!(tools.len(), 4);
    }

    #[tokio::test]
    async fn federated_tools_call_routes_to_correct_upstream() {
        let gw = make_gw_federated(vec!["read_file"], vec!["query_db"]);
        // First, populate the routing table via tools/list
        let list_msg = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}});
        gw.handle("agent", list_msg, None).await;

        // Call a tool that belongs to the "beta" upstream
        let call_msg = json!({
            "jsonrpc": "2.0", "id": 2,
            "method": "tools/call",
            "params": {"name": "query_db", "arguments": {}}
        });
        let (resp, _, _) = gw.handle("agent", call_msg, None).await;
        let resp = resp.unwrap();
        // ToolListUpstream echoes back the tool name it received — should be real name "query_db"
        assert_eq!(
            resp["result"]["content"][0]["text"],
            "query_db",
            "should forward real tool name to upstream"
        );
    }

    #[tokio::test]
    async fn federated_tools_call_routes_prefixed_collision() {
        let gw = make_gw_federated(vec!["shared_tool"], vec!["shared_tool"]);
        // Populate routing table
        let list_msg = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}});
        gw.handle("agent", list_msg, None).await;

        // Determine one of the prefixed names (alpha or beta)
        let prefixed = "alpha__shared_tool";
        let call_msg = json!({
            "jsonrpc": "2.0", "id": 2,
            "method": "tools/call",
            "params": {"name": prefixed, "arguments": {}}
        });
        let (resp, _, _) = gw.handle("agent", call_msg, None).await;
        let resp = resp.unwrap();
        // The upstream should have received the real name (without prefix)
        assert_eq!(
            resp["result"]["content"][0]["text"],
            "shared_tool",
            "upstream should receive stripped real name"
        );
    }

    // ── upstreams_health ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn upstreams_health_includes_default() {
        let gw = make_gw(HashMap::new(), vec![]);
        let health = gw.upstreams_health().await;
        assert!(
            health.contains_key("default"),
            "health map should have 'default'"
        );
    }

    #[tokio::test]
    async fn upstreams_health_includes_named_upstreams() {
        let gw = make_gw_with_named_upstream("agent", "filesystem");
        let health = gw.upstreams_health().await;
        assert!(health.contains_key("default"));
        assert!(health.contains_key("filesystem"));
    }
}
