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
use tokio::sync::watch;
use uuid::Uuid;

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
            arguments,
            client_ip,
        };

        match self.pipeline.run(&ctx).await {
            Decision::Allow { rl } => {
                self.audit.record(Arc::new(AuditEntry {
                    ts: SystemTime::now(),
                    agent_id: agent_id.to_string(),
                    method: method.to_string(),
                    tool: tool_name,
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
        let encoded =
            base64::engine::general_purpose::STANDARD.encode("private_key=AAAABBBBCCCC");
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
}
