use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub transport: TransportConfig,
    /// Single audit backend — kept for backward compatibility.
    #[serde(default)]
    pub audit: Option<AuditConfig>,
    /// Multiple audit backends — fan-out to all of them simultaneously.
    #[serde(default)]
    pub audits: Vec<AuditConfig>,
    #[serde(default)]
    pub agents: HashMap<String, AgentPolicy>,
    /// Fallback policy applied to agents not listed in `agents`.
    /// Without this, unknown agents are blocked entirely.
    pub default_policy: Option<AgentPolicy>,
    #[serde(default)]
    pub rules: Rules,
    /// Named upstream servers — agents can reference these by name via `upstream:` in their policy.
    #[serde(default)]
    pub upstreams: HashMap<String, String>,
    /// JWT / OIDC authentication — single provider or list of providers.
    pub auth: Option<AuthConfig>,
    /// Optional Bearer token required to access `/dashboard` and `/metrics`.
    /// When unset both endpoints are publicly accessible.
    pub admin_token: Option<String>,
    /// OpenTelemetry tracing — exports spans to an OTLP endpoint.
    pub telemetry: Option<TelemetryConfig>,
}

// ── Transport ────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum TransportConfig {
    Http {
        #[serde(default = "default_addr")]
        addr: String,
        #[serde(default = "default_upstream_url")]
        upstream: String,
        /// Session TTL in seconds. Requests with an expired session receive 404.
        #[serde(default = "default_session_ttl")]
        session_ttl_secs: u64,
        /// Optional TLS — if present the server runs HTTPS, otherwise plain HTTP.
        tls: Option<TlsConfig>,
        /// Circuit breaker for the upstream. Defaults to threshold=5, recovery=30s.
        #[serde(default)]
        circuit_breaker: CircuitBreakerConfig,
    },
    Stdio {
        server: Vec<String>,
        /// Optional binary verification before spawn (supply-chain security).
        #[serde(default)]
        verify: Option<BinaryVerifyConfig>,
    },
}

/// Supply-chain verification settings for the stdio server binary.
/// Both checks are optional and independent — configure one or both.
///
/// Example:
/// ```yaml
/// transport:
///   type: stdio
///   server: ["/usr/local/bin/mcp-server", "--data-dir", "/data"]
///   verify:
///     sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
///     cosign_bundle: "/etc/mcp/server.bundle"
///     cosign_identity: "ci@example.com"
///     cosign_issuer: "https://accounts.google.com"
/// ```
#[derive(Debug, Deserialize, Clone)]
pub struct BinaryVerifyConfig {
    /// Expected lowercase hex SHA-256 digest of the server binary.
    /// Gateway startup is aborted if the binary on disk does not match.
    pub sha256: Option<String>,
    /// Path to a cosign bundle file produced by `cosign sign-blob --bundle`.
    /// When set, `cosign verify-blob` is invoked before the server is spawned.
    pub cosign_bundle: Option<String>,
    /// Expected signer identity (email or SAN URI) for keyless cosign verification.
    pub cosign_identity: Option<String>,
    /// OIDC issuer URL for keyless cosign verification.
    /// Example: `"https://token.actions.githubusercontent.com"`
    pub cosign_issuer: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TlsConfig {
    pub cert: String,
    pub key: String,
}

impl Default for TransportConfig {
    fn default() -> Self {
        TransportConfig::Http {
            addr: default_addr(),
            upstream: default_upstream_url(),
            session_ttl_secs: default_session_ttl(),
            tls: None,
            circuit_breaker: CircuitBreakerConfig::default(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures before the circuit opens. Default: 5.
    #[serde(default = "default_cb_threshold")]
    pub threshold: usize,
    /// Seconds to wait before probing the upstream again (half-open). Default: 30.
    #[serde(default = "default_cb_recovery_secs")]
    pub recovery_secs: u64,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            threshold: default_cb_threshold(),
            recovery_secs: default_cb_recovery_secs(),
        }
    }
}

fn default_cb_threshold() -> usize {
    5
}
fn default_cb_recovery_secs() -> u64 {
    30
}

fn default_addr() -> String {
    "0.0.0.0:4000".to_string()
}

fn default_upstream_url() -> String {
    "http://localhost:3000/mcp".to_string()
}

fn default_session_ttl() -> u64 {
    3600
}

// ── Audit ────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum AuditConfig {
    Stdout,
    Sqlite {
        #[serde(default = "default_db_path")]
        path: String,
        /// Max number of audit entries to keep. Oldest entries are pruned on each insert.
        max_entries: Option<usize>,
        /// Max age in days for audit entries. Older entries are pruned on each insert.
        max_age_days: Option<u64>,
    },
    Webhook {
        url: String,
        /// Optional Bearer token sent in the Authorization header.
        token: Option<String>,
        /// Emit events in CNCF CloudEvents 1.0 format.
        /// Content-Type becomes `application/cloudevents+json`.
        /// Enables direct ingestion by SIEMs (Splunk, Elastic, Datadog).
        #[serde(default)]
        cloudevents: bool,
        /// CloudEvents `source` attribute — identifies this gateway instance.
        /// Should be a URI-reference. Defaults to `/arbit`.
        #[serde(default = "default_ce_source")]
        source: String,
    },
}

fn default_ce_source() -> String {
    "/arbit".to_string()
}

fn default_db_path() -> String {
    "gateway-audit.db".to_string()
}

// ── Policy ───────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone)]
pub struct AgentPolicy {
    /// None = all tools allowed (except denied_tools).
    /// Entries may contain `*` as a glob wildcard (e.g. `read_*`, `fs/*`).
    pub allowed_tools: Option<Vec<String>>,
    /// Entries may contain `*` as a glob wildcard.
    #[serde(default)]
    pub denied_tools: Vec<String>,
    #[serde(default = "default_rate_limit")]
    pub rate_limit: usize,
    /// Per-tool rate limits (calls/min). Checked in addition to the global rate_limit.
    #[serde(default)]
    pub tool_rate_limits: HashMap<String, usize>,
    /// Named upstream to use for this agent. Falls back to the default upstream if unset.
    pub upstream: Option<String>,
    /// Pre-shared API key. When set, the agent must send `X-Api-Key: <key>` on initialize.
    pub api_key: Option<String>,
    /// Per-agent upstream timeout in seconds. Overrides the default 30s client timeout.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    /// Tools that require human approval before being forwarded to the upstream.
    /// Supports the same glob syntax as `allowed_tools` / `denied_tools`.
    #[serde(default)]
    pub approval_required: Vec<String>,
    /// Seconds to wait for a human decision before auto-rejecting. Default: 60.
    #[serde(default = "default_hitl_timeout")]
    pub hitl_timeout_secs: u64,
    /// Tools that run in shadow mode: intercepted, logged, but NOT forwarded to the upstream.
    /// The gateway returns a mock success response so the agent can continue normally.
    /// Supports the same glob syntax as `allowed_tools` / `denied_tools`.
    #[serde(default)]
    pub shadow_tools: Vec<String>,
    /// When true the gateway queries ALL named upstreams for this agent, merges their tool
    /// lists into a single view, and routes each `tools/call` to the correct upstream.
    /// Colliding tool names are prefixed with `<upstream>__` (e.g. `filesystem__read_file`).
    #[serde(default)]
    pub federate: bool,
}

fn default_rate_limit() -> usize {
    60
}

fn default_hitl_timeout() -> u64 {
    60
}

/// Match a tool name against a pattern that may contain `*` as a wildcard.
/// `*` matches zero or more characters. Multiple wildcards are supported.
///
/// Examples:
/// - `"read_file"` matches only `"read_file"` (exact)
/// - `"read_*"` matches `"read_file"`, `"read_dir"`, etc.
/// - `"*"` matches any tool name
pub(crate) fn tool_matches(pattern: &str, tool: &str) -> bool {
    if !pattern.contains('*') {
        return pattern == tool;
    }
    fn r#match(p: &[u8], t: &[u8]) -> bool {
        match p.first() {
            None => t.is_empty(),
            Some(b'*') => (0..=t.len()).any(|i| r#match(&p[1..], &t[i..])),
            Some(&c) => !t.is_empty() && t[0] == c && r#match(&p[1..], &t[1..]),
        }
    }
    r#match(pattern.as_bytes(), tool.as_bytes())
}

// ── JWT / OIDC ────────────────────────────────────────────────────────────────

/// Accepts either a single provider config or a list of providers.
/// On `initialize`, each provider is tried in order — the first that
/// successfully validates the token wins.
///
/// ```yaml
/// # Single provider (backward compatible)
/// auth:
///   jwks_url: "https://example.com/.well-known/jwks.json"
///
/// # Multiple providers
/// auth:
///   - provider: google
///     audience: "my-client-id"
///   - provider: okta
///     issuer: "https://dev-123.okta.com"
/// ```
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum AuthConfig {
    Single(JwtConfig),
    Multi(Vec<JwtConfig>),
}

impl AuthConfig {
    /// Expand into a flat list of validated configs.
    pub fn into_configs(self) -> anyhow::Result<Vec<JwtConfig>> {
        match self {
            AuthConfig::Single(c) => Ok(vec![c.with_provider_defaults()?]),
            AuthConfig::Multi(cs) => cs.into_iter().map(|c| c.with_provider_defaults()).collect(),
        }
    }
}

/// JWT authentication config — validated on every `initialize` that carries
/// an `Authorization: Bearer <token>` header. The decoded claim identified by
/// `agent_claim` is used as the agent identity.
#[derive(Debug, Deserialize, Clone)]
pub struct JwtConfig {
    /// HMAC secret for HS256 tokens. Mutually exclusive with `jwks_url`.
    pub secret: Option<String>,
    /// Explicit JWKS endpoint URL. Mutually exclusive with `secret`.
    /// Ignored when `oidc_discovery: true` — the URL is discovered automatically.
    pub jwks_url: Option<String>,
    /// Required `iss` claim. Token is rejected if the issuer doesn't match.
    /// Also used as the base URL for OIDC discovery.
    pub issuer: Option<String>,
    /// Required `aud` claim. Token is rejected if the audience doesn't match.
    pub audience: Option<String>,
    /// JWT claim used as the agent identity. Defaults to `"sub"`.
    #[serde(default = "default_agent_claim")]
    pub agent_claim: String,
    /// Auto-discover the JWKS URL from `{issuer}/.well-known/openid-configuration`.
    /// Enabled automatically when `provider` is set. Requires `issuer`.
    #[serde(default)]
    pub oidc_discovery: bool,
    /// Provider shorthand. Sets `issuer` and enables `oidc_discovery` automatically.
    /// Supported: `google`, `github-actions`, `auth0`, `okta`.
    /// For `auth0` and `okta`, `issuer` must also be set.
    pub provider: Option<String>,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            secret: None,
            jwks_url: None,
            issuer: None,
            audience: None,
            agent_claim: default_agent_claim(),
            oidc_discovery: false,
            provider: None,
        }
    }
}

impl JwtConfig {
    /// Apply built-in provider defaults and validate the config.
    pub fn with_provider_defaults(mut self) -> anyhow::Result<Self> {
        match self.provider.as_deref() {
            Some("google") => {
                self.issuer
                    .get_or_insert_with(|| "https://accounts.google.com".to_string());
                self.oidc_discovery = true;
            }
            Some("github-actions") => {
                self.issuer.get_or_insert_with(|| {
                    "https://token.actions.githubusercontent.com".to_string()
                });
                self.oidc_discovery = true;
            }
            Some("auth0") => {
                if self.issuer.is_none() {
                    return Err(anyhow::anyhow!(
                        "provider 'auth0' requires 'issuer' to be set"
                    ));
                }
                self.oidc_discovery = true;
            }
            Some("okta") => {
                if self.issuer.is_none() {
                    return Err(anyhow::anyhow!(
                        "provider 'okta' requires 'issuer' to be set"
                    ));
                }
                self.oidc_discovery = true;
            }
            Some(p) => {
                return Err(anyhow::anyhow!(
                    "unknown auth provider '{p}'. Supported: google, github-actions, auth0, okta"
                ));
            }
            None => {}
        }
        Ok(self)
    }
}

fn default_agent_claim() -> String {
    "sub".to_string()
}

// ── Telemetry ─────────────────────────────────────────────────────────────────

/// OpenTelemetry tracing configuration.
/// When set, spans are exported to the configured OTLP endpoint.
#[derive(Debug, Deserialize, Clone)]
pub struct TelemetryConfig {
    /// OTLP gRPC endpoint (e.g. `http://localhost:4317`).
    pub otlp_endpoint: String,
    /// `service.name` resource attribute. Defaults to `"arbit"`.
    #[serde(default = "default_service_name")]
    pub service_name: String,
}

fn default_service_name() -> String {
    "arbit".to_string()
}

// ── Rules ─────────────────────────────────────────────────────────────────────

/// Controls what happens when a `tools/call` argument matches a `block_pattern`.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum FilterMode {
    /// Reject the request with an error (default).
    #[default]
    Block,
    /// Scrub matching values from the arguments and allow the sanitised request through.
    Redact,
}

#[derive(Debug, Deserialize, Default)]
pub struct Rules {
    #[serde(default)]
    pub block_patterns: Vec<String>,
    /// Maximum requests per minute from a single IP address (HTTP mode only).
    /// Applies before per-agent limits. None = no IP-based limit.
    pub ip_rate_limit: Option<usize>,
    /// Enable built-in prompt injection detection. Matched requests are always blocked,
    /// regardless of `filter_mode`. Default: false.
    #[serde(default)]
    pub block_prompt_injection: bool,
    /// How to handle `tools/call` arguments that match `block_patterns`.
    /// `block` (default): reject the request with an error.
    /// `redact`: scrub matching values and allow the sanitised request.
    #[serde(default)]
    pub filter_mode: FilterMode,
}

#[cfg(test)]
pub(crate) fn make_agent(
    allowed: Option<Vec<&str>>,
    denied: Vec<&str>,
    rate_limit: usize,
) -> AgentPolicy {
    AgentPolicy {
        allowed_tools: allowed.map(|v| v.into_iter().map(String::from).collect()),
        denied_tools: denied.into_iter().map(String::from).collect(),
        rate_limit,
        tool_rate_limits: std::collections::HashMap::new(),
        upstream: None,
        api_key: None,
        timeout_secs: None,
        approval_required: vec![],
        hitl_timeout_secs: 60,
        shadow_tools: vec![],
        federate: false,
    }
}

impl Config {
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let s = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("could not read '{}': {}", path, e))?;
        let config: Self =
            serde_yaml::from_str(&s).map_err(|e| anyhow::anyhow!("invalid config: {}", e))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> anyhow::Result<()> {
        // Validate block_patterns are valid regexes
        for pattern in &self.rules.block_patterns {
            Regex::new(pattern)
                .map_err(|e| anyhow::anyhow!("invalid block_pattern '{}': {}", pattern, e))?;
        }

        // Validate tool names contain only safe characters to prevent injection.
        // '*' is allowed as a glob wildcard in allowed_tools and denied_tools patterns.
        let tool_name_re = Regex::new(r"^[a-zA-Z0-9_/.\-*]+$").unwrap();
        let all_policies = self
            .agents
            .iter()
            .map(|(k, v)| (k.as_str(), v))
            .chain(self.default_policy.as_ref().map(|p| ("default_policy", p)));
        for (agent, policy) in all_policies {
            for tool in policy
                .allowed_tools
                .iter()
                .flatten()
                .chain(&policy.denied_tools)
            {
                if !tool_name_re.is_match(tool) {
                    return Err(anyhow::anyhow!(
                        "agent '{}': invalid tool name '{}'",
                        agent,
                        tool
                    ));
                }
            }
        }

        // Validate agent upstream references exist in upstreams map
        for (agent, policy) in &self.agents {
            if let Some(upstream_name) = &policy.upstream
                && !self.upstreams.contains_key(upstream_name)
            {
                return Err(anyhow::anyhow!(
                    "agent '{}' references unknown upstream '{}'",
                    agent,
                    upstream_name
                ));
            }
        }

        // Validate TLS files exist when TLS is configured
        if let TransportConfig::Http { tls: Some(tls), .. } = &self.transport {
            if !std::path::Path::new(&tls.cert).exists() {
                return Err(anyhow::anyhow!("TLS cert file not found: {}", tls.cert));
            }
            if !std::path::Path::new(&tls.key).exists() {
                return Err(anyhow::anyhow!("TLS key file not found: {}", tls.key));
            }
        }

        // Validate circuit breaker threshold is non-zero
        if let TransportConfig::Http {
            circuit_breaker: cb,
            ..
        } = &self.transport
            && cb.threshold == 0
        {
            return Err(anyhow::anyhow!("circuit_breaker.threshold must be > 0"));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn base() -> Config {
        Config {
            transport: TransportConfig::default(),
            audit: None,
            audits: vec![],
            agents: HashMap::new(),
            default_policy: None,
            rules: Rules::default(),
            upstreams: HashMap::new(),
            auth: None,
            admin_token: None,
            telemetry: None,
        }
    }

    #[test]
    fn empty_config_passes_validate() {
        assert!(base().validate().is_ok());
    }

    #[test]
    fn invalid_regex_is_rejected() {
        let mut cfg = base();
        cfg.rules.block_patterns = vec!["[unclosed".to_string()];
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn valid_block_patterns_pass() {
        let mut cfg = base();
        cfg.rules.block_patterns = vec!["private_key".to_string(), r"\bsecret\b".to_string()];
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn tool_name_with_spaces_is_rejected() {
        let mut cfg = base();
        cfg.agents.insert(
            "a".to_string(),
            make_agent(Some(vec!["bad name"]), vec![], 60),
        );
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn tool_name_with_exclamation_is_rejected() {
        let mut cfg = base();
        cfg.agents
            .insert("a".to_string(), make_agent(None, vec!["bad!tool"], 60));
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn valid_tool_names_pass() {
        let mut cfg = base();
        cfg.agents.insert(
            "a".to_string(),
            make_agent(
                Some(vec!["read_file", "list-dir", "tools/v2.echo"]),
                vec!["delete_file"],
                60,
            ),
        );
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn unknown_upstream_reference_fails() {
        let mut cfg = base();
        let mut policy = make_agent(None, vec![], 60);
        policy.upstream = Some("ghost".to_string());
        cfg.agents.insert("a".to_string(), policy);
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn known_upstream_reference_passes() {
        let mut cfg = base();
        cfg.upstreams
            .insert("mcp".to_string(), "http://localhost:3000/mcp".to_string());
        let mut policy = make_agent(None, vec![], 60);
        policy.upstream = Some("mcp".to_string());
        cfg.agents.insert("a".to_string(), policy);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn zero_circuit_breaker_threshold_fails() {
        let mut cfg = base();
        cfg.transport = TransportConfig::Http {
            addr: "0.0.0.0:4000".to_string(),
            upstream: "http://localhost:3000/mcp".to_string(),
            session_ttl_secs: 3600,
            tls: None,
            circuit_breaker: CircuitBreakerConfig {
                threshold: 0,
                recovery_secs: 30,
            },
        };
        assert!(cfg.validate().is_err());
    }

    // ── JwtConfig provider presets ───────────────────────────────────────────

    #[test]
    fn google_preset_sets_issuer_and_discovery() {
        let cfg = JwtConfig {
            provider: Some("google".to_string()),
            ..JwtConfig::default()
        }
        .with_provider_defaults()
        .unwrap();
        assert_eq!(cfg.issuer.as_deref(), Some("https://accounts.google.com"));
        assert!(cfg.oidc_discovery);
    }

    #[test]
    fn github_actions_preset_sets_issuer() {
        let cfg = JwtConfig {
            provider: Some("github-actions".to_string()),
            ..JwtConfig::default()
        }
        .with_provider_defaults()
        .unwrap();
        assert_eq!(
            cfg.issuer.as_deref(),
            Some("https://token.actions.githubusercontent.com")
        );
        assert!(cfg.oidc_discovery);
    }

    #[test]
    fn auth0_without_issuer_fails() {
        let cfg = JwtConfig {
            provider: Some("auth0".to_string()),
            ..JwtConfig::default()
        };
        assert!(cfg.with_provider_defaults().is_err());
    }

    #[test]
    fn auth0_with_issuer_enables_discovery() {
        let cfg = JwtConfig {
            provider: Some("auth0".to_string()),
            issuer: Some("https://myapp.auth0.com".to_string()),
            ..JwtConfig::default()
        }
        .with_provider_defaults()
        .unwrap();
        assert!(cfg.oidc_discovery);
    }

    #[test]
    fn unknown_provider_fails() {
        let cfg = JwtConfig {
            provider: Some("magic".to_string()),
            ..JwtConfig::default()
        };
        assert!(cfg.with_provider_defaults().is_err());
    }

    #[test]
    fn no_provider_is_unchanged() {
        let cfg = JwtConfig {
            secret: Some("s".to_string()),
            ..JwtConfig::default()
        }
        .with_provider_defaults()
        .unwrap();
        assert_eq!(cfg.secret.as_deref(), Some("s"));
        assert!(!cfg.oidc_discovery);
    }

    // ── tool_matches ─────────────────────────────────────────────────────────

    #[test]
    fn exact_match() {
        assert!(tool_matches("read_file", "read_file"));
        assert!(!tool_matches("read_file", "write_file"));
    }

    #[test]
    fn suffix_wildcard() {
        assert!(tool_matches("read_*", "read_file"));
        assert!(tool_matches("read_*", "read_dir"));
        assert!(tool_matches("read_*", "read_"));
        assert!(!tool_matches("read_*", "write_file"));
    }

    #[test]
    fn prefix_wildcard() {
        assert!(tool_matches("*_file", "read_file"));
        assert!(tool_matches("*_file", "write_file"));
        assert!(!tool_matches("*_file", "read_dir"));
    }

    #[test]
    fn star_matches_all() {
        assert!(tool_matches("*", "read_file"));
        assert!(tool_matches("*", "anything"));
        assert!(tool_matches("*", ""));
    }

    #[test]
    fn middle_wildcard() {
        assert!(tool_matches("read_*_v2", "read_file_v2"));
        assert!(!tool_matches("read_*_v2", "read_file_v3"));
    }

    #[test]
    fn wildcard_in_denied_tools_validation() {
        let mut cfg = base();
        cfg.agents.insert(
            "a".to_string(),
            make_agent(Some(vec!["read_*", "list_*"]), vec!["delete_*"], 60),
        );
        assert!(cfg.validate().is_ok());
    }
}
