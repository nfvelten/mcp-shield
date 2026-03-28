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
    #[serde(default)]
    pub rules: Rules,
    /// Named upstream servers — agents can reference these by name via `upstream:` in their policy.
    #[serde(default)]
    pub upstreams: HashMap<String, String>,
    /// Optional JWT / OIDC authentication configuration.
    pub auth: Option<JwtConfig>,
    /// Optional Bearer token required to access `/dashboard` and `/metrics`.
    /// When unset both endpoints are publicly accessible.
    pub admin_token: Option<String>,
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
    },
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
        Self { threshold: default_cb_threshold(), recovery_secs: default_cb_recovery_secs() }
    }
}

fn default_cb_threshold() -> usize { 5 }
fn default_cb_recovery_secs() -> u64 { 30 }

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
    },
}

fn default_db_path() -> String {
    "gateway-audit.db".to_string()
}

// ── Policy ───────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone)]
pub struct AgentPolicy {
    /// None = all tools allowed (except denied_tools)
    pub allowed_tools: Option<Vec<String>>,
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
}

fn default_rate_limit() -> usize {
    60
}

// ── JWT / OIDC ────────────────────────────────────────────────────────────────

/// JWT authentication config — validated on every `initialize` that carries
/// an `Authorization: Bearer <token>` header. The decoded claim identified by
/// `agent_claim` is used as the agent identity.
#[derive(Debug, Deserialize, Clone)]
pub struct JwtConfig {
    /// HMAC secret for HS256 tokens. Mutually exclusive with `jwks_url`.
    pub secret: Option<String>,
    /// JWKS endpoint URL for RS256/ES256 (OIDC). Mutually exclusive with `secret`.
    pub jwks_url: Option<String>,
    /// Required `iss` claim. Token is rejected if the issuer doesn't match.
    pub issuer: Option<String>,
    /// Required `aud` claim. Token is rejected if the audience doesn't match.
    pub audience: Option<String>,
    /// JWT claim used as the agent identity. Defaults to `"sub"`.
    #[serde(default = "default_agent_claim")]
    pub agent_claim: String,
}

fn default_agent_claim() -> String {
    "sub".to_string()
}

// ── Rules ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Default)]
pub struct Rules {
    #[serde(default)]
    pub block_patterns: Vec<String>,
    /// Maximum requests per minute from a single IP address (HTTP mode only).
    /// Applies before per-agent limits. None = no IP-based limit.
    pub ip_rate_limit: Option<usize>,
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

        // Validate tool names contain only safe characters to prevent injection
        let tool_name_re = Regex::new(r"^[a-zA-Z0-9_/.\-]+$").unwrap();
        for (agent, policy) in &self.agents {
            for tool in policy.allowed_tools.iter().flatten().chain(&policy.denied_tools) {
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
            if let Some(upstream_name) = &policy.upstream {
                if !self.upstreams.contains_key(upstream_name) {
                    return Err(anyhow::anyhow!(
                        "agent '{}' references unknown upstream '{}'",
                        agent,
                        upstream_name
                    ));
                }
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
        if let TransportConfig::Http { circuit_breaker: cb, .. } = &self.transport {
            if cb.threshold == 0 {
                return Err(anyhow::anyhow!("circuit_breaker.threshold must be > 0"));
            }
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
            rules: Rules::default(),
            upstreams: HashMap::new(),
            auth: None,
            admin_token: None,
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
        cfg.agents.insert("a".to_string(), make_agent(Some(vec!["bad name"]), vec![], 60));
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn tool_name_with_exclamation_is_rejected() {
        let mut cfg = base();
        cfg.agents.insert("a".to_string(), make_agent(None, vec!["bad!tool"], 60));
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn valid_tool_names_pass() {
        let mut cfg = base();
        cfg.agents.insert(
            "a".to_string(),
            make_agent(Some(vec!["read_file", "list-dir", "tools/v2.echo"]), vec!["delete_file"], 60),
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
        cfg.upstreams.insert("mcp".to_string(), "http://localhost:3000/mcp".to_string());
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
            circuit_breaker: CircuitBreakerConfig { threshold: 0, recovery_secs: 30 },
        };
        assert!(cfg.validate().is_err());
    }
}
