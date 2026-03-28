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

#[derive(Debug, Deserialize, Default)]
pub struct Rules {
    #[serde(default)]
    pub block_patterns: Vec<String>,
    /// Maximum requests per minute from a single IP address (HTTP mode only).
    /// Applies before per-agent limits. None = no IP-based limit.
    pub ip_rate_limit: Option<usize>,
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
