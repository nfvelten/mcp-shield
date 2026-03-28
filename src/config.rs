use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub transport: TransportConfig,
    #[serde(default)]
    pub audit: AuditConfig,
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
        }
    }
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
    },
    Webhook {
        url: String,
        /// Optional Bearer token sent in the Authorization header.
        token: Option<String>,
    },
}

impl Default for AuditConfig {
    fn default() -> Self {
        AuditConfig::Stdout
    }
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
    /// Named upstream to use for this agent. Falls back to the default upstream if unset.
    pub upstream: Option<String>,
}

fn default_rate_limit() -> usize {
    60
}

#[derive(Debug, Deserialize, Default)]
pub struct Rules {
    #[serde(default)]
    pub block_patterns: Vec<String>,
}

impl Config {
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let s = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("could not read '{}': {}", path, e))?;
        serde_yaml::from_str(&s).map_err(|e| anyhow::anyhow!("invalid config: {}", e))
    }
}
