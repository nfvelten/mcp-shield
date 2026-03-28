use crate::config::AgentPolicy;
use regex::Regex;
use std::collections::HashMap;

/// Hot-reloadable configuration snapshot.
/// Wrapped in `Arc` and broadcast via `tokio::sync::watch`.
/// All consumers (`borrow()`) always see the latest reloaded version.
pub struct LiveConfig {
    pub agents: HashMap<String, AgentPolicy>,
    pub block_patterns: Vec<Regex>,
    /// Reverse map: api_key → agent_name.
    /// Used for key-based agent identity on `initialize`.
    pub api_keys: HashMap<String, String>,
    /// Max requests per minute per IP (HTTP mode). None = unlimited.
    pub ip_rate_limit: Option<usize>,
}

impl LiveConfig {
    pub fn new(
        agents: HashMap<String, AgentPolicy>,
        block_patterns: Vec<Regex>,
        ip_rate_limit: Option<usize>,
    ) -> Self {
        let api_keys = agents
            .iter()
            .filter_map(|(name, p)| p.api_key.as_ref().map(|k| (k.clone(), name.clone())))
            .collect();
        Self { agents, block_patterns, api_keys, ip_rate_limit }
    }
}
