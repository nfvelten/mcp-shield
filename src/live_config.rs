use crate::config::AgentPolicy;
use regex::Regex;
use std::{collections::HashMap, sync::Arc};

/// Hot-reloadable configuration snapshot.
/// Wrapped in `Arc` and broadcast via `tokio::sync::watch`.
/// All consumers (`borrow()`) always see the latest reloaded version.
pub struct LiveConfig {
    pub agents: HashMap<String, AgentPolicy>,
    /// Block patterns shared via `Arc` — cheap to snapshot in middleware without cloning
    /// each `Regex`. The inner `Vec` is immutable once constructed.
    pub block_patterns: Arc<Vec<Regex>>,
    /// Reverse map: api_key → agent_name.
    /// Used for key-based agent identity on `initialize`.
    pub api_keys: HashMap<String, String>,
    /// Max requests per minute per IP (HTTP mode). None = unlimited.
    pub ip_rate_limit: Option<usize>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AgentPolicy;
    use std::collections::HashMap;

    fn policy_with_key(key: &str) -> AgentPolicy {
        AgentPolicy {
            allowed_tools: None,
            denied_tools: vec![],
            rate_limit: 60,
            tool_rate_limits: HashMap::new(),
            upstream: None,
            api_key: Some(key.to_string()),
        }
    }

    fn policy_no_key() -> AgentPolicy {
        AgentPolicy {
            allowed_tools: None,
            denied_tools: vec![],
            rate_limit: 60,
            tool_rate_limits: HashMap::new(),
            upstream: None,
            api_key: None,
        }
    }

    #[test]
    fn api_keys_reverse_map_built_correctly() {
        let mut agents = HashMap::new();
        agents.insert("cursor".to_string(), policy_with_key("key-cursor"));
        agents.insert("claude".to_string(), policy_with_key("key-claude"));
        let live = LiveConfig::new(agents, vec![], None);
        assert_eq!(live.api_keys.get("key-cursor").map(String::as_str), Some("cursor"));
        assert_eq!(live.api_keys.get("key-claude").map(String::as_str), Some("claude"));
        assert_eq!(live.api_keys.len(), 2);
    }

    #[test]
    fn agent_without_api_key_not_in_map() {
        let mut agents = HashMap::new();
        agents.insert("anon".to_string(), policy_no_key());
        let live = LiveConfig::new(agents, vec![], None);
        assert!(live.api_keys.is_empty());
    }

    #[test]
    fn mixed_agents_only_keyed_ones_in_map() {
        let mut agents = HashMap::new();
        agents.insert("keyed".to_string(), policy_with_key("k1"));
        agents.insert("open".to_string(), policy_no_key());
        let live = LiveConfig::new(agents, vec![], None);
        assert_eq!(live.api_keys.len(), 1);
        assert!(live.api_keys.contains_key("k1"));
    }

    #[test]
    fn block_patterns_stored_in_arc() {
        let re = regex::Regex::new("secret").unwrap();
        let live = LiveConfig::new(HashMap::new(), vec![re], None);
        assert_eq!(live.block_patterns.len(), 1);
        // Arc::strong_count confirms it's wrapped
        assert_eq!(Arc::strong_count(&live.block_patterns), 1);
    }

    #[test]
    fn ip_rate_limit_preserved() {
        let live = LiveConfig::new(HashMap::new(), vec![], Some(100));
        assert_eq!(live.ip_rate_limit, Some(100));
        let live2 = LiveConfig::new(HashMap::new(), vec![], None);
        assert_eq!(live2.ip_rate_limit, None);
    }
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
        Self {
            agents,
            block_patterns: Arc::new(block_patterns),
            api_keys,
            ip_rate_limit,
        }
    }
}
