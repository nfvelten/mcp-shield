use prometheus::{CounterVec, Encoder, Opts, Registry, TextEncoder};

pub struct GatewayMetrics {
    registry: Registry,
    requests: CounterVec,
    /// Per-agent token counter. Labels: `agent`, `direction` ("input" | "output").
    tokens: CounterVec,
}

impl GatewayMetrics {
    pub fn new() -> anyhow::Result<Self> {
        let registry = Registry::new();

        let requests = CounterVec::new(
            Opts::new("arbit_requests_total", "Total requests processed by arbit"),
            &["agent", "outcome"],
        )?;
        registry.register(Box::new(requests.clone()))?;

        let tokens = CounterVec::new(
            Opts::new(
                "arbit_tokens_total",
                "Estimated token count processed by arbit (4-chars-per-token heuristic)",
            ),
            &["agent", "direction"],
        )?;
        registry.register(Box::new(tokens.clone()))?;

        Ok(Self {
            registry,
            requests,
            tokens,
        })
    }

    pub fn record(&self, agent: &str, outcome: &str) {
        self.requests.with_label_values(&[agent, outcome]).inc();
    }

    /// Record estimated token usage for a single request.
    ///
    /// - `input_tokens`: tokens estimated from the request arguments
    /// - `output_tokens`: tokens estimated from the upstream response
    pub fn record_tokens(&self, agent: &str, input_tokens: u32, output_tokens: u32) {
        if input_tokens > 0 {
            self.tokens
                .with_label_values(&[agent, "input"])
                .inc_by(f64::from(input_tokens));
        }
        if output_tokens > 0 {
            self.tokens
                .with_label_values(&[agent, "output"])
                .inc_by(f64::from(output_tokens));
        }
    }

    /// Render all metrics in Prometheus text exposition format.
    pub fn render(&self) -> String {
        let encoder = TextEncoder::new();
        let families = self.registry.gather();
        let mut buf = Vec::new();
        let _ = encoder.encode(&families, &mut buf);
        String::from_utf8(buf).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_tokens_updates_counter() {
        let m = GatewayMetrics::new().unwrap();
        m.record_tokens("agent-a", 10, 25);
        let rendered = m.render();
        assert!(rendered.contains("arbit_tokens_total"));
        assert!(rendered.contains(r#"direction="input""#));
        assert!(rendered.contains(r#"direction="output""#));
    }

    #[test]
    fn zero_tokens_not_recorded() {
        let m = GatewayMetrics::new().unwrap();
        m.record_tokens("agent-a", 0, 0);
        let rendered = m.render();
        // Counter family is registered but no samples emitted for this agent
        assert!(!rendered.contains(r#"agent="agent-a""#));
    }

    #[test]
    fn multiple_agents_tracked_independently() {
        let m = GatewayMetrics::new().unwrap();
        m.record_tokens("cursor", 5, 10);
        m.record_tokens("claude", 20, 40);
        let rendered = m.render();
        assert!(rendered.contains(r#"agent="cursor""#));
        assert!(rendered.contains(r#"agent="claude""#));
    }
}
