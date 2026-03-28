use mcp_gateway::{
    audit::{sqlite::SqliteAudit, stdout::StdoutAudit, AuditLog},
    config::{AuditConfig, Config, TransportConfig},
    gateway::McpGateway,
    middleware::{
        auth::AuthMiddleware, payload_filter::PayloadFilterMiddleware,
        rate_limit::RateLimitMiddleware, Pipeline,
    },
    transport::{http::HttpTransport, stdio::StdioTransport, Transport},
    upstream::http::HttpUpstream,
};
use regex::Regex;
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config_path = std::env::args().nth(1).unwrap_or_else(|| "gateway.yml".into());
    let config = Config::from_file(&config_path)?;

    // Audit log — pluggable via config
    let audit: Arc<dyn AuditLog> = match &config.audit {
        AuditConfig::Stdout => Arc::new(StdoutAudit),
        AuditConfig::Sqlite { path } => {
            eprintln!("[GATEWAY] SQLite audit at {path}");
            Arc::new(SqliteAudit::new(path)?)
        }
    };

    let block_patterns: Vec<Regex> = config
        .rules
        .block_patterns
        .iter()
        .map(|p| Regex::new(p).unwrap_or_else(|_| panic!("invalid regex: {p}")))
        .collect();

    // Wrap agents in Arc so all consumers share the same allocation
    let agents = Arc::new(config.agents);

    let pipeline = Pipeline::new()
        .add(Arc::new(RateLimitMiddleware::new(&agents)))
        .add(Arc::new(AuthMiddleware::new(Arc::clone(&agents))))
        .add(Arc::new(PayloadFilterMiddleware::new(block_patterns)));

    match config.transport {
        TransportConfig::Http { addr, upstream } => {
            eprintln!("[GATEWAY] HTTP mode | upstream={upstream} | addr={addr}");
            let gateway = Arc::new(McpGateway::new(
                pipeline,
                Arc::new(HttpUpstream::new(upstream)),
                audit.clone(),
                Arc::clone(&agents),
            ));
            HttpTransport::new(addr).serve(gateway).await?;
        }
        TransportConfig::Stdio { server } => {
            eprintln!("[GATEWAY] stdio mode | server={}", server.join(" "));
            let gateway = Arc::new(McpGateway::new(
                pipeline,
                Arc::new(HttpUpstream::new("")), // not used in stdio mode
                audit.clone(),
                Arc::clone(&agents),
            ));
            StdioTransport::new(server).serve(gateway).await?;
        }
    }

    // Flush pending audit writes before the process exits
    audit.flush().await;
    Ok(())
}
