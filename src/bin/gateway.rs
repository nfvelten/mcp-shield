use mcp_gateway::{
    audit::{
        fanout::FanoutAudit, sqlite::SqliteAudit, stdout::StdoutAudit, webhook::WebhookAudit,
        AuditLog,
    },
    config::{AuditConfig, Config, TransportConfig},
    gateway::McpGateway,
    jwt::JwtValidator,
    live_config::LiveConfig,
    metrics::GatewayMetrics,
    middleware::{
        auth::AuthMiddleware, payload_filter::PayloadFilterMiddleware,
        rate_limit::RateLimitMiddleware, Pipeline,
    },
    transport::{http::HttpTransport, stdio::StdioTransport, Transport},
    upstream::{http::HttpUpstream, McpUpstream},
};
use regex::Regex;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::watch;
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ── Logging ────────────────────────────────────────────────────────────────
    // LOG_FORMAT=json  → structured JSON (production)
    // LOG_FORMAT=<anything else> or unset → human-readable (default)
    // LOG_LEVEL overrides the default "info" level (e.g. LOG_LEVEL=debug)
    let filter = EnvFilter::try_from_env("LOG_LEVEL")
        .unwrap_or_else(|_| EnvFilter::new("info"));
    if std::env::var("LOG_FORMAT").as_deref() == Ok("json") {
        fmt().json().with_env_filter(filter).init();
    } else {
        fmt().with_env_filter(filter).init();
    }

    let config_path = std::env::args().nth(1).unwrap_or_else(|| "gateway.yml".into());
    let config = Config::from_file(&config_path)?;

    // ── Audit log — pluggable, fan-out to all configured backends ──────────────
    let mut audit_backends: Vec<Arc<dyn AuditLog>> = Vec::new();
    // Track the first SQLite path for the /dashboard endpoint
    let mut sqlite_db_path: Option<String> = None;

    // New-style `audits:` list
    for backend_cfg in &config.audits {
        if let AuditConfig::Sqlite { path, .. } = backend_cfg {
            if sqlite_db_path.is_none() { sqlite_db_path = Some(path.clone()); }
        }
        audit_backends.push(build_audit_backend(backend_cfg)?);
    }
    // Legacy `audit:` single backend (backward compat)
    if let Some(backend_cfg) = &config.audit {
        if let AuditConfig::Sqlite { path, .. } = backend_cfg {
            if sqlite_db_path.is_none() { sqlite_db_path = Some(path.clone()); }
        }
        audit_backends.push(build_audit_backend(backend_cfg)?);
    }
    // Default: stdout if nothing configured
    if audit_backends.is_empty() {
        audit_backends.push(Arc::new(StdoutAudit));
    }

    let audit: Arc<dyn AuditLog> = if audit_backends.len() == 1 {
        audit_backends.remove(0)
    } else {
        Arc::new(FanoutAudit::new(audit_backends))
    };

    // ── Live config — shared via watch channel for hot-reload ──────────────────
    let block_patterns: Vec<Regex> = config
        .rules
        .block_patterns
        .iter()
        .map(|p| Regex::new(p).unwrap_or_else(|_| panic!("invalid regex: {p}")))
        .collect();

    let live = Arc::new(LiveConfig::new(config.agents, block_patterns, config.rules.ip_rate_limit));
    let (config_tx, config_rx) = watch::channel(live);

    // ── Hot-reload — SIGUSR1 for immediate reload, polls every 30s as fallback ──
    {
        let reload_path = config_path.clone();
        let tx = config_tx;
        tokio::spawn(async move {
            #[cfg(unix)]
            let mut sigusr1 = {
                use tokio::signal::unix::{signal, SignalKind};
                signal(SignalKind::user_defined1()).expect("failed to install SIGUSR1 handler")
            };

            let mut last_modified = tokio::fs::metadata(&reload_path)
                .await
                .ok()
                .and_then(|m| m.modified().ok());
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            interval.tick().await; // consume immediate first tick

            loop {
                // Wait for either the polling interval or a SIGUSR1 signal.
                // On SIGUSR1 we reload immediately regardless of mtime.
                #[cfg(unix)]
                {
                    enum Trigger { Timer, Signal }
                    let trigger = tokio::select! {
                        _ = interval.tick() => Trigger::Timer,
                        _ = sigusr1.recv() => Trigger::Signal,
                    };
                    if matches!(trigger, Trigger::Signal) {
                        tracing::info!("SIGUSR1 received, reloading config");
                        do_reload(&reload_path, &tx);
                        last_modified = tokio::fs::metadata(&reload_path)
                            .await
                            .ok()
                            .and_then(|m| m.modified().ok());
                        continue;
                    }
                }
                #[cfg(not(unix))]
                interval.tick().await;

                let modified = tokio::fs::metadata(&reload_path)
                    .await
                    .ok()
                    .and_then(|m| m.modified().ok());
                if modified.is_some() && modified != last_modified {
                    last_modified = modified;
                    do_reload(&reload_path, &tx);
                }
            }
        });
    }

    // ── Pipeline — each middleware subscribes to live config ───────────────────
    let pipeline = Pipeline::new()
        .add(Arc::new(RateLimitMiddleware::new(config_rx.clone())))
        .add(Arc::new(AuthMiddleware::new(config_rx.clone())))
        .add(Arc::new(PayloadFilterMiddleware::new(config_rx.clone())));

    // ── Named upstreams ────────────────────────────────────────────────────────
    let named_upstreams: HashMap<String, Arc<dyn McpUpstream>> = config
        .upstreams
        .iter()
        .map(|(name, url)| {
            let upstream: Arc<dyn McpUpstream> = Arc::new(HttpUpstream::new(url));
            (name.clone(), upstream)
        })
        .collect();

    let metrics = Arc::new(GatewayMetrics::new()?);

    // ── JWT validator — built once at startup ───────────────────────────────
    let jwt = config.auth.map(|jwt_cfg| {
        if let Some(url) = &jwt_cfg.jwks_url {
            tracing::info!(url, "JWT auth via JWKS");
        } else {
            tracing::info!("JWT auth via HMAC secret");
        }
        Arc::new(JwtValidator::new(jwt_cfg))
    });

    match config.transport {
        TransportConfig::Http { addr, upstream, session_ttl_secs, tls, circuit_breaker } => {
            tracing::info!(upstream, addr, "HTTP mode");
            let default_upstream = Arc::new(HttpUpstream::with_circuit_breaker(
                &upstream,
                circuit_breaker.threshold,
                circuit_breaker.recovery_secs,
            ));
            let gateway = Arc::new(McpGateway::new(
                pipeline,
                default_upstream,
                named_upstreams,
                audit.clone(),
                Arc::clone(&metrics),
                config_rx.clone(),
            ));
            HttpTransport::new(addr, session_ttl_secs, tls, metrics, config_rx, jwt, sqlite_db_path)
                .serve(gateway)
                .await?;
        }
        TransportConfig::Stdio { server } => {
            tracing::info!(server = %server.join(" "), "stdio mode");
            let gateway = Arc::new(McpGateway::new(
                pipeline,
                Arc::new(HttpUpstream::new("")), // not used in stdio mode
                named_upstreams,
                audit.clone(),
                Arc::clone(&metrics),
                config_rx,
            ));
            StdioTransport::new(server).serve(gateway).await?;
        }
    }

    // Flush pending audit writes before the process exits
    audit.flush().await;
    Ok(())
}

fn build_audit_backend(cfg: &AuditConfig) -> anyhow::Result<Arc<dyn AuditLog>> {
    match cfg {
        AuditConfig::Stdout => Ok(Arc::new(StdoutAudit)),
        AuditConfig::Sqlite { path, max_entries, max_age_days } => {
            tracing::info!(path, "SQLite audit");
            Ok(Arc::new(SqliteAudit::with_rotation(path, *max_entries, *max_age_days)?))
        }
        AuditConfig::Webhook { url, token } => {
            tracing::info!(url, "webhook audit");
            Ok(Arc::new(WebhookAudit::new(url, token.clone())))
        }
    }
}

fn do_reload(
    reload_path: &str,
    tx: &tokio::sync::watch::Sender<Arc<LiveConfig>>,
) {
    match Config::from_file(reload_path) {
        Ok(new_cfg) => {
            let new_patterns: Vec<Regex> = new_cfg
                .rules
                .block_patterns
                .iter()
                .filter_map(|p| {
                    Regex::new(p)
                        .map_err(|e| tracing::warn!(pattern = p, error = %e, "invalid regex in reloaded config"))
                        .ok()
                })
                .collect();
            let new_live = Arc::new(LiveConfig::new(new_cfg.agents, new_patterns, new_cfg.rules.ip_rate_limit));
            if tx.send(new_live).is_ok() {
                tracing::info!(path = reload_path, "config reloaded");
            }
        }
        Err(e) => tracing::error!(error = %e, "config reload failed"),
    }
}
