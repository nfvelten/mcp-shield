use mcp_shield::{
    audit::{
        AuditLog, fanout::FanoutAudit, sqlite::SqliteAudit, stdout::StdoutAudit,
        webhook::WebhookAudit,
    },
    config::{AuditConfig, Config, TelemetryConfig, TransportConfig},
    gateway::McpGateway,
    jwt::MultiJwtValidator,
    live_config::LiveConfig,
    metrics::GatewayMetrics,
    middleware::{
        Pipeline, auth::AuthMiddleware, payload_filter::PayloadFilterMiddleware,
        rate_limit::RateLimitMiddleware,
        schema_validation::SchemaValidationMiddleware,
    },
    prompt_injection,
    schema_cache::SchemaCache,
    transport::{Transport, http::HttpTransport, stdio::StdioTransport},
    upstream::{McpUpstream, http::HttpUpstream},
};
use regex::Regex;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::watch;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load config first — needed for telemetry setup
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "gateway.yml".into());
    let config = Config::from_file(&config_path)?;

    // ── Logging + OpenTelemetry ────────────────────────────────────────────────
    // LOG_FORMAT=json  → structured JSON (production)
    // LOG_FORMAT=<anything else> or unset → human-readable (default)
    // LOG_LEVEL overrides the default "info" level (e.g. LOG_LEVEL=debug)
    let _otel_guard = init_tracing(config.telemetry.as_ref());

    // ── Audit log — pluggable, fan-out to all configured backends ──────────────
    let mut audit_backends: Vec<Arc<dyn AuditLog>> = Vec::new();
    // Track the first SQLite path for the /dashboard endpoint
    let mut sqlite_db_path: Option<String> = None;

    // New-style `audits:` list
    for backend_cfg in &config.audits {
        if let AuditConfig::Sqlite { path, .. } = backend_cfg
            && sqlite_db_path.is_none()
        {
            sqlite_db_path = Some(path.clone());
        }
        audit_backends.push(build_audit_backend(backend_cfg)?);
    }
    // Legacy `audit:` single backend (backward compat)
    if let Some(backend_cfg) = &config.audit {
        if let AuditConfig::Sqlite { path, .. } = backend_cfg
            && sqlite_db_path.is_none()
        {
            sqlite_db_path = Some(path.clone());
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

    let injection_patterns: Vec<Regex> = if config.rules.block_prompt_injection {
        tracing::info!(
            "prompt injection detection enabled ({} patterns)",
            prompt_injection::PATTERNS.len()
        );
        prompt_injection::PATTERNS
            .iter()
            .map(|p| Regex::new(p).unwrap_or_else(|_| panic!("invalid injection regex: {p}")))
            .collect()
    } else {
        vec![]
    };

    let live = Arc::new(LiveConfig::new(
        config.agents,
        block_patterns,
        injection_patterns,
        config.rules.ip_rate_limit,
        config.rules.filter_mode,
        config.default_policy,
    ));
    let (config_tx, config_rx) = watch::channel(live);

    // ── Hot-reload — SIGUSR1 for immediate reload, polls every 30s as fallback ──
    {
        let reload_path = config_path.clone();
        let tx = config_tx;
        tokio::spawn(async move {
            #[cfg(unix)]
            let mut sigusr1 = {
                use tokio::signal::unix::{SignalKind, signal};
                signal(SignalKind::user_defined1()).expect("failed to install SIGUSR1 handler")
            };

            let mut last_modified = tokio::fs::metadata(&reload_path)
                .await
                .ok()
                .and_then(|m| m.modified().ok());
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            interval.tick().await; // consume immediate first tick
            let mut last_error: Option<std::time::Instant> = None;

            loop {
                // Wait for either the polling interval or a SIGUSR1 signal.
                // On SIGUSR1 we reload immediately regardless of mtime.
                #[cfg(unix)]
                {
                    enum Trigger {
                        Timer,
                        Signal,
                    }
                    let trigger = tokio::select! {
                        _ = interval.tick() => Trigger::Timer,
                        _ = sigusr1.recv() => Trigger::Signal,
                    };
                    if matches!(trigger, Trigger::Signal) {
                        tracing::info!("SIGUSR1 received, reloading config");
                        do_reload(&reload_path, &tx, &mut last_error);
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
                    do_reload(&reload_path, &tx, &mut last_error);
                }
            }
        });
    }

    // ── Schema cache — shared between gateway (writes) and validation middleware (reads) ──
    let schema_cache = SchemaCache::new();

    // ── Pipeline — each middleware subscribes to live config ───────────────────
    let pipeline = Pipeline::new()
        .add(Arc::new(RateLimitMiddleware::new(config_rx.clone())))
        .add(Arc::new(AuthMiddleware::new(config_rx.clone())))
        .add(Arc::new(SchemaValidationMiddleware::new(schema_cache.clone())))
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

    // ── JWT / OAuth validator — built once at startup ──────────────────────
    let jwt = config.auth.map(|auth_cfg| {
        let configs = auth_cfg.into_configs().expect("invalid auth config");
        tracing::info!(providers = configs.len(), "auth configured");
        Arc::new(MultiJwtValidator::new(configs))
    });

    match config.transport {
        TransportConfig::Http {
            addr,
            upstream,
            session_ttl_secs,
            tls,
            circuit_breaker,
        } => {
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
                schema_cache,
            ));
            HttpTransport::new(
                addr,
                session_ttl_secs,
                tls,
                metrics,
                config_rx,
                jwt,
                sqlite_db_path,
                config.admin_token,
            )
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
                schema_cache,
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
        AuditConfig::Sqlite {
            path,
            max_entries,
            max_age_days,
        } => {
            tracing::info!(path, "SQLite audit");
            Ok(Arc::new(SqliteAudit::with_rotation(
                path,
                *max_entries,
                *max_age_days,
            )?))
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
    last_error: &mut Option<std::time::Instant>,
) {
    match Config::from_file(reload_path) {
        Ok(new_cfg) => {
            *last_error = None;
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
            let new_injection: Vec<Regex> = if new_cfg.rules.block_prompt_injection {
                prompt_injection::PATTERNS
                    .iter()
                    .filter_map(|p| Regex::new(p).ok())
                    .collect()
            } else {
                vec![]
            };
            let new_live = Arc::new(LiveConfig::new(
                new_cfg.agents,
                new_patterns,
                new_injection,
                new_cfg.rules.ip_rate_limit,
                new_cfg.rules.filter_mode,
                new_cfg.default_policy,
            ));
            if tx.send(new_live).is_ok() {
                tracing::info!(path = reload_path, "config reloaded");
            }
        }
        Err(e) => {
            // Throttle error logging to at most once every 5s to prevent log spam
            // when the file is temporarily invalid (e.g. mid-write by an editor).
            let now = std::time::Instant::now();
            let should_log = last_error
                .map(|t| now.duration_since(t).as_secs() >= 5)
                .unwrap_or(true);
            if should_log {
                tracing::error!(error = %e, "config reload failed");
                *last_error = Some(now);
            }
        }
    }
}

// ── OpenTelemetry ─────────────────────────────────────────────────────────────

/// RAII guard that shuts down the global OTel tracer provider on drop,
/// flushing any buffered spans before the process exits.
struct OtelGuard;

impl Drop for OtelGuard {
    fn drop(&mut self) {
        opentelemetry::global::shutdown_tracer_provider();
    }
}

/// Initialise tracing subscriber (fmt + optional OTel OTLP layer).
///
/// LOG_FORMAT=json  → structured JSON output
/// LOG_LEVEL        → override log level (default: info)
/// telemetry config → enables OTLP span export when present
fn init_tracing(telemetry: Option<&TelemetryConfig>) -> Option<OtelGuard> {
    let filter = EnvFilter::try_from_env("LOG_LEVEL").unwrap_or_else(|_| EnvFilter::new("info"));
    let json = std::env::var("LOG_FORMAT").as_deref() == Ok("json");

    let tracer = telemetry.and_then(|tel| match build_otel_tracer(tel) {
        Ok(t) => Some(t),
        Err(e) => {
            eprintln!("warn: OTel init failed: {e}");
            None
        }
    });

    let has_otel = tracer.is_some();

    // Four branches to keep concrete types — Option<Layer> would require boxing
    // both the fmt and OTel layers due to incompatible generic parameters.
    match (json, tracer) {
        (true, Some(t)) => tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().json())
            .with(tracing_opentelemetry::layer().with_tracer(t))
            .init(),
        (true, None) => tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().json())
            .init(),
        (false, Some(t)) => tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer())
            .with(tracing_opentelemetry::layer().with_tracer(t))
            .init(),
        (false, None) => tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer())
            .init(),
    }

    if has_otel { Some(OtelGuard) } else { None }
}

/// Build an OTLP gRPC tracer. Returns the `Tracer` handle so the caller can
/// create a `tracing_opentelemetry::Layer` with the correct concrete type.
fn build_otel_tracer(tel: &TelemetryConfig) -> anyhow::Result<opentelemetry_sdk::trace::Tracer> {
    use opentelemetry::KeyValue;
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_otlp::WithExportConfig;
    use opentelemetry_sdk::{Resource, runtime::Tokio, trace::Config};

    let resource = Resource::new(vec![KeyValue::new(
        "service.name",
        tel.service_name.clone(),
    )]);

    let provider = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint(&tel.otlp_endpoint),
        )
        .with_trace_config(Config::default().with_resource(resource))
        .install_batch(Tokio)
        .map_err(|e| anyhow::anyhow!("OTLP pipeline: {e}"))?;

    Ok(provider.tracer("mcp-shield"))
}
