//! CLI tool for querying the gateway's SQLite audit log.
//!
//! Usage:
//!   audit [db_path] [--agent NAME] [--since DURATION] [--outcome OUTCOME] [--limit N]
//!
//! DURATION examples: 30s, 5m, 2h, 7d
//! OUTCOME values:    allowed | blocked | forwarded

use rusqlite::{types::Value, Connection};
use std::{
    env,
    time::{SystemTime, UNIX_EPOCH},
};

// ── CLI ───────────────────────────────────────────────────────────────────────

struct Opts {
    db_path: String,
    agent: Option<String>,
    since_secs: Option<u64>,
    outcome: Option<String>,
    limit: usize,
}

fn parse_args() -> Result<Opts, String> {
    let mut args = env::args().skip(1).peekable();

    let mut db_path = "gateway-audit.db".to_string();
    let mut agent = None;
    let mut since_secs = None;
    let mut outcome = None;
    let mut limit = 50usize;

    // First positional arg (if not a flag) is the db path
    if let Some(first) = args.peek() {
        if !first.starts_with("--") {
            db_path = first.clone();
            args.next();
        }
    }

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--agent" => {
                agent = Some(args.next().ok_or("--agent requires a value")?);
            }
            "--since" => {
                let raw = args.next().ok_or("--since requires a value")?;
                since_secs = Some(parse_duration(&raw)?);
            }
            "--outcome" => {
                let v = args.next().ok_or("--outcome requires a value")?;
                match v.as_str() {
                    "allowed" | "blocked" | "forwarded" => outcome = Some(v),
                    other => return Err(format!("unknown outcome '{other}'; use allowed, blocked, or forwarded")),
                }
            }
            "--limit" => {
                let v = args.next().ok_or("--limit requires a value")?;
                limit = v.parse::<usize>().map_err(|_| format!("invalid limit '{v}'"))?;
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument '{other}'")),
        }
    }

    Ok(Opts { db_path, agent, since_secs, outcome, limit })
}

fn parse_duration(s: &str) -> Result<u64, String> {
    let (num, unit) = s
        .find(|c: char| c.is_alphabetic())
        .map(|i| s.split_at(i))
        .ok_or_else(|| format!("invalid duration '{s}'; expected e.g. 30s, 5m, 2h, 7d"))?;

    let n: u64 = num.parse().map_err(|_| format!("invalid duration '{s}'"))?;
    let mult = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        other => return Err(format!("unknown unit '{other}'; use s, m, h, or d")),
    };
    Ok(n * mult)
}

fn print_help() {
    eprintln!(
        "audit — query the MCP gateway audit log\n\
         \n\
         Usage:\n\
           audit [db_path] [options]\n\
         \n\
         Options:\n\
           --agent NAME       filter by agent name\n\
           --since DURATION   show entries from last N seconds/minutes/hours/days (e.g. 1h, 30m)\n\
           --outcome VALUE    filter by outcome: allowed | blocked | forwarded\n\
           --limit N          max rows to show (default: 50)\n\
           --help             show this message\n\
         \n\
         Examples:\n\
           audit gateway-audit.db\n\
           audit gateway-audit.db --outcome blocked\n\
           audit gateway-audit.db --agent cursor --since 1h\n\
           audit gateway-audit.db --outcome blocked --limit 100"
    );
}

// ── Query ─────────────────────────────────────────────────────────────────────

fn run_query(opts: &Opts) -> anyhow::Result<()> {
    let conn = Connection::open(&opts.db_path)?;

    let now_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let mut conditions: Vec<String> = Vec::new();
    let mut binds: Vec<Value> = Vec::new();

    if let Some(agent) = &opts.agent {
        conditions.push("agent_id = ?".to_string());
        binds.push(Value::Text(agent.clone()));
    }
    if let Some(since) = opts.since_secs {
        let cutoff = now_ts - since as i64;
        conditions.push("ts >= ?".to_string());
        binds.push(Value::Integer(cutoff));
    }
    if let Some(outcome) = &opts.outcome {
        conditions.push("outcome = ?".to_string());
        binds.push(Value::Text(outcome.clone()));
    }

    let where_sql = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    let sql = format!(
        "SELECT ts, agent_id, method, tool, outcome, reason \
         FROM audit_log {where_sql} \
         ORDER BY ts DESC \
         LIMIT {}",
        opts.limit
    );

    let refs: Vec<&dyn rusqlite::types::ToSql> = binds.iter().map(|v| v as _).collect();

    let mut stmt = conn.prepare(&sql)?;
    let rows: Vec<_> = stmt
        .query_map(refs.as_slice(), |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
            ))
        })?
        .filter_map(|r| r.ok())
        .collect();

    // ── Summary stats ─────────────────────────────────────────────────────────

    let total: i64 = conn.query_row(
        &format!("SELECT COUNT(*) FROM audit_log {where_sql}"),
        refs.as_slice(),
        |r| r.get(0),
    )?;

    // ── Table ─────────────────────────────────────────────────────────────────

    println!(
        "\n{:<14} {:<16} {:<18} {:<22} {:<10} {}",
        "AGE", "AGENT", "METHOD", "TOOL", "OUTCOME", "REASON"
    );
    println!("{}", "─".repeat(110));

    for (ts, agent, method, tool, outcome, reason) in &rows {
        let age = format_age(*ts, now_ts);
        let outcome_display = match outcome.as_str() {
            "blocked"   => format!("\x1b[31m{outcome:<10}\x1b[0m"),
            "allowed"   => format!("\x1b[32m{outcome:<10}\x1b[0m"),
            "forwarded" => format!("{outcome:<10}"),
            _           => format!("{outcome:<10}"),
        };
        println!(
            "{:<14} {:<16} {:<18} {:<22} {} {}",
            age,
            trunc(agent, 15),
            trunc(method, 17),
            trunc(tool.as_deref().unwrap_or("-"), 21),
            outcome_display,
            reason.as_deref().unwrap_or(""),
        );
    }

    println!("{}", "─".repeat(110));

    // Filter summary line
    let mut filter_parts = Vec::new();
    if let Some(a) = &opts.agent   { filter_parts.push(format!("agent={a}")); }
    if let Some(s) = opts.since_secs { filter_parts.push(format!("since={}", format_duration(s))); }
    if let Some(o) = &opts.outcome  { filter_parts.push(format!("outcome={o}")); }
    let filter_str = if filter_parts.is_empty() {
        String::from("no filters")
    } else {
        filter_parts.join(", ")
    };

    println!(
        "Showing {} of {} total record(s) — {filter_str}",
        rows.len(),
        total,
    );
    Ok(())
}

// ── Formatting helpers ────────────────────────────────────────────────────────

fn format_age(ts: i64, now: i64) -> String {
    let diff = now - ts;
    if diff < 0       { "just now".to_string() }
    else if diff < 60 { format!("{diff}s ago") }
    else if diff < 3600 { format!("{}m ago", diff / 60) }
    else if diff < 86400 { format!("{}h ago", diff / 3600) }
    else               { format!("{}d ago", diff / 86400) }
}

fn format_duration(secs: u64) -> String {
    if secs % 86400 == 0 { format!("{}d", secs / 86400) }
    else if secs % 3600 == 0 { format!("{}h", secs / 3600) }
    else if secs % 60 == 0 { format!("{}m", secs / 60) }
    else { format!("{secs}s") }
}

fn trunc(s: &str, max: usize) -> String {
    if s.len() <= max {
        format!("{s:<max$}")
    } else {
        format!("{}…", &s[..max - 1])
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    let opts = match parse_args() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("error: {e}\n");
            print_help();
            std::process::exit(1);
        }
    };

    if let Err(e) = run_query(&opts) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
