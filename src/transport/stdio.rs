use super::Transport;
use crate::gateway::McpGateway;
use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::Command,
    sync::Mutex,
};

pub struct StdioTransport {
    server_cmd: Vec<String>,
}

impl StdioTransport {
    pub fn new(server_cmd: Vec<String>) -> Self {
        Self { server_cmd }
    }
}

#[async_trait]
impl Transport for StdioTransport {
    async fn serve(&self, gateway: Arc<McpGateway>) -> anyhow::Result<()> {
        let (cmd, args) = self
            .server_cmd
            .split_first()
            .ok_or_else(|| anyhow::anyhow!("empty server_cmd"))?;

        let mut child = Command::new(cmd)
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()?;

        // Wrapped in Arc<Mutex> to allow explicit close after the main loop
        let child_stdin = Arc::new(Mutex::new(
            child.stdin.take().ok_or_else(|| anyhow::anyhow!("child stdin unavailable"))?,
        ));
        let child_stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("child stdout unavailable"))?;

        let our_stdout = Arc::new(Mutex::new(tokio::io::stdout()));
        let agent_id: Arc<Mutex<String>> = Arc::new(Mutex::new("unknown".to_string()));

        // Task A: child stdout → our stdout
        // Intercepts tools/list responses to filter tools per agent.
        let stdout_a = our_stdout.clone();
        let agent_id_a = agent_id.clone();
        let gateway_a = gateway.clone();
        let passthrough = tokio::spawn(async move {
            let mut lines = BufReader::new(child_stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let output = filter_if_tools_list(&gateway_a, &agent_id_a, &line).await;
                write_line(&stdout_a, &output).await;
            }
        });

        // Task B (main loop): our stdin → gateway intercept → child stdin or our stdout
        let mut lines = BufReader::new(tokio::io::stdin()).lines();

        while let Ok(Some(line)) = lines.next_line().await {
            let line = line.trim().to_string();
            if line.is_empty() {
                continue;
            }

            let msg: Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("[GATEWAY] invalid message ignored: {e}");
                    continue;
                }
            };

            if msg["method"].as_str() == Some("initialize") {
                if let Some(name) = msg["params"]["clientInfo"]["name"].as_str() {
                    eprintln!("[GATEWAY] agent identified: {name}");
                    *agent_id.lock().await = name.to_string();
                }
            }

            let current_agent = agent_id.lock().await.clone();

            match gateway.intercept(&current_agent, &msg).await {
                Some(block_response) => {
                    let json_str = serde_json::to_string(&block_response).unwrap_or_default();
                    write_line(&our_stdout, &json_str).await;
                }
                None => {
                    let mut child_in = child_stdin.lock().await;
                    let _ = child_in.write_all(line.as_bytes()).await;
                    let _ = child_in.write_all(b"\n").await;
                    let _ = child_in.flush().await;
                }
            }
        }

        // Close child stdin — signals EOF so the child knows to finish.
        // The passthrough task will keep reading until the child closes its stdout.
        drop(child_stdin);

        // Wait for passthrough to drain all pending responses before exiting.
        let _ = passthrough.await;
        child.wait().await?;
        Ok(())
    }
}

async fn filter_if_tools_list(
    gateway: &McpGateway,
    agent_id: &Mutex<String>,
    line: &str,
) -> String {
    let Ok(msg) = serde_json::from_str::<Value>(line) else {
        return line.to_string();
    };
    if msg["result"]["tools"].is_array() {
        let agent = agent_id.lock().await.clone();
        let filtered = gateway.filter_tools_response(&agent, msg);
        return serde_json::to_string(&filtered).unwrap_or_else(|_| line.to_string());
    }
    line.to_string()
}

async fn write_line(stdout: &Arc<Mutex<tokio::io::Stdout>>, line: &str) {
    let mut out = stdout.lock().await;
    let _ = out.write_all(line.as_bytes()).await;
    let _ = out.write_all(b"\n").await;
    let _ = out.flush().await;
}
