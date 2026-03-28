use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use serde_json::{json, Value};
use std::sync::Arc;

// Estado compartilhado — por enquanto só guarda o nome do server
struct AppState {
    name: String,
}

#[tokio::main]
async fn main() {
    let state = Arc::new(AppState {
        name: "dummy-server".to_string(),
    });

    let app = Router::new()
        .route("/mcp", post(handle_mcp))
        .with_state(state);

    let addr = "0.0.0.0:3000";
    println!("MCP dummy server rodando em http://{addr}");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn handle_mcp(
    State(state): State<Arc<AppState>>,
    Json(msg): Json<Value>,
) -> impl IntoResponse {
    let method = msg["method"].as_str().unwrap_or("");
    let id = &msg["id"];

    match method {
        // ── Handshake ────────────────────────────────────────────────────
        "initialize" => {
            println!("[initialize] client: {}", msg["params"]["clientInfo"]);
            Json(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {
                        "tools": { "listChanged": false }
                    },
                    "serverInfo": {
                        "name": state.name,
                        "version": "0.1.0"
                    }
                }
            }))
            .into_response()
        }

        // Notification — sem resposta (202)
        "notifications/initialized" => {
            println!("[notifications/initialized] handshake completo");
            StatusCode::ACCEPTED.into_response()
        }

        // ── Tools ────────────────────────────────────────────────────────
        "tools/list" => {
            println!("[tools/list]");
            Json(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "tools": [{
                        "name": "echo",
                        "description": "Retorna o texto enviado — tool de teste",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "text": {
                                    "type": "string",
                                    "description": "Texto a ser ecoado"
                                }
                            },
                            "required": ["text"]
                        }
                    }]
                }
            }))
            .into_response()
        }

        "tools/call" => {
            let tool_name = msg["params"]["name"].as_str().unwrap_or("");
            let args = &msg["params"]["arguments"];
            println!("[tools/call] tool={tool_name} args={args}");

            match tool_name {
                "echo" => {
                    let text = args["text"].as_str().unwrap_or("(vazio)");
                    Json(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "content": [{
                                "type": "text",
                                "text": format!("echo: {text}")
                            }]
                        }
                    }))
                    .into_response()
                }
                _ => Json(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": -32601, "message": format!("tool '{tool_name}' não existe") }
                }))
                .into_response(),
            }
        }

        // ── Fallback ─────────────────────────────────────────────────────
        other => {
            println!("[desconhecido] method={other}");
            Json(json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": -32601, "message": format!("método '{other}' não implementado") }
            }))
            .into_response()
        }
    }
}
