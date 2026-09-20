//! Minimal MCP stdio server used only for adapter integration tests.
//!
//! This intentionally does not depend on the adapter's production code paths; it speaks JSON-RPC
//! over stdio directly (one JSON message per line).

use serde_json::json;
use std::io::{BufRead as _, Write};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> anyhow::Result<()> {
    let mut state = ServerState::new();
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();

    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if let Some(resp) = handle_line(&mut state, &line) {
            write_json_line(&mut stdout, &resp)?;
        }
    }

    Ok(())
}

struct ServerState {
    instance_id: String,
    pid: u32,
    call_count: u64,
    roots_changes: u64,
}

impl ServerState {
    fn new() -> Self {
        let pid = std::process::id();
        let started_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let instance_id = format!("{pid}-{started_ns}");
        Self {
            instance_id,
            pid,
            call_count: 0,
            roots_changes: 0,
        }
    }
}

fn handle_line(state: &mut ServerState, line: &str) -> Option<serde_json::Value> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

    let msg: serde_json::Value = serde_json::from_str(line).ok()?;
    handle_message(state, &msg)
}

fn handle_message(state: &mut ServerState, msg: &serde_json::Value) -> Option<serde_json::Value> {
    let method = msg.get("method").and_then(serde_json::Value::as_str)?;

    if method == "notifications/roots/list_changed" {
        state.roots_changes += 1;
        return None;
    }

    // Ignore notifications (no `id`).
    let id = msg.get("id")?.clone();

    match method {
        "initialize" => {
            let result = initialize_result(msg);
            Some(jsonrpc_ok(&id, &result))
        }
        "resources/list" => {
            let result = json!({ "resources": [] });
            Some(jsonrpc_ok(&id, &result))
        }
        "resources/templates/list" => Some(jsonrpc_ok(
            &id,
            &json!({"resourceTemplates":[{
                "uriTemplate":"test:///notes/{id}","name":"note","mimeType":"text/plain"
            }]}),
        )),
        "resources/read" => Some(jsonrpc_ok(
            &id,
            &json!({"contents":[{
                "uri":msg["params"]["uri"],"mimeType":"text/plain","text":"template resource"
            }]}),
        )),
        "prompts/list" => {
            let result = json!({ "prompts": [] });
            Some(jsonrpc_ok(&id, &result))
        }
        "tools/list" => {
            let result = tools_list_result();
            Some(jsonrpc_ok(&id, &result))
        }
        "tools/call" => match tools_call_result(state, msg) {
            Ok(result) => Some(jsonrpc_ok(&id, &result)),
            Err(error) => Some(jsonrpc_err(&id, &error)),
        },
        _ => {
            let error = json!({ "code": -32601, "message": "method not found" });
            Some(jsonrpc_err(&id, &error))
        }
    }
}

fn initialize_result(msg: &serde_json::Value) -> serde_json::Value {
    let protocol_version = msg
        .get("params")
        .and_then(|p| p.get("protocolVersion"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("2024-11-05")
        .to_string();

    json!({
        "protocolVersion": protocol_version,
        "capabilities": { "tools": {} },
        "serverInfo": { "name": "adapter-stdio-test-server", "version": "0" }
    })
}

fn tools_list_result() -> serde_json::Value {
    json!({
        "tools": [{
            "name": "whoami",
            "description": "Return per-process instance info",
            "inputSchema": { "type": "object" }
        }]
    })
}

fn tools_call_result(
    state: &mut ServerState,
    msg: &serde_json::Value,
) -> Result<serde_json::Value, serde_json::Value> {
    let name = msg
        .get("params")
        .and_then(|p| p.get("name"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");

    if name != "whoami" {
        return Err(json!({ "code": -32601, "message": "unknown tool" }));
    }

    state.call_count += 1;
    let body = json!({
        "body": {
            "instanceId": state.instance_id,
            "pid": state.pid,
            "callCount": state.call_count,
            "rootsChanges": state.roots_changes
        }
    });

    Ok(json!({
        "content": [{ "type": "text", "text": body.to_string() }]
    }))
}

fn jsonrpc_ok(id: &serde_json::Value, result: &serde_json::Value) -> serde_json::Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn jsonrpc_err(id: &serde_json::Value, error: &serde_json::Value) -> serde_json::Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": error })
}

fn write_json_line(stdout: &mut dyn Write, v: &serde_json::Value) -> anyhow::Result<()> {
    writeln!(stdout, "{}", serde_json::to_string(v)?)?;
    stdout.flush()?;
    Ok(())
}
