use std::io::BufRead;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;

use serde_json::{json, Value};

use crate::ai::{AiEvent, AiMode, LlmClient, StateSnapshot, TurnResult};
use crate::ai_tools;

pub struct ClaudeClient {
    api_key: String,
    model: String,
    #[allow(dead_code)]
    mode: AiMode,
    messages: Vec<Value>,
    system_prompt: String,
    tools_json: Vec<Value>,
}

impl ClaudeClient {
    pub fn new(
        api_key: String,
        model: String,
        mode: AiMode,
        prompt: &str,
        snapshot: &StateSnapshot,
    ) -> Self {
        let system_prompt = build_system_prompt(mode, snapshot);
        let tools_json = ai_tools::tools_to_claude_json(mode);

        let messages = vec![json!({
            "role": "user",
            "content": prompt,
        })];

        Self {
            api_key,
            model,
            mode,
            messages,
            system_prompt,
            tools_json,
        }
    }
}

impl LlmClient for ClaudeClient {
    fn send_turn(
        &mut self,
        cancel: &AtomicBool,
        delta_tx: &mpsc::Sender<AiEvent>,
    ) -> Result<TurnResult, String> {
        let body = json!({
            "model": self.model,
            "max_tokens": 8192,
            "system": self.system_prompt,
            "messages": self.messages,
            "tools": self.tools_json,
            "stream": true,
        });

        let client = reqwest::blocking::Client::new();
        let resp = client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .map_err(|e| format!("HTTP request failed: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().unwrap_or_default();
            return Err(format!("Claude API error {}: {}", status, body));
        }

        // Parse SSE stream manually
        let reader = std::io::BufReader::new(resp);
        let mut current_text = String::new();
        let mut tool_calls: Vec<(String, String, String)> = Vec::new(); // (id, name, json_input)
        let mut current_tool_id = String::new();
        let mut current_tool_name = String::new();
        let mut current_tool_input = String::new();
        let mut in_tool_use = false;
        let mut stop_reason = String::new();

        for line in reader.lines() {
            if cancel.load(Ordering::Relaxed) {
                return Err("Cancelled".into());
            }

            let line = line.map_err(|e| format!("Stream read error: {}", e))?;

            // SSE format: "data: {...}" or empty lines
            if line.is_empty() || line.starts_with(':') {
                continue;
            }

            let data = if let Some(d) = line.strip_prefix("data: ") {
                d
            } else {
                continue;
            };

            if data == "[DONE]" {
                break;
            }

            let event: Value = match serde_json::from_str(data) {
                Ok(v) => v,
                Err(_) => continue,
            };

            let event_type = event.get("type").and_then(|v| v.as_str()).unwrap_or("");

            match event_type {
                "content_block_start" => {
                    if let Some(cb) = event.get("content_block") {
                        let cb_type = cb.get("type").and_then(|v| v.as_str()).unwrap_or("");
                        if cb_type == "tool_use" {
                            in_tool_use = true;
                            current_tool_id = cb.get("id")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            current_tool_name = cb.get("name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            current_tool_input.clear();
                        }
                    }
                }
                "content_block_delta" => {
                    if let Some(delta) = event.get("delta") {
                        let delta_type = delta.get("type").and_then(|v| v.as_str()).unwrap_or("");
                        match delta_type {
                            "text_delta" => {
                                if let Some(text) = delta.get("text").and_then(|v| v.as_str()) {
                                    current_text.push_str(text);
                                    let _ = delta_tx.send(AiEvent::TextDelta(text.to_string()));
                                }
                            }
                            "input_json_delta" => {
                                if let Some(json_str) = delta.get("partial_json").and_then(|v| v.as_str()) {
                                    current_tool_input.push_str(json_str);
                                }
                            }
                            _ => {}
                        }
                    }
                }
                "content_block_stop" => {
                    if in_tool_use {
                        tool_calls.push((
                            current_tool_id.clone(),
                            current_tool_name.clone(),
                            current_tool_input.clone(),
                        ));
                        in_tool_use = false;
                    }
                }
                "message_delta" => {
                    if let Some(delta) = event.get("delta") {
                        if let Some(sr) = delta.get("stop_reason").and_then(|v| v.as_str()) {
                            stop_reason = sr.to_string();
                        }
                    }
                }
                _ => {}
            }
        }

        // Build the assistant message for conversation history
        let mut content_blocks: Vec<Value> = Vec::new();

        if !current_text.is_empty() {
            content_blocks.push(json!({
                "type": "text",
                "text": current_text,
            }));
        }

        for (id, name, input_str) in &tool_calls {
            let input: Value = serde_json::from_str(input_str).unwrap_or(json!({}));
            content_blocks.push(json!({
                "type": "tool_use",
                "id": id,
                "name": name,
                "input": input,
            }));
        }

        if !content_blocks.is_empty() {
            self.messages.push(json!({
                "role": "assistant",
                "content": content_blocks,
            }));
        }

        // Send tool call events for each tool use
        for (id, name, input_str) in &tool_calls {
            let input: Value = serde_json::from_str(input_str).unwrap_or(json!({}));
            let _ = delta_tx.send(AiEvent::ToolCall {
                tool_use_id: id.clone(),
                name: name.clone(),
                input,
            });
        }

        if stop_reason == "tool_use" || !tool_calls.is_empty() {
            Ok(TurnResult::ToolUse(tool_calls.len()))
        } else {
            Ok(TurnResult::EndTurn)
        }
    }

    fn add_tool_result(&mut self, tool_use_id: &str, result: &str) {
        let new_block = json!({
            "type": "tool_result",
            "tool_use_id": tool_use_id,
            "content": result,
        });
        // Claude API requires all tool_results for a turn in one user message.
        // If the last message is already a user tool_result batch, append to it.
        if let Some(last) = self.messages.last_mut() {
            if last.get("role").and_then(|v| v.as_str()) == Some("user") {
                if let Some(content) = last.get_mut("content").and_then(|c| c.as_array_mut()) {
                    if content.iter().any(|b| {
                        b.get("type").and_then(|t| t.as_str()) == Some("tool_result")
                    }) {
                        content.push(new_block);
                        return;
                    }
                }
            }
        }
        self.messages.push(json!({
            "role": "user",
            "content": [new_block],
        }));
    }

    fn add_assistant_text(&mut self, text: &str) {
        self.messages.push(json!({
            "role": "assistant",
            "content": text,
        }));
    }

    fn add_assistant_tool_use(&mut self, tool_use_id: &str, name: &str, input: &Value) {
        self.messages.push(json!({
            "role": "assistant",
            "content": [{
                "type": "tool_use",
                "id": tool_use_id,
                "name": name,
                "input": input,
            }],
        }));
    }

    fn add_user_message(&mut self, text: &str) {
        self.messages.push(json!({
            "role": "user",
            "content": text,
        }));
    }
}

/// Build system prompt text (also used by OllamaClient).
pub fn build_system_prompt_text(mode: AiMode, snapshot: &StateSnapshot) -> String {
    build_system_prompt(mode, snapshot)
}

fn build_system_prompt(mode: AiMode, snapshot: &StateSnapshot) -> String {
    let mode_desc = match mode {
        AiMode::Auto => "You have full access to all tools. Execute actions freely without confirmation.",
        AiMode::Ask => "You have access to all tools. Read-only tools execute immediately. Execution tools (breakpoints, stepping, recording) require user confirmation before executing.",
        AiMode::Explain => "You have read-only access. You can inspect state, search strings, view bytecodes, but cannot set breakpoints, step, or modify execution.",
    };

    let mut prompt = format!(
r#"You are an Android malware analysis AI agent integrated into the dexbgd debugger.
You analyze Android apps by using the debugger's tools to inspect loaded classes, search DEX strings, set breakpoints, record API calls, and examine runtime state.

## Mode
{}

## Current State
- Connection: {}
- Location: {}
- Recording: {}
- Breakpoints: {}
- Threads: {}
- DEX loaded: {}
- DEX strings: {}
- Call records: {}

## Analysis Guidelines
1. Start by understanding what's loaded: use get_state, then search strings for suspicious patterns
2. Look for hardcoded URLs, API keys, passwords, encryption keys
3. Use xref to find which code references suspicious strings
4. Set breakpoints on crypto/network/exec APIs to catch runtime behavior
5. Record API calls to build a behavioral profile
6. Analyze call sequences for malicious patterns (C2 communication, data exfiltration, privilege escalation)
7. Use xref to find anti-tamper strings ("su", "test-keys", "Superuser", "debuggable"), use dis to confirm the method, then anti to silently bypass. Prefer anti over bp+force_return for persistent silent interception.

## Output Format
Structure your analysis with markdown headers (## Section).
Be concise but thorough. Focus on security-relevant findings.
When you find suspicious behavior, explain the risk clearly."#,
        mode_desc,
        snapshot.app_state,
        format_location(snapshot),
        if snapshot.recording_active { "active" } else { "inactive" },
        snapshot.bp_count,
        snapshot.thread_count,
        if snapshot.dex_loaded { "yes" } else { "no" },
        snapshot.dex_string_count,
        snapshot.call_record_count,
    );

    if snapshot.call_record_count > 0 {
        prompt.push_str("\n\nCall records are available. Use get_calls to review recorded API call history.");
    }

    prompt
}

fn format_location(snapshot: &StateSnapshot) -> String {
    match (&snapshot.current_class, &snapshot.current_method) {
        (Some(cls), Some(meth)) => {
            let short = crate::commands::short_class(cls);
            if let Some(line) = snapshot.current_line {
                if line >= 0 {
                    return format!("{}.{}:{}", short, meth, line);
                }
            }
            format!("{}.{}", short, meth)
        }
        _ => "(not suspended)".to_string(),
    }
}
