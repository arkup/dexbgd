use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::ai::{AiEvent, AiMode, LlmClient, StateSnapshot, TurnResult};
use crate::ai_tools;

pub struct OllamaClient {
    url: String,
    model: String,
    #[allow(dead_code)]
    mode: AiMode,
    messages: Vec<Value>,
    tools_json: Vec<Value>,
    tool_id_counter: usize,
    /// After first empty-with-tools response, disable native tool calling.
    tools_disabled: bool,
}

impl OllamaClient {
    pub fn new(
        url: String,
        model: String,
        mode: AiMode,
        prompt: &str,
        snapshot: &StateSnapshot,
    ) -> Self {
        let system_prompt = crate::ai_claude::build_system_prompt_text(mode, snapshot);
        let tools_json = ai_tools::tools_to_ollama_json(mode);

        let messages = vec![
            json!({ "role": "system", "content": system_prompt }),
            json!({ "role": "user", "content": prompt }),
        ];

        Self {
            url,
            model,
            mode,
            messages,
            tools_json,
            tool_id_counter: 0,
            tools_disabled: false,
        }
    }

    fn next_tool_id(&mut self) -> String {
        let id = format!("ollama_tc_{}", self.tool_id_counter);
        self.tool_id_counter += 1;
        id
    }

    /// Send HTTP request in a helper thread, poll for result with cancel support.
    fn http_request(
        &self,
        body_json: &Value,
        cancel: &AtomicBool,
        delta_tx: &mpsc::Sender<AiEvent>,
    ) -> Result<(reqwest::StatusCode, String), String> {
        let url = format!("{}/api/chat", self.url);
        let body_str = body_json.to_string();
        let (http_tx, http_rx) = mpsc::channel();

        let start = Instant::now();

        std::thread::spawn(move || {
            let result = (|| {
                let client = reqwest::blocking::Client::builder()
                    .connect_timeout(Duration::from_secs(10))
                    .timeout(Duration::from_secs(300))
                    .build()
                    .map_err(|e| format!("HTTP client error: {}", e))?;
                let resp = client
                    .post(&url)
                    .header("content-type", "application/json")
                    .body(body_str)
                    .send()
                    .map_err(|e| format!("Ollama request failed: {}  - is Ollama running?", e))?;
                let status = resp.status();
                let text = resp
                    .text()
                    .map_err(|e| format!("Failed to read response: {}", e))?;
                Ok((status, text))
            })();
            let _ = http_tx.send(result);
        });

        // Poll for result, checking cancel every 500ms. Show elapsed time.
        let mut last_tick = 0u64;
        loop {
            if cancel.load(Ordering::Relaxed) {
                return Err("Cancelled".into());
            }
            match http_rx.recv_timeout(Duration::from_millis(500)) {
                Ok(Ok(result)) => {
                    let elapsed = start.elapsed().as_secs();
                    let _ = delta_tx.send(AiEvent::TextDelta(format!(
                        " done ({:.0}s)\n",
                        elapsed
                    )));
                    return Ok(result);
                }
                Ok(Err(e)) => return Err(e),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    let secs = start.elapsed().as_secs();
                    if secs > last_tick && secs % 5 == 0 {
                        last_tick = secs;
                        let _ = delta_tx.send(AiEvent::TextDelta(format!(
                            " {}s...", secs
                        )));
                    }
                    continue;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err("HTTP request thread crashed".into());
                }
            }
        }
    }

    /// Parse a single JSON response (non-streaming format).
    fn parse_response(
        &mut self,
        body: &str,
        delta_tx: &mpsc::Sender<AiEvent>,
    ) -> Option<(String, Vec<(String, String, Value)>)> {
        let resp: Value = serde_json::from_str(body).ok()?;

        if let Some(err) = resp.get("error").and_then(|v| v.as_str()) {
            let _ = delta_tx.send(AiEvent::TextDelta(format!(
                "\n[Ollama error: {}]\n",
                err
            )));
            return Some((String::new(), Vec::new()));
        }

        let message = resp.get("message")?;
        let mut text = String::new();
        let mut tool_calls = Vec::new();

        if let Some(content) = message.get("content").and_then(|v| v.as_str()) {
            if !content.is_empty() {
                text = content.to_string();
                let _ = delta_tx.send(AiEvent::TextDelta(content.to_string()));
            }
        }

        if let Some(tcs) = message.get("tool_calls").and_then(|v| v.as_array()) {
            for tc in tcs {
                if let Some(func) = tc.get("function") {
                    let name = func
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let args = func.get("arguments").cloned().unwrap_or(json!({}));
                    let id = self.next_tool_id();
                    tool_calls.push((id, name, args));
                }
            }
        }

        Some((text, tool_calls))
    }

    /// Parse NDJSON streaming response (one JSON object per line).
    fn parse_ndjson(
        &mut self,
        body: &str,
        cancel: &AtomicBool,
        delta_tx: &mpsc::Sender<AiEvent>,
    ) -> Result<(String, Vec<(String, String, Value)>), String> {
        let mut current_text = String::new();
        let mut tool_calls: Vec<(String, String, Value)> = Vec::new();

        for line in body.lines() {
            if cancel.load(Ordering::Relaxed) {
                return Err("Cancelled".into());
            }
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let event: Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if let Some(err) = event.get("error").and_then(|v| v.as_str()) {
                return Err(format!("Ollama error: {}", err));
            }
            if let Some(message) = event.get("message") {
                if let Some(content) = message.get("content").and_then(|v| v.as_str()) {
                    if !content.is_empty() {
                        current_text.push_str(content);
                        let _ = delta_tx.send(AiEvent::TextDelta(content.to_string()));
                    }
                }
                if let Some(tcs) = message.get("tool_calls").and_then(|v| v.as_array()) {
                    for tc in tcs {
                        if let Some(func) = tc.get("function") {
                            let name = func
                                .get("name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let args =
                                func.get("arguments").cloned().unwrap_or(json!({}));
                            let id = self.next_tool_id();
                            tool_calls.push((id, name, args));
                        }
                    }
                }
            }
        }
        Ok((current_text, tool_calls))
    }

    /// Check if Ollama is reachable and the model exists.
    fn preflight_check(&self) -> Result<(), String> {
        let client = reqwest::blocking::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| format!("HTTP client error: {}", e))?;

        let version_resp = client
            .get(format!("{}/api/version", self.url))
            .send()
            .map_err(|e| {
                format!(
                    "Cannot reach Ollama at {}  - is it running? ({})\n\
                     Start with: ollama serve",
                    self.url, e
                )
            })?;

        if !version_resp.status().is_success() {
            return Err(format!(
                "Ollama at {} returned status {}  - is it running correctly?",
                self.url,
                version_resp.status()
            ));
        }

        let tags_resp = client
            .get(format!("{}/api/tags", self.url))
            .send()
            .map_err(|e| format!("Failed to list Ollama models: {}", e))?;

        if tags_resp.status().is_success() {
            let tags_text = tags_resp.text().unwrap_or_default();
            if let Ok(body) = serde_json::from_str::<Value>(&tags_text) {
                if let Some(models) = body.get("models").and_then(|v| v.as_array()) {
                    let model_base =
                        self.model.split(':').next().unwrap_or(&self.model);
                    let found = models.iter().any(|m: &Value| {
                        m.get("name")
                            .and_then(|v| v.as_str())
                            .map(|name| {
                                name == self.model
                                    || name.starts_with(&format!("{}:", model_base))
                            })
                            .unwrap_or(false)
                    });
                    if !found {
                        let available: Vec<&str> = models
                            .iter()
                            .filter_map(|m: &Value| {
                                m.get("name").and_then(|v| v.as_str())
                            })
                            .collect();
                        return Err(format!(
                            "Model '{}' not found in Ollama. Available: {}\n\
                             Pull with: ollama pull {}",
                            self.model,
                            if available.is_empty() {
                                "(none)".to_string()
                            } else {
                                available.join(", ")
                            },
                            self.model
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    /// Build tool-description text to embed in system prompt when native tools are disabled.
    fn tool_hint_text(&self) -> String {
        let tools = ai_tools::all_tools();
        let tool_lines: Vec<String> = tools
            .iter()
            .filter(|t| self.mode != AiMode::Explain || !t.is_execution)
            .map(|t| format!("- `{}`: {}", t.name, t.description))
            .collect();
        format!(
            "\n\n## Available debugger tools\n\
             You have access to these tools. Call them by name to inspect the app.\n\
             {}\n",
            tool_lines.join("\n")
        )
    }
}

impl LlmClient for OllamaClient {
    fn send_turn(
        &mut self,
        cancel: &AtomicBool,
        delta_tx: &mpsc::Sender<AiEvent>,
    ) -> Result<TurnResult, String> {
        // Preflight check on first turn only
        if self.messages.len() <= 2 {
            self.preflight_check()?;
        }

        // Build request  - with or without tools
        let use_tools = !self.tools_disabled && !self.tools_json.is_empty();

        let mut body = json!({
            "model": self.model,
            "messages": self.messages,
            "stream": false,
        });
        if use_tools {
            body["tools"] = json!(self.tools_json);
        }

        let _ = delta_tx.send(AiEvent::TextDelta(format!(
            "[Waiting for Ollama ({}){}...] ",
            self.model,
            if use_tools { " +tools" } else { "" },
        )));

        let (status, raw_body) = self.http_request(&body, cancel, delta_tx)?;

        if !status.is_success() {
            return Err(format!("Ollama API error {}: {}", status, raw_body));
        }

        if raw_body.is_empty() {
            return Err("Ollama returned empty response  - is the model loaded?".into());
        }

        // Parse response
        let parsed = self.parse_response(&raw_body, delta_tx);
        let (current_text, tool_calls) = match parsed {
            Some(result) => result,
            None => self.parse_ndjson(&raw_body, cancel, delta_tx)?,
        };

        // If tools were sent but got empty response, retry WITHOUT tools.
        // Many models don't support native tool calling and return empty.
        if current_text.is_empty() && tool_calls.is_empty() && use_tools {
            let _ = delta_tx.send(AiEvent::TextDelta(
                "\n[Model returned empty with tools  - retrying without tool calling...]\n"
                    .into(),
            ));

            self.tools_disabled = true;

            // Add tool hints to system prompt so model knows what's available
            let hint = self.tool_hint_text();
            if let Some(sys_msg) = self.messages.first_mut() {
                if let Some(content) = sys_msg.get("content").and_then(|v| v.as_str()) {
                    let enhanced = format!("{}{}", content, hint);
                    sys_msg["content"] = json!(enhanced);
                }
            }

            let body_no_tools = json!({
                "model": self.model,
                "messages": self.messages,
                "stream": false,
            });

            let _ = delta_tx.send(AiEvent::TextDelta(format!(
                "[Waiting for Ollama ({})...] ",
                self.model,
            )));

            let (status2, raw_body2) =
                self.http_request(&body_no_tools, cancel, delta_tx)?;

            if !status2.is_success() {
                return Err(format!(
                    "Ollama API error {}: {}",
                    status2, raw_body2
                ));
            }

            let parsed2 = self.parse_response(&raw_body2, delta_tx);
            let (text2, tc2) = match parsed2 {
                Some(result) => result,
                None => self.parse_ndjson(&raw_body2, cancel, delta_tx)?,
            };

            if text2.is_empty() && tc2.is_empty() {
                let preview = &raw_body2[..raw_body2.len().min(500)];
                let _ = delta_tx.send(AiEvent::TextDelta(format!(
                    "\n[Still empty. Raw ({} bytes): {}]\n",
                    raw_body2.len(),
                    preview
                )));
            }

            // Store assistant message
            if !text2.is_empty() {
                self.messages
                    .push(json!({ "role": "assistant", "content": text2 }));
            }

            return if !tc2.is_empty() {
                Ok(TurnResult::ToolUse(tc2.len()))
            } else {
                Ok(TurnResult::EndTurn)
            };
        }

        // If we got neither text nor tool calls (shouldn't happen after retry above)
        if current_text.is_empty() && tool_calls.is_empty() {
            let preview = &raw_body[..raw_body.len().min(500)];
            let _ = delta_tx.send(AiEvent::TextDelta(format!(
                "\n[No content. Raw ({} bytes): {}]\n",
                raw_body.len(),
                preview
            )));
            return Ok(TurnResult::EndTurn);
        }

        // Build assistant message for history
        let mut msg = json!({ "role": "assistant" });
        if !current_text.is_empty() {
            msg["content"] = json!(current_text);
        }
        if !tool_calls.is_empty() {
            let tc_json: Vec<Value> = tool_calls
                .iter()
                .map(|(_, name, args)| {
                    json!({
                        "function": {
                            "name": name,
                            "arguments": args,
                        }
                    })
                })
                .collect();
            msg["tool_calls"] = json!(tc_json);
        }
        self.messages.push(msg);

        // Send tool call events
        for (id, name, args) in &tool_calls {
            let _ = delta_tx.send(AiEvent::ToolCall {
                tool_use_id: id.clone(),
                name: name.clone(),
                input: args.clone(),
            });
        }

        if !tool_calls.is_empty() {
            Ok(TurnResult::ToolUse(tool_calls.len()))
        } else {
            Ok(TurnResult::EndTurn)
        }
    }

    fn add_tool_result(&mut self, _tool_use_id: &str, result: &str) {
        self.messages.push(json!({
            "role": "tool",
            "content": result,
        }));
    }

    fn add_assistant_text(&mut self, text: &str) {
        self.messages.push(json!({
            "role": "assistant",
            "content": text,
        }));
    }

    fn add_assistant_tool_use(
        &mut self,
        _tool_use_id: &str,
        name: &str,
        input: &Value,
    ) {
        self.messages.push(json!({
            "role": "assistant",
            "tool_calls": [{
                "function": {
                    "name": name,
                    "arguments": input,
                }
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
