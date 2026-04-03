use std::sync::mpsc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde_json::Value;

// ---------------------------------------------------------------------------
// AI mode / state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AiMode {
    /// Full autonomy  - all tools, no confirmation.
    Auto,
    /// All tools, but execution tools require y/n confirmation.
    Ask,
    /// Read-only tools only, execution tools rejected.
    Explain,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AiState {
    Idle,
    Running,
    WaitingApproval,
}

// ---------------------------------------------------------------------------
// Channel types
// ---------------------------------------------------------------------------

/// Requests from main thread → AI thread.
#[allow(dead_code)]
pub enum AiRequest {
    Start {
        mode: AiMode,
        prompt: String,
        snapshot: StateSnapshot,
    },
    ToolResult {
        tool_use_id: String,
        result: String,
    },
    UserApproval(bool),
    Cancel,
}

/// Events from AI thread → main thread.
#[allow(dead_code)]
pub enum AiEvent {
    ToolCall {
        tool_use_id: String,
        name: String,
        input: Value,
    },
    TextDelta(String),
    AnalysisBlock(String),
    ConfirmRequest {
        tool_use_id: String,
        description: String,
    },
    Done,
    Error(String),
}

// ---------------------------------------------------------------------------
// State snapshot (passed to AI thread for context)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct StateSnapshot {
    pub app_state: String,
    pub current_class: Option<String>,
    pub current_method: Option<String>,
    pub current_line: Option<i32>,
    pub current_thread: Option<String>,
    pub bp_count: usize,
    pub thread_count: usize,
    pub recording_active: bool,
    pub call_record_count: usize,
    pub dex_loaded: bool,
    pub dex_string_count: usize,
}

// ---------------------------------------------------------------------------
// AI output line (for rendering in AI tab)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AiLineKind {
    Text,
    Header,
    ToolCall,
    ToolResult,
    Error,
}

#[derive(Debug, Clone)]
pub struct AiOutputLine {
    pub kind: AiLineKind,
    pub text: String,
}

// ---------------------------------------------------------------------------
// LLM client trait
// ---------------------------------------------------------------------------

pub enum TurnResult {
    /// Model wants to call tools. Carries the number of tool_use blocks returned.
    ToolUse(usize),
    /// Model produced only text (end_turn).
    EndTurn,
}

#[allow(dead_code)]
pub trait LlmClient: Send {
    /// Send a conversation turn to the LLM. Streams TextDelta events via `delta_tx`.
    /// Returns whether the model wants to call tools or is done.
    fn send_turn(
        &mut self,
        cancel: &AtomicBool,
        delta_tx: &mpsc::Sender<AiEvent>,
    ) -> Result<TurnResult, String>;

    /// Add a tool result to the conversation history.
    fn add_tool_result(&mut self, tool_use_id: &str, result: &str);

    /// Add assistant text to the conversation history.
    fn add_assistant_text(&mut self, text: &str);

    /// Add an assistant tool_use block to the conversation history.
    fn add_assistant_tool_use(&mut self, tool_use_id: &str, name: &str, input: &Value);

    /// Add a user message to the conversation history.
    fn add_user_message(&mut self, text: &str);
}

// ---------------------------------------------------------------------------
// AI thread spawn + agentic loop
// ---------------------------------------------------------------------------

pub fn spawn_ai_thread(
    config: crate::config::AiConfig,
    _mode: AiMode,
    req_rx: mpsc::Receiver<AiRequest>,
    evt_tx: mpsc::Sender<AiEvent>,
    cancel: std::sync::Arc<AtomicBool>,
) {
    std::thread::spawn(move || {
        // Wait for Start request
        let (mode, prompt, snapshot) = match req_rx.recv() {
            Ok(AiRequest::Start { mode, prompt, snapshot }) => (mode, prompt, snapshot),
            _ => return,
        };

        // Create LLM client based on config
        let mut client: Box<dyn LlmClient> = if config.backend == "ollama" {
            Box::new(crate::ai_ollama::OllamaClient::new(
                config.ollama_url.clone(),
                config.ollama_model.clone(),
                mode,
                &prompt,
                &snapshot,
            ))
        } else {
            // Claude backend (default)
            let api_key = match std::env::var("ANTHROPIC_API_KEY") {
                Ok(key) if !key.is_empty() => key,
                _ => {
                    let _ = evt_tx.send(AiEvent::Error(
                        "ANTHROPIC_API_KEY not set. Set it in your environment to use Claude.".into()
                    ));
                    return;
                }
            };
            Box::new(crate::ai_claude::ClaudeClient::new(
                api_key,
                config.claude_model.clone(),
                mode,
                &prompt,
                &snapshot,
            ))
        };

        // Run agentic loop
        run_conversation(&mut *client, mode, &req_rx, &evt_tx, &cancel, config.max_turns, config.turn_delay_ms);
    });
}

fn run_conversation(
    client: &mut dyn LlmClient,
    _mode: AiMode,
    req_rx: &mpsc::Receiver<AiRequest>,
    evt_tx: &mpsc::Sender<AiEvent>,
    cancel: &std::sync::Arc<AtomicBool>,
    max_turns: usize,
    turn_delay_ms: u64,
) {
    let mut nudge_count = 0u32;
    const MAX_NUDGES: u32 = 3;

    for turn in 0..max_turns {
        if cancel.load(Ordering::Relaxed) {
            let _ = evt_tx.send(AiEvent::Error("Cancelled".into()));
            return;
        }

        // Optional inter-turn delay to avoid rate limits (skip on first turn)
        if turn > 0 && turn_delay_ms > 0 {
            std::thread::sleep(Duration::from_millis(turn_delay_ms));
        }

        // Send a turn to the LLM
        let result = client.send_turn(cancel, evt_tx);

        match result {
            Ok(TurnResult::EndTurn) => {
                // If this is an early turn and we haven't nudged too many times,
                // prompt the model to actually use tools instead of just describing.
                if turn < 4 && nudge_count < MAX_NUDGES {
                    nudge_count += 1;
                    let _ = evt_tx.send(AiEvent::TextDelta(
                        "\n[Continuing analysis...]\n".into()
                    ));
                    // Add a user message nudging the model to use tools
                    client.add_user_message(
                        "Don't stop yet. Continue your analysis  - use the tools \
                         (strings, cls, xref, get_state, get_calls, etc.) to gather \
                         real data from the debugger. Execute the tools now.");
                    continue;
                }
                let _ = evt_tx.send(AiEvent::Done);
                return;
            }
            Ok(TurnResult::ToolUse(n)) => {
                // Wait for exactly n tool results from the main thread.
                // All results must arrive before the next send_turn so that
                // every tool_use block has a corresponding tool_result.
                let mut received = 0;
                while received < n {
                    if cancel.load(Ordering::Relaxed) {
                        let _ = evt_tx.send(AiEvent::Error("Cancelled".into()));
                        return;
                    }

                    match req_rx.recv_timeout(Duration::from_millis(100)) {
                        Ok(AiRequest::ToolResult { tool_use_id, result }) => {
                            client.add_tool_result(&tool_use_id, &result);
                            received += 1;
                        }
                        Ok(AiRequest::Cancel) => {
                            let _ = evt_tx.send(AiEvent::Error("Cancelled".into()));
                            return;
                        }
                        Ok(AiRequest::UserApproval(_)) | Ok(AiRequest::Start { .. }) => {}
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) => {
                            return;
                        }
                    }
                }
            }
            Err(e) => {
                let _ = evt_tx.send(AiEvent::Error(e));
                return;
            }
        }

        if turn + 1 >= max_turns {
            let _ = evt_tx.send(AiEvent::TextDelta(
                "\n\n[Reached maximum turn limit]\n".into()
            ));
            let _ = evt_tx.send(AiEvent::Done);
            return;
        }
    }

    let _ = evt_tx.send(AiEvent::Done);
}
