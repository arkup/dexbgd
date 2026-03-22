use std::collections::{VecDeque, HashSet, HashMap};
use std::net::TcpStream;
use std::sync::mpsc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseEvent, MouseEventKind, MouseButton};

use crate::ai::{AiEvent, AiLineKind, AiMode, AiOutputLine, AiRequest, AiState};
use crate::commands::{self, short_class, display_class, modifiers_str, short_type};
use crate::condition::{self, BreakpointCondition, BreakpointAction, FORCE_RETURN_VOID};
use crate::config::Config;
use crate::connection;
use crate::debugger::BreakpointManager;
use crate::theme::Theme;
use crate::disassembler::{self, Instruction};
use crate::protocol::*;
use crate::tui::statusbar::{self, StatusBarAction};

// ---------------------------------------------------------------------------
// Clipboard helper  - platform-specific
// ---------------------------------------------------------------------------

fn copy_to_clipboard(text: &str) {
    #[cfg(target_os = "windows")]
    {
        use std::process::{Command, Stdio};
        use std::io::Write;
        if let Ok(mut child) = Command::new("clip")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(text.as_bytes());
            }
            let _ = child.wait();
        }
    }
    #[cfg(target_os = "macos")]
    {
        use std::process::{Command, Stdio};
        use std::io::Write;
        if let Ok(mut child) = Command::new("pbcopy")
            .stdin(Stdio::piped())
            .spawn()
        {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(text.as_bytes());
            }
            let _ = child.wait();
        }
    }
    #[cfg(target_os = "linux")]
    {
        use std::process::{Command, Stdio};
        use std::io::Write;
        // Try xclip first, then xsel
        let progs = ["xclip", "xsel"];
        for prog in &progs {
            if let Ok(mut child) = Command::new(prog)
                .args(["-selection", "clipboard"])
                .stdin(Stdio::piped())
                .spawn()
            {
                if let Some(mut stdin) = child.stdin.take() {
                    let _ = stdin.write_all(text.as_bytes());
                }
                let _ = child.wait();
                break;
            }
        }
    }
}

fn paste_from_clipboard() -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        let out = Command::new("powershell")
            .args(["-noprofile", "-command", "Get-Clipboard"])
            .output().ok()?;
        let s = String::from_utf8_lossy(&out.stdout).trim_end_matches(['\r', '\n']).to_string();
        return if s.is_empty() { None } else { Some(s) };
    }
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        let out = Command::new("pbpaste").output().ok()?;
        let s = String::from_utf8_lossy(&out.stdout).to_string();
        return if s.is_empty() { None } else { Some(s) };
    }
    #[cfg(target_os = "linux")]
    {
        use std::process::Command;
        for prog in &[["xclip", "-selection", "clipboard", "-o"], ["xsel", "--clipboard", "--output", ""]] {
            if let Ok(out) = Command::new(prog[0]).args(&prog[1..]).output() {
                let s = String::from_utf8_lossy(&out.stdout).to_string();
                if !s.is_empty() { return Some(s); }
            }
        }
        return None;
    }
    #[allow(unreachable_code)]
    None
}

/// Word-wrap a long line at approximately `max_width` characters.
fn wrap_line(line: &str, max_width: usize) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = String::new();
    for word in line.split_inclusive(' ') {
        if !current.is_empty() && current.len() + word.len() > max_width {
            result.push(current.clone());
            current.clear();
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        result.push(current);
    }
    if result.is_empty() {
        result.push(line.to_string());
    }
    result
}

// ---------------------------------------------------------------------------
// State types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AppState {
    Disconnected,
    Connected,
    Suspended,
    Stepping,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LeftTab {
    Bytecodes,
    Decompiler,
    Trace,
    Ai,
    JniMonitor,
}

/// A native method binding captured from RegisterNatives or created via redirect.
#[derive(Debug, Clone)]
pub struct JniNativeEntry {
    pub class_sig: String,
    pub method_name: String,
    pub method_sig: String,
    pub native_addr: i64,
    pub lib_name: String,
    pub lib_offset: i64,
    /// True when a redirect stub is installed in place of the original function.
    pub redirected: bool,
    /// The redirect action in effect ("block", "true", "spoof"), if any.
    pub redirect_action: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LocalsTab {
    Locals,
    Registers,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RightTab {
    Stack,
    Breakpoints,
    Threads,
    Watch,
    Heap,
    Bookmarks,
}

/// A user-registered watch expression, re-evaluated on every suspension.
#[derive(Debug, Clone)]
pub struct WatchEntry {
    pub expr: String,
    pub last_value: Option<String>,
    pub last_type:  Option<String>,
}

/// A user-placed bookmark in the disassembly.
#[derive(Debug, Clone)]
pub struct Bookmark {
    pub class: String,
    pub method: String,
    pub offset: i64,   // bytecode offset
    pub label: String, // user-editable name
}

/// A single row in the heap browser panel.
#[derive(Debug, Clone)]
pub enum HeapRow {
    /// Header line summarizing the search.
    Header(String),
    /// A top-level heap object (index, display string).
    Object { index: i32, value: String },
    /// A heap string match.
    StringMatch { index: i32, value: String },
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LogLevel {
    Info,
    Error,
    Crypto,
    Exception,
    Debug,
    Agent,
    Call,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CallCategory {
    Crypto,
    Network,
    Exec,
    Reflection,
    DexLoad,
    Exfil,
    Other,
}

#[derive(Debug, Clone)]
pub struct CallRecord {
    pub seq: i32,
    pub thread: String,
    pub class: String,
    pub method: String,
    pub args: Vec<String>,
    pub ret: Option<String>,
    pub exception: bool,
    pub category: CallCategory,
    pub depth: usize,
    pub is_exit: bool,
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub level: LogLevel,
    pub text: String,
}

/// Which border is currently being dragged.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DragTarget {
    None,
    /// Vertical border between left (bytecodes) and right (locals/tabbed) columns.
    VerticalSplit,
    /// Horizontal border between top panels area and log.
    HorizontalSplit,
    /// Horizontal border between locals and tabbed in the right panel.
    RightHorizontalSplit,
    /// Click-drag selection in the command line input.
    CommandArea,
    /// Click-drag selection in the log panel.
    LogArea,
    /// Click-drag selection in the bytecodes panel.
    BytecodesArea,
}

/// Which panel spawned the context menu.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ContextMenuSource {
    Log,
    Trace,
    Ai,
    Bytecodes,
    Locals,
    Tabbed,
    PatchSubmenu,
    CommandInput,
    JniMonitor,
}

/// Saved bytecodes view state for Esc-back navigation after double-click follow.
#[derive(Debug, Clone)]
pub struct NavEntry {
    pub class: Option<String>,
    pub method: Option<String>,
    pub bytecodes: Vec<Instruction>,
    pub scroll: usize,
    pub cursor: Option<usize>,
    pub current_loc: Option<i64>,
}

/// State for pending conditional breakpoint evaluation (waiting for locals/regs).
#[derive(Debug, Clone)]
pub struct PendingCondEval {
    pub bp_id: i32,
    pub class: String,
    pub method: String,
    pub location: i64,
    pub line: i32,
    pub got_locals: bool,
    pub got_regs: bool,
}

/// Pending breakpoint that needs class name resolution via `cls` query.
#[derive(Debug, Clone)]
pub struct PendingBpResolve {
    pub short_name: String,
    pub method: String,
    pub sig: Option<String>,
    pub location: Option<i64>,
    pub cond: Option<BreakpointCondition>,
    pub force_deopt: bool,
}

/// Context menu state for right-click popups.
#[derive(Debug, Clone)]
pub struct ContextMenu {
    pub x: u16,
    pub y: u16,
    pub items: Vec<String>,
    pub selected: usize,
    pub source: ContextMenuSource,
    /// Line index in the source panel.
    pub line_idx: usize,
    /// Column position within the panel text (for word-under-cursor).
    pub click_col: usize,
    /// Up/Down/Enter navigate instead of dismissing the menu.
    pub keyboard_navigable: bool,
}

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------

pub struct App {
    pub running: bool,
    pub state: AppState,

    // Connection
    pub agent_rx: Option<mpsc::Receiver<AgentMessage>>,
    pub cmd_tx: Option<mpsc::Sender<OutboundCommand>>,

    // Focus: 0=bytecodes, 1=locals, 2=tabbed, 3=log
    pub focus: usize,
    pub command_focused: bool,

    // Tabs
    pub left_tab: LeftTab,
    pub locals_tab: LocalsTab,
    pub right_tab: RightTab,

    // Command input
    pub command_input: String,
    pub command_cursor: usize,      // cursor position (byte offset, always on char boundary)
    pub command_sel_anchor: Option<usize>, // selection anchor (byte offset); None = no selection
    pub command_history: Vec<String>,
    pub history_idx: Option<usize>,

    // Bytecodes panel
    pub bytecodes: Vec<Instruction>,
    pub bytecodes_scroll: usize,
    pub bytecodes_auto_scroll: bool,
    pub bytecodes_cursor: Option<usize>,    // selected instruction index for F2/follow
    pub nav_stack: Vec<NavEntry>,           // for Esc-back after double-click follow
    pub last_click_time: std::time::Instant,
    pub last_click_pos: (u16, u16),
    pub pending_follow: bool,         // true after follow_at_cursor sends dis
    pub pending_dis_scroll_location: Option<i64>,  // scroll to this bytecode offset after next DisResult
    pub stepping_since: Option<std::time::Instant>,  // timeout safety for stuck STEPPING
    pub stepping_quiet: bool,  // suppress verbose logs during step sequences
    pub bytecodes_highlight: Option<String>,  // word to highlight in all occurrences
    pub current_loc: Option<i64>,
    pub current_class: Option<String>,
    pub current_method: Option<String>,
    pub current_bytecode_bytes: Vec<u8>,  // raw bytes from last DisResult, for re-disassembly
    pub current_line: Option<i32>,
    pub current_thread: Option<String>,

    // Locals panel
    pub locals: Vec<LocalVar>,
    pub locals_scroll: usize,

    // Raw register values (from "regs" command  - all slots, for branch evaluation)
    pub regs: Vec<crate::protocol::RegValue>,

    // Stack
    pub stack: Vec<StackFrame>,

    // Threads
    pub threads: Vec<ThreadEntry>,

    // Breakpoints
    pub bp_manager: BreakpointManager,

    // Watch expressions
    pub watches: Vec<WatchEntry>,
    pub watch_selected: usize,

    // Bookmarks
    pub bookmarks: Vec<Bookmark>,
    pub bookmarks_cursor: usize,

    // Log
    pub log: Vec<LogEntry>,
    pub log_scroll: usize,
    pub log_auto_scroll: bool,
    /// Mouse selection in the log panel: (absolute_log_idx, display_col).
    /// Anchor is fixed; head tracks the drag end.
    pub log_sel_anchor: Option<(usize, usize)>,
    pub log_sel_head: Option<(usize, usize)>,

    /// Mouse selection in the bytecodes panel: (bc_idx, display_col).
    /// Anchor is fixed; head tracks the drag end.
    pub bytecodes_sel_anchor: Option<(usize, usize)>,
    pub bytecodes_sel_head: Option<(usize, usize)>,

    // Tabbed panel scroll
    pub tabbed_scroll: usize,

    // Heap browser
    pub heap_rows: Vec<HeapRow>,
    pub heap_scroll: usize,
    pub heap_selected: usize,

    // Hexdump: show extended rows when "full" flag is set
    pub hexdump_full: bool,

    // Panel split ratios (0.0 to 1.0)
    /// Left/right column split: fraction of width for left panel.
    pub split_h: f32,
    /// Top/bottom split: fraction of available height for top panels.
    pub split_v: f32,
    /// Right panel locals/tabbed split: fraction of top height for locals.
    pub split_right_v: f32,

    // Mouse drag state
    pub drag: DragTarget,
    /// Last layout geometry (for mouse hit-testing).
    pub layout_geom: Option<crate::tui::LayoutGeometry>,

    // Mouse capture toggle (F12)
    pub mouse_enabled: bool,
    /// Set to true when mouse_enabled changed  - main loop will send crossterm command.
    pub mouse_toggled: bool,

    // Context menu (right-click popup)
    pub context_menu: Option<ContextMenu>,

    // DEX constant pool data (loaded from APK for symbol resolution)
    pub dex_data: Vec<crate::dex_parser::DexData>,

    // Labels for each DexData: "apk", "dynamic-1", "dynamic-2", etc.
    pub dex_labels: Vec<String>,

    // Counter for dynamic DEX labels
    pub dynamic_dex_count: usize,

    // Background auto-load (spawned when DisResult arrives with no DEX loaded)
    pub auto_dex_loading: bool,
    pub dex_load_rx: Option<mpsc::Receiver<Result<(Vec<crate::dex_parser::DexData>, String), String>>>,

    // Pending bp class resolution (lazy: sends cls query, resolves on ClsResult)
    pub pending_bp_resolve: Option<PendingBpResolve>,
    pub cls_auto_pending: bool,

    // Flag: log register values when next RegsResult arrives
    pub pending_regs_log: bool,

    // Conditional breakpoint evaluation state
    pub pending_cond_eval: Option<PendingCondEval>,
    /// Condition for the current single `bp` command (applies to all overloads).
    pub pending_bp_cond: Option<BreakpointCondition>,
    /// Queue of conditions for batch operations (bp profiles).
    pub pending_bp_conditions: VecDeque<BreakpointCondition>,
    /// Bypass-SSL: bp IDs that should auto force-return void + continue on hit.
    pub bypass_ssl_bps: HashSet<i32>,
    /// Number of pending BpSetOk confirmations to absorb into bypass_ssl_bps.
    pub pending_bypass_count: usize,
    /// True while bypass-ssl is active — enables SSLContext.init TrustManager inspection.
    pub bypass_ssl_active: bool,
    /// BP IDs that should silently ForceEarlyReturn with a neutral value on hit.
    pub anti_bps: HashSet<i32>,
    /// Number of pending BpSetOk confirmations to absorb into anti_bps.
    pub pending_anti_count: usize,

    // Per-app session state (loaded on connect, saved with Ctrl+S)
    /// Package name of the connected app (from /proc/self/cmdline).
    pub current_package: Option<String>,
    /// User-defined display aliases: JNI class sig → label.
    pub aliases: HashMap<String, String>,
    /// App-specific intercept hooks (persisted in sessions/<pkg>.json).
    pub hooks: Vec<crate::session::HookRule>,
    /// Breakpoints queued for restore after RedefineClasses cleared them.
    /// Each entry: (class, method, location, optional_condition).
    /// Consumed by the next matching BpSetOk to re-attach conditions.
    pub redefine_restore: Vec<(String, String, i64, Option<crate::condition::BreakpointCondition>)>,

    // JNI monitor
    pub jni_natives: Vec<JniNativeEntry>,
    pub jni_monitoring: bool,
    pub jni_monitor_scroll: usize,

    // Call recording
    pub call_records: Vec<CallRecord>,
    pub recording_active: bool,
    pub trace_scroll: usize,
    pub trace_auto_scroll: bool,
    /// Per-thread call depth for tree indentation.
    pub trace_depth: std::collections::HashMap<String, usize>,
    /// When true, record flat (no tree indentation, no exit records).
    pub trace_flat: bool,
    /// When true, skip exit records (entry-only recording).
    pub trace_onenter: bool,

    // Trace file save (live flush)
    pub trace_save_active: bool,
    pub trace_save_file: Option<std::io::BufWriter<std::fs::File>>,

    // Config
    pub config: Config,

    // Startup command queue (from dexbgd.ini [startup])
    pub startup_queue: VecDeque<String>,
    // Session startup commands deferred until APK symbols are loaded
    pub session_startup_queue: Vec<String>,
    /// When auto_connect_retry is on, tracks when last disconnect/fail occurred.
    pub retry_timer: Option<std::time::Instant>,

    // Agent capabilities (optional)
    pub cap_force_early_return: bool,
    pub cap_pop_frame: bool,
    pub cap_frame_pop: bool,
    pub cap_redefine_classes: bool,

    /// When true, F9/sout/finish use sout2 instead of single-step step-out.
    pub use_sout2: bool,

    // Color theme (Ctrl+T to cycle)
    pub theme: Theme,
    pub theme_index: usize,
    pub themes: Vec<Theme>,

    // AI analysis agent
    pub ai_mode: AiMode,
    pub ai_state: AiState,
    pub ai_output: Vec<AiOutputLine>,
    pub ai_scroll: usize,
    pub ai_auto_scroll: bool,
    pub ai_req_tx: Option<mpsc::Sender<AiRequest>>,
    pub ai_evt_rx: Option<mpsc::Receiver<AiEvent>>,
    pub ai_cancel: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    pub ai_pending_tool_call: Option<(String, String)>, // (tool_use_id, description)
    pub ai_pending_tool_input: Option<(String, serde_json::Value)>, // (name, input) for Ask mode

    // Inline comments: (class, method, bci) -> comment text
    pub comments: std::collections::HashMap<(String, String, u32), String>,
    // Comment dialog state
    pub comment_open: bool,
    pub comment_address: Option<u32>,
    // Alias dialog state (n key — rename current class, IDA-style)
    pub alias_open: bool,
    pub alias_target: Option<String>, // JNI sig being renamed
    pub comment_input: String,
    pub comment_cursor: usize,

    // Session picker dialog (Ctrl+L)
    pub session_picker_open: bool,
    pub session_picker_list: Vec<String>,  // package names from sessions/*.json
    pub session_picker_sel: usize,
}

const MAX_LOG_ENTRIES: usize = 10000;

/// Background worker for auto-loading APK symbols from device.
/// Runs on a spawned thread; result sent back via mpsc channel.
/// Returns (dex_data, local_apk_path) on success, error string on failure.
fn auto_load_dex_bg(class_sig: &str) -> Result<(Vec<crate::dex_parser::DexData>, String), String> {
    // Extract package from JNI sig: "Lcom/test/jitdemo/MainActivity;" → "com.test.jitdemo"
    let inner = class_sig
        .strip_prefix('L').unwrap_or(class_sig)
        .strip_suffix(';').unwrap_or(class_sig);
    let parts: Vec<&str> = inner.split('/').collect();
    if parts.len() < 2 {
        return Err("class sig too short to derive package".to_string());
    }

    // Try progressively shorter package prefixes
    for end in (2..=parts.len().saturating_sub(1)).rev() {
        let package = parts[..end].join(".");
        match crate::dex_parser::adb_pull_apk(&package) {
            Ok(local_path) => {
                match crate::dex_parser::load_apk(&local_path) {
                    Ok(dex_data) => return Ok((dex_data, local_path)),
                    Err(e) => return Err(format!("DEX parse failed: {}", e)),
                }
            }
            Err(_) => continue, // try shorter prefix
        }
    }

    Err("no matching package found".to_string())
}

impl App {
    pub fn new(config: Config) -> Self {
        Self {
            running: true,
            state: AppState::Disconnected,
            agent_rx: None,
            cmd_tx: None,
            focus: 4,
            command_focused: true, // start with command focused
            left_tab: LeftTab::Bytecodes,
            locals_tab: LocalsTab::Locals,
            right_tab: RightTab::Stack,
            command_input: String::new(),
            command_cursor: 0,
            command_sel_anchor: None,
            command_history: config.history.clone(),
            history_idx: None,
            bytecodes: Vec::new(),
            bytecodes_scroll: 0,
            bytecodes_auto_scroll: true,
            bytecodes_cursor: None,
            nav_stack: Vec::new(),
            last_click_time: std::time::Instant::now(),
            last_click_pos: (0, 0),
            pending_follow: false,
            pending_dis_scroll_location: None,
            stepping_since: None,
            stepping_quiet: false,
            bytecodes_highlight: None,
            current_loc: None,
            current_class: None,
            current_method: None,
            current_bytecode_bytes: Vec::new(),
            current_line: None,
            current_thread: None,
            locals: Vec::new(),
            locals_scroll: 0,
            regs: Vec::new(),
            stack: Vec::new(),
            threads: Vec::new(),
            bp_manager: BreakpointManager::default(),
            watches: Vec::new(),
            watch_selected: 0,
            bookmarks: Vec::new(),
            bookmarks_cursor: 0,
            log: Vec::new(),
            log_scroll: 0,
            log_auto_scroll: true,
            log_sel_anchor: None,
            log_sel_head: None,
            bytecodes_sel_anchor: None,
            bytecodes_sel_head: None,
            tabbed_scroll: 0,
            heap_rows: Vec::new(),
            heap_scroll: 0,
            heap_selected: 0,
            hexdump_full: false,
            split_h: config.split_h,
            split_v: config.split_v,
            split_right_v: config.split_right_v,
            drag: DragTarget::None,
            layout_geom: None,
            mouse_enabled: true,
            mouse_toggled: false,
            context_menu: None,
            dex_data: Vec::new(),
            dex_labels: Vec::new(),
            dynamic_dex_count: 0,
            auto_dex_loading: false,
            dex_load_rx: None,
            pending_bp_resolve: None,
            cls_auto_pending: false,
            pending_regs_log: false,
            pending_cond_eval: None,
            pending_bp_cond: None,
            pending_bp_conditions: VecDeque::new(),
            bypass_ssl_bps: HashSet::new(),
            pending_bypass_count: 0,
            bypass_ssl_active: false,
            anti_bps: HashSet::new(),
            pending_anti_count: 0,
            current_package: None,
            aliases: HashMap::new(),
            hooks: Vec::new(),
            redefine_restore: Vec::new(),
            jni_natives: Vec::new(),
            jni_monitoring: false,
            jni_monitor_scroll: 0,
            call_records: Vec::new(),
            recording_active: false,
            trace_scroll: 0,
            trace_auto_scroll: true,
            trace_depth: std::collections::HashMap::new(),
            trace_flat: false,
            trace_onenter: false,
            trace_save_active: false,
            trace_save_file: None,
            startup_queue: {
                let mut q = VecDeque::from(config.startup_cmds.clone());
                // auto_connect prepends "connect" if not already first
                if config.auto_connect && q.front().map(|s: &String| s.trim() != "connect").unwrap_or(true) {
                    q.push_front("connect".to_string());
                }
                q
            },
            retry_timer: None,
            session_startup_queue: Vec::new(),
            cap_force_early_return: false,
            cap_pop_frame: false,
            cap_frame_pop: false,
            cap_redefine_classes: false,
            use_sout2: false,
            theme_index: config.theme_index.min(crate::theme::builtin_themes().len().saturating_sub(1)),
            themes: crate::theme::builtin_themes(),
            theme: {
                let themes = crate::theme::builtin_themes();
                let idx = config.theme_index.min(themes.len().saturating_sub(1));
                themes[idx].clone()
            },
            config,
            ai_mode: AiMode::Auto,
            ai_state: AiState::Idle,
            ai_output: Vec::new(),
            ai_scroll: 0,
            ai_auto_scroll: true,
            ai_req_tx: None,
            ai_evt_rx: None,
            ai_cancel: None,
            ai_pending_tool_call: None,
            ai_pending_tool_input: None,
            comments: std::collections::HashMap::new(),
            comment_open: false,
            comment_address: None,
            alias_open: false,
            alias_target: None,
            comment_input: String::new(),
            comment_cursor: 0,
            session_picker_open: false,
            session_picker_list: Vec::new(),
            session_picker_sel: 0,
        }
    }

    // -------------------------------------------------------------------
    // Event loop tick
    // -------------------------------------------------------------------

    pub fn tick(&mut self) {
        // Startup command queue: fire next command when the right state is reached.
        // "connect" fires immediately (after first tick). All subsequent commands
        // wait until Connected/Suspended.
        if !self.startup_queue.is_empty() {
            let next_is_connect = self.startup_queue.front()
                .map(|s| s.trim() == "connect")
                .unwrap_or(false);
            let ready = next_is_connect
                || matches!(self.state, AppState::Connected | AppState::Suspended);
            if ready {
                let cmd = self.startup_queue.pop_front().unwrap();
                self.execute_command(&cmd);
            }
        }

        // auto_connect_retry: when disconnected and the startup queue is done,
        // re-fire connect after retry_interval_s.
        if self.config.auto_connect_retry
            && self.state == AppState::Disconnected
            && self.agent_rx.is_none()
            && self.startup_queue.is_empty()
        {
            if let Some(since) = self.retry_timer {
                if since.elapsed() >= Duration::from_secs(self.config.retry_interval_s) {
                    self.retry_timer = None;
                    self.do_connect();
                }
            }
        }

        // Process agent messages (non-blocking)
        self.poll_agent_messages();

        // Safety: cancel stuck STEPPING after 5 seconds
        if self.state == AppState::Stepping {
            if let Some(since) = self.stepping_since {
                if since.elapsed() > Duration::from_secs(5) {
                    self.log_error("Stepping timed out (5s) - sending continue");
                    self.stepping_since = None;
                    self.execute_command("c");
                }
            }
        } else {
            self.stepping_since = None;
        }

        // Process background DEX auto-load result (non-blocking)
        self.poll_dex_load();

        // Process AI events (non-blocking)
        self.poll_ai_events();


        // Process terminal events
        if event::poll(Duration::from_millis(50)).unwrap_or(false) {
            if let Ok(ev) = event::read() {
                match ev {
                    Event::Key(key) if key.kind == KeyEventKind::Press => self.handle_key(key),
                    Event::Mouse(mouse) => self.handle_mouse(mouse),
                    Event::Resize(_, _) => {} // ratatui handles this
                    _ => {}
                }
            }
        }
    }

    // -------------------------------------------------------------------
    // Agent message handling
    // -------------------------------------------------------------------

    fn poll_agent_messages(&mut self) {
        // Drain all available messages into a temporary vec to avoid borrow conflict
        let mut messages = Vec::new();
        let mut disconnected = false;

        if let Some(rx) = &self.agent_rx {
            loop {
                match rx.try_recv() {
                    Ok(msg) => messages.push(msg),
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        disconnected = true;
                        break;
                    }
                }
            }
        } else {
            return;
        }

        for msg in messages {
            self.handle_agent_message(msg);
        }

        if disconnected {
            self.log_info("Agent disconnected");
            self.state = AppState::Disconnected;
            self.agent_rx = None;
            self.cmd_tx = None;
            if self.config.auto_connect_retry {
                self.retry_timer = Some(std::time::Instant::now());
            }
        }
    }

    fn handle_agent_message(&mut self, msg: AgentMessage) {
        match msg {
            AgentMessage::Connected { pid, version, device, api_level, capabilities, package_name } => {
                self.state = AppState::Connected;
                let dev = device.as_deref().unwrap_or("unknown");
                let api = api_level.map_or("?".to_string(), |v| v.to_string());
                self.log_agent(&format!("Connected: pid={}, {}, API {}, {}", pid, dev, api, version));
                if let Some(caps) = capabilities {
                    let mut missing = Vec::new();
                    if !caps.breakpoints.unwrap_or(false) { missing.push("breakpoints"); }
                    if !caps.single_step.unwrap_or(false) { missing.push("single-step"); }
                    if !caps.local_vars.unwrap_or(false) { missing.push("locals"); }
                    if !caps.bytecodes.unwrap_or(false) { missing.push("bytecodes"); }
                    if !caps.tag_objects.unwrap_or(false) { missing.push("heap-search"); }
                    if missing.is_empty() {
                        self.log_debug("All capabilities available");
                    } else {
                        self.log_error(&format!("MISSING capabilities: {}  - some features will not work", missing.join(", ")));
                    }
                    // Report optional capabilities
                    let fer = caps.force_early_return.unwrap_or(false);
                    let pf = caps.pop_frame.unwrap_or(false);
                    let fp = caps.frame_pop.unwrap_or(false);
                    if fer || pf || fp {
                        let mut extras = Vec::new();
                        if fer { extras.push("force-early-return"); }
                        if pf { extras.push("pop-frame"); }
                        if fp { extras.push("frame-pop"); }
                        self.log_info(&format!("Extra capabilities: {}", extras.join(", ")));
                    }
                    self.cap_force_early_return = fer;
                    self.cap_pop_frame = pf;
                    self.cap_frame_pop = fp;
                    self.cap_redefine_classes = caps.redefine_classes.unwrap_or(false);
                }
                // Load per-app session (aliases, comments, hooks, bookmarks)
                if let Some(pkg) = package_name {
                    self.current_package = Some(pkg.clone());
                    self.load_session(&pkg);
                }
                // Auto-refresh thread list on connect
                self.send_command(OutboundCommand::Threads {});
            }

            AgentMessage::ClsResult { count, classes } => {
                if self.cls_auto_pending {
                    // This was an auto-cls for bp short-name resolution
                    self.cls_auto_pending = false;
                    if let Some(pending) = self.pending_bp_resolve.take() {
                        let suffix = format!("/{};\n", pending.short_name);
                        let suffix = &suffix[..suffix.len() - 1]; // "/Cipher;"
                        let exact = format!("L{};", pending.short_name);
                        let matches: Vec<&str> = classes.iter()
                            .map(|c| c.sig.as_str())
                            .filter(|s| s.ends_with(suffix) || *s == exact)
                            .collect();
                        if matches.len() == 1 {
                            let resolved = matches[0].to_string();
                            self.log_debug(&format!("Resolved {} -> {}", pending.short_name, resolved));
                            self.pending_bp_cond = pending.cond;
                            if pending.force_deopt {
                                self.send_command(OutboundCommand::BpSetDeopt {
                                    class: resolved,
                                    method: pending.method,
                                    sig: pending.sig,
                                    location: pending.location,
                                });
                            } else {
                                self.send_command(OutboundCommand::BpSet {
                                    class: resolved,
                                    method: pending.method,
                                    sig: pending.sig,
                                    location: pending.location,
                                });
                            }
                        } else if matches.is_empty() {
                            self.log_error(&format!("No class found matching '{}'", pending.short_name));
                            self.log_info("Use full class name, e.g.: bp javax.crypto.Cipher init");
                        } else {
                            self.log_error(&format!("Ambiguous class '{}'  - {} matches:", pending.short_name, matches.len()));
                            for (i, m) in matches.iter().enumerate() {
                                if i >= 10 {
                                    self.log_error(&format!("  ... and {} more", matches.len() - 10));
                                    break;
                                }
                                self.log_error(&format!("  {}", m));
                            }
                            self.log_info("Use full class name, e.g.: bp javax.crypto.Cipher init");
                        }
                    }
                } else {
                    self.log_info(&format!("Classes matched: {}", count));
                    for (i, cls) in classes.iter().enumerate() {
                        if i >= 200 {
                            self.log_info(&format!("  ... and {} more", count as usize - 200));
                            break;
                        }
                        self.log_info(&format!("  {}", cls.sig));
                    }
                }
            }

            AgentMessage::MethodsResult { class, count, methods } => {
                let cls = short_class(&class);
                self.log_info(&format!("{} methods in {}:", count, cls));
                for m in &methods {
                    let mods = modifiers_str(m.modifiers);
                    self.log_info(&format!("  {}{}{}", if mods.is_empty() { "" } else { &mods }, if mods.is_empty() { "" } else { " " }, m.name));
                }
            }

            AgentMessage::FieldsResult { class, count, fields } => {
                let cls = short_class(&class);
                self.log_info(&format!("{} fields in {}:", count, cls));
                for f in &fields {
                    let mods = modifiers_str(f.modifiers);
                    let t = short_type(&f.sig);
                    self.log_info(&format!("  {}{}{}: {}", if mods.is_empty() { "" } else { &mods }, if mods.is_empty() { "" } else { " " }, f.name, t));
                }
            }

            AgentMessage::ThreadsResult { count, threads } => {
                self.threads = threads.clone();
                if !self.stepping_quiet {
                    self.log_debug(&format!("{} threads (see [Thd] tab)", count));
                }
            }

            AgentMessage::DisResult { class, method, bytecode_len, bytecodes_b64, current_loc } => {
                self.pending_follow = false;
                // Auto-load DEX data on first disassembly (background thread - non-blocking)
                if self.dex_data.is_empty() && !self.auto_dex_loading {
                    self.auto_dex_loading = true;
                    let (tx, rx) = mpsc::channel();
                    self.dex_load_rx = Some(rx);
                    let class_sig = class.clone();
                    std::thread::spawn(move || {
                        let _ = tx.send(auto_load_dex_bg(&class_sig));
                    });
                }
                match BASE64.decode(&bytecodes_b64) {
                    Ok(bytes) => {
                        let dex = self.find_dex_for_class(&class);
                        let has_dex = dex.is_some();
                        let instructions = disassembler::disassemble(&bytes, dex);
                        self.current_bytecode_bytes = bytes;
                        self.bytecodes = instructions;
                        self.bytecodes_highlight = None;
                        self.bytecodes_cursor = None;
                        self.current_loc = current_loc;

                        // Scroll to a specific bytecode offset if requested (e.g. from
                        // stack double-click or 'u Method:offset').
                        if let Some(target_loc) = self.pending_dis_scroll_location.take() {
                            if let Some(idx) = self.bytecodes.iter().position(|i| i.offset as i64 == target_loc) {
                                self.bytecodes_cursor = Some(idx);
                                self.bytecodes_scroll = idx.saturating_sub(2);
                            }
                        } else if self.bytecodes_auto_scroll {
                            // Show 2 instructions before current PC, then lock to manual mode
                            // so subsequent steps "walk" through the view instead of re-centering.
                            let scroll = current_loc
                                .and_then(|loc| self.bytecodes.iter().position(|i| i.offset == loc as u32))
                                .map(|idx| idx.saturating_sub(2))
                                .unwrap_or(0);
                            self.bytecodes_scroll = scroll;
                            self.bytecodes_auto_scroll = false;
                        } else {
                            self.bytecodes_scroll = 0;
                        }
                        self.current_class = Some(class.clone());
                        self.current_method = Some(method.clone());
                        let cls = short_class(&class);
                        let res_info = if has_dex {
                            "resolved"
                        } else if !self.dex_data.is_empty() {
                            "unresolved (class not in loaded DEX)"
                        } else {
                            "unresolved (no DEX loaded)"
                        };
                        if !self.stepping_quiet {
                            self.log_debug(&format!("Disassembled {}.{}: {} bytes, {} insns [{}]",
                                cls, method, bytecode_len, self.bytecodes.len(), res_info));
                        }
                    }
                    Err(e) => {
                        self.log_error(&format!("base64 decode failed: {}", e));
                    }
                }
            }

            AgentMessage::BpSetOk { id, class, method, location } => {
                // Absorb into bypass set if bypass-ssl is pending
                if self.pending_bypass_count > 0 {
                    self.bypass_ssl_bps.insert(id);
                    self.pending_bypass_count -= 1;
                }
                // Absorb into anti set if anti is pending
                if self.pending_anti_count > 0 {
                    self.anti_bps.insert(id);
                    self.pending_anti_count -= 1;
                }
                let cls = short_class(&class);
                let was_deferred = self.bp_manager.update_or_add(BreakpointEntry {
                    id,
                    class: class.clone(),
                    method: method.clone(),
                    sig: String::new(),
                    location,
                });
                // Check if this confirms a restore after RedefineClasses cleared the bp
                if let Some(pos) = self.redefine_restore.iter().position(|(c, m, l, _)| {
                    *c == class && *m == method && *l == location
                }) {
                    let (_, _, _, cond) = self.redefine_restore.remove(pos);
                    if let Some(c) = cond {
                        self.bp_manager.set_condition(id, c.clone());
                        self.log_info(&format!("Breakpoint #{} restored: {}.{} @{:04x} [{}]", id, cls, method, location, c));
                    } else {
                        self.log_info(&format!("Breakpoint #{} restored after patch: {}.{} @{:04x}", id, cls, method, location));
                    }
                } else {
                    if was_deferred {
                        // Deferred breakpoint now active — condition was already attached on BpDeferred
                        self.log_info(&format!("Breakpoint #{} set (class loaded): {}.{} @{:04x}", id, cls, method, location));
                    } else {
                        // Normal (non-deferred) breakpoint confirmation — attach condition now.
                        let cond = if let Some(ref c) = self.pending_bp_cond {
                            Some(c.clone())
                        } else {
                            self.pending_bp_conditions.pop_front()
                        };
                        if let Some(c) = cond {
                            if !c.is_empty() {
                                self.log_info(&format!("Breakpoint #{} set: {}.{} @{:04x} [{}]",
                                    id, cls, method, location, c));
                                self.bp_manager.set_condition(id, c);
                            } else {
                                self.log_info(&format!("Breakpoint #{} set: {}.{} @{:04x}", id, cls, method, location));
                            }
                        } else {
                            self.log_info(&format!("Breakpoint #{} set: {}.{} @{:04x}", id, cls, method, location));
                        }
                    }
                }
            }

            AgentMessage::BpClearOk { id } => {
                self.log_info(&format!("Breakpoint #{} cleared", id));
                self.bp_manager.remove(id);
                self.anti_bps.remove(&id);
            }

            AgentMessage::BpDeferred { id, class, method } => {
                let cls = short_class(&class);
                self.log_info(&format!("Breakpoint #{} deferred (class not loaded): {}.{}", id, cls, method));
                self.bp_manager.add_pending(BreakpointEntry {
                    id,
                    class: class.clone(),
                    method: method.clone(),
                    sig: String::new(),
                    location: -1,
                });
                // Attach any pending condition from the current command
                if let Some(cond) = self.pending_bp_cond.take() {
                    self.bp_manager.set_condition(id, cond);
                } else if let Some(cond) = self.pending_bp_conditions.pop_front() {
                    self.bp_manager.set_condition(id, cond);
                }
            }

            AgentMessage::BpListResult { count, breakpoints } => {
                self.bp_manager.replace_all(breakpoints.clone());
                self.log_info(&format!("{} breakpoints:", count));
                for bp in &breakpoints {
                    let cls = short_class(&bp.class);
                    self.log_info(&format!("  #{} {}.{} @{}", bp.id, cls, bp.method, bp.location));
                }
            }

            AgentMessage::BpHit { bp_id, class, method, sig, location, line } => {
                self.stepping_quiet = false;
                // Auto-bypass SSL breakpoints — force return void + continue, no pause
                if self.bypass_ssl_bps.contains(&bp_id) {
                    let cls = short_class(&class);
                    self.log_info(&format!("[bypass-ssl] {}.{} bypassed", cls, method));
                    self.send_command(OutboundCommand::ForceReturn { return_value: 0 });
                    self.send_command(OutboundCommand::Continue {});
                    return;
                }
                // Anti hooks — silent ghost breakpoint, ForceEarlyReturn neutral value
                if self.anti_bps.contains(&bp_id) {
                    let retval = match self.bp_manager.get_condition(bp_id).and_then(|c| c.action.clone()) {
                        Some(condition::BreakpointAction::ForceReturn(v)) if v == condition::FORCE_RETURN_AUTO =>
                            condition::neutral_return_for_sig(&sig),
                        Some(condition::BreakpointAction::ForceReturn(v)) => v,
                        _ => condition::neutral_return_for_sig(&sig),
                    };
                    let label = if retval == condition::FORCE_RETURN_VOID { "void" } else { "0/false/null" };
                    let cls = short_class(&class);
                    self.log_info(&format!("[anti] {}.{}{} -> {}", cls, method, sig, label));
                    self.send_command(OutboundCommand::ForceReturn {
                        return_value: if retval == condition::FORCE_RETURN_VOID { 0 } else { retval },
                    });
                    self.send_command(OutboundCommand::Continue {});
                    return;
                }
                // SSLContext.init interception — inspect TrustManager[] to find obfuscated TM class
                if self.bypass_ssl_active && method == "init"
                    && class == "Ljavax/net/ssl/SSLContext;"
                {
                    self.log_info("[bypass-ssl] SSLContext.init hit - inspecting TrustManager[]...");
                    self.send_command(OutboundCommand::SslGetTmClasses {});
                    return;
                }
                // Check for BreakpointAction (intercept hook — fires before condition eval)
                if let Some(action) = self.bp_manager.get_condition(bp_id)
                    .and_then(|c| c.action.clone())
                {
                    let cls = display_class(&class, &self.aliases);
                    match action {
                        BreakpointAction::LogAndContinue => {
                            self.log_info(&format!("[hook] {}.{} @{}", cls, method, location));
                            self.send_command(OutboundCommand::Continue {});
                            return;
                        }
                        BreakpointAction::ForceReturn(v) => {
                            let label = if v == FORCE_RETURN_VOID { "void".to_string() } else { v.to_string() };
                            self.log_info(&format!("[hook] {}.{} force-return {}", cls, method, label));
                            self.send_command(OutboundCommand::ForceReturn { return_value: if v == FORCE_RETURN_VOID { 0 } else { v } });
                            self.send_command(OutboundCommand::Continue {});
                            return;
                        }
                    }
                }

                // Check if this breakpoint has conditions
                let has_condition = self.bp_manager.get_condition(bp_id).is_some();
                if has_condition {
                    self.log_debug(&format!("BP#{} hit with condition, evaluating...", bp_id));
                } else {
                    self.log_debug(&format!("BP#{} hit (no condition, {} conditions total in manager)",
                        bp_id, self.bp_manager.conditions.len()));
                }
                if has_condition {
                    let hit_count = self.bp_manager.increment_hit(bp_id);
                    let cond = self.bp_manager.get_condition(bp_id).unwrap().clone();

                    // Evaluate hit condition first (no round-trip needed)
                    if let Some(ref hit_cond) = cond.hit_condition {
                        if !condition::evaluate_hit_condition(hit_cond, hit_count) {
                            // Hit condition failed  - auto-continue
                            if cond.var_condition.is_none() {
                                let cls = short_class(&class);
                                self.log_debug(&format!("BP#{} skipped (hit {}/{}): {}.{}",
                                    bp_id, hit_count, hit_cond, cls, method));
                                self.send_command(OutboundCommand::Continue {});
                                return;
                            }
                            // If there's also a var condition, skip entirely (hit didn't match)
                            let cls = short_class(&class);
                            self.log_debug(&format!("BP#{} skipped (hit {}/{}): {}.{}",
                                bp_id, hit_count, hit_cond, cls, method));
                            self.send_command(OutboundCommand::Continue {});
                            return;
                        }
                    }

                    // If there's a var condition, we need locals/regs to evaluate it
                    if cond.var_condition.is_some() {
                        let is_native = location == -1;
                        if is_native {
                            // Can't get locals for native methods  - skip var condition
                            let cls = short_class(&class);
                            self.log_debug(&format!("BP#{} native method, skipping var condition: {}.{}",
                                bp_id, cls, method));
                            self.send_command(OutboundCommand::Continue {});
                            return;
                        }
                        // Set up pending evaluation  - request only locals+regs
                        // Clear stale data so evaluation uses fresh results
                        self.locals = Vec::new();
                        self.regs = Vec::new();
                        self.current_class = Some(class.clone());
                        self.current_method = Some(method.clone());
                        self.current_loc = Some(location);
                        self.current_line = Some(line);
                        self.pending_cond_eval = Some(PendingCondEval {
                            bp_id,
                            class,
                            method,
                            location,
                            line,
                            got_locals: false,
                            got_regs: false,
                        });
                        self.send_command(OutboundCommand::Locals {});
                        self.send_command(OutboundCommand::Regs {});
                        return;
                    }

                    // Hit condition passed, no var condition  - normal suspend
                }

                // No conditions or all conditions passed  - normal suspend flow
                self.state = AppState::Suspended;
                self.current_class = Some(class.clone());
                self.current_method = Some(method.clone());
                self.current_loc = Some(location);
                self.current_line = Some(line);
                let cls = short_class(&class);
                let line_str = if line >= 0 { format!(":{}", line) } else { String::new() };
                self.log_info(&format!("Breakpoint #{} hit: {}.{}{} @{:04x}",
                    bp_id, cls, method, line_str, location));
                self.auto_refresh();

                // Auto-dump DEX when hitting DexClassLoader/InMemoryDexClassLoader breakpoints
                if class.contains("DexClassLoader") || class.contains("InMemoryDexClassLoader") {
                    self.log_info("[DEX] Auto-dumping DEX from DexClassLoader...");
                    self.send_command(OutboundCommand::DexDump {});
                }
            }

            AgentMessage::StepHit { class, method, sig: _, location, line } => {
                self.state = AppState::Suspended;
                self.stepping_quiet = true;

                let same_method = self.current_class.as_deref() == Some(&class)
                    && self.current_method.as_deref() == Some(&method)
                    && !self.bytecodes.is_empty();

                self.current_class = Some(class.clone());
                self.current_method = Some(method.clone());
                self.current_loc = Some(location);
                self.current_line = Some(line);

                if same_method {
                    // Stay in the same bytecodes view; only scroll if PC left visible range.
                    let code_height = self.layout_geom.as_ref()
                        .map(|g| g.bytecodes_area.height.saturating_sub(2).saturating_sub(1) as usize)
                        .unwrap_or(20);
                    if let Some(new_idx) = self.bytecodes.iter().position(|i| i.offset == location as u32) {
                        let visible = new_idx >= self.bytecodes_scroll
                            && new_idx < self.bytecodes_scroll + code_height.max(1);
                        if !visible {
                            // Scroll to show 2 instructions before PC
                            self.bytecodes_scroll = new_idx.saturating_sub(2);
                        }
                        // bytecodes_auto_scroll stays false; view follows PC only when needed
                    } else {
                        // PC offset not in current bytecodes (shouldn't normally happen) — full refresh
                        self.auto_refresh();
                        return;
                    }
                    self.send_command(OutboundCommand::Locals {});
                    self.send_command(OutboundCommand::Regs {});
                    self.send_command(OutboundCommand::Stack {});
                } else {
                    // New method — full refresh (sends Dis + Locals + Regs + Stack)
                    self.auto_refresh();
                }
            }

            AgentMessage::Stepping { mode: _ } => {
                self.state = AppState::Stepping;
                self.stepping_since = Some(std::time::Instant::now());
            }

            AgentMessage::FramePop { class, method, ret_type, ret_value, was_exception } => {
                // Just log the return value — step_hit follows and handles state/display
                self.stepping_quiet = false;
                self.stepping_since = None;
                let ret_str = if was_exception {
                    " (exception)".to_string()
                } else if ret_type == "void" {
                    String::new()
                } else {
                    format!(" -> {} {}", ret_type, ret_value)
                };
                self.log_info(&format!("[sout2] {}.{}(){}", short_class(&class), method, ret_str));
            }

            AgentMessage::StepThreadEnd {} => {
                self.state = AppState::Connected;
                self.stepping_since = None;
                self.stepping_quiet = false;
                self.log_error("Step thread terminated");
            }

            AgentMessage::Resumed {} => {
                self.state = AppState::Connected;
                self.stepping_quiet = false;
                self.log_debug("Resumed");
            }

            AgentMessage::Suspended { thread, class, method, sig: _, location, line } => {
                self.state = AppState::Suspended;
                self.stepping_quiet = false;
                self.current_class = Some(class.clone());
                self.current_method = Some(method.clone());
                self.current_loc = Some(location);
                self.current_line = Some(line);
                if let Some(t) = &thread {
                    self.current_thread = Some(t.clone());
                }
                let cls = short_class(&class);
                let tname = thread.as_deref().unwrap_or("?");
                self.log_info(&format!("Suspended thread '{}' at {}.{} @{}", tname, cls, method, location));
                self.auto_refresh();
            }

            AgentMessage::LocalsResult { vars } => {
                self.locals = vars;
                self.locals_scroll = 0;
                self.refresh_watches_from_locals();
                // Check if pending condition eval needs this
                if self.pending_cond_eval.is_some() {
                    if let Some(ref mut pending) = self.pending_cond_eval {
                        pending.got_locals = true;
                    }
                    self.try_complete_cond_eval();
                }
            }

            AgentMessage::RegsResult { regs } => {
                self.regs = regs;
                if self.pending_regs_log {
                    self.pending_regs_log = false;
                    self.log_regs_to_output();
                }
                // Check if pending condition eval needs this
                if self.pending_cond_eval.is_some() {
                    if let Some(ref mut pending) = self.pending_cond_eval {
                        pending.got_regs = true;
                    }
                    self.try_complete_cond_eval();
                }
            }

            AgentMessage::StackResult { count: _, frames } => {
                self.stack = frames;
            }

            AgentMessage::InspectResult { class, slot, fields } => {
                let cls = short_class(&class);
                self.log_info(&format!("Inspect v{} ({}): {} fields", slot, cls, fields.len()));
                for f in &fields {
                    let t = short_type(&f.field_type);
                    self.log_info(&format!("  {}: {} = {}", f.name, t, f.value));
                }
            }

            AgentMessage::EvalResult { expr, return_type, value } => {
                let t = commands::short_type(&return_type);
                self.log_info(&format!("{} -> ({}) {}", expr, t, value));
                // Update matching watch entry
                for watch in &mut self.watches {
                    if watch.expr == expr {
                        watch.last_value = Some(value.clone());
                        watch.last_type  = Some(return_type.clone());
                    }
                }
            }

            AgentMessage::HexdumpResult { slot, array_type, length, data_b64 } => {
                match BASE64.decode(&data_b64) {
                    Ok(bytes) => {
                        let t = commands::short_type(&array_type);
                        let max_rows = if self.hexdump_full { 32 } else { 16 };
                        let max_bytes = max_rows * 16;
                        let show_bytes = bytes.len().min(max_bytes);
                        self.log_info(&format!("Hexdump v{} ({}): {} bytes", slot, t, length));
                        format_hexdump(&bytes[..show_bytes], |line| self.log_info(line));
                        if show_bytes < bytes.len() {
                            let remaining = bytes.len() - show_bytes;
                            self.log_info(&format!("  ... {} more bytes (use 'hexdump v{} full' to show up to 512)", remaining, slot));
                        }
                        if (bytes.len() as i32) < length {
                            self.log_info(&format!("  (agent capped at {} of {} total bytes)", bytes.len(), length));
                        }
                    }
                    Err(e) => {
                        self.log_error(&format!("hexdump: base64 decode failed: {}", e));
                    }
                }
            }

            AgentMessage::HeapResult { class, total, reported, objects } => {
                let cls = short_class(&class);
                self.log_info(&format!("Heap {}: {} total, {} reported", cls, total, reported));
                // Populate heap browser
                self.heap_rows.clear();
                self.heap_scroll = 0;
                self.heap_selected = 0;
                self.heap_rows.push(HeapRow::Header(
                    format!("{}: {} total, {} shown", cls, total, reported)
                ));
                for obj in &objects {
                    self.heap_rows.push(HeapRow::Object {
                        index: obj.index,
                        value: obj.value.clone(),
                    });
                }
                self.right_tab = RightTab::Heap;
                self.tabbed_scroll = 0;
            }

            AgentMessage::HeapStringsResult { pattern, total_strings, matches, strings } => {
                self.log_info(&format!(
                    "Heap strings \"{}\": {} matches / {} scanned",
                    pattern, matches, total_strings
                ));
                // Populate heap browser
                self.heap_rows.clear();
                self.heap_scroll = 0;
                self.heap_selected = 0;
                self.heap_rows.push(HeapRow::Header(
                    format!("\"{}\"  - {} matches / {} scanned", pattern, matches, total_strings)
                ));
                for entry in &strings {
                    self.heap_rows.push(HeapRow::StringMatch {
                        index: entry.index,
                        value: entry.value.clone(),
                    });
                }
                self.right_tab = RightTab::Heap;
                self.tabbed_scroll = 0;
            }

            AgentMessage::MemDumpResult { addr, size, path, data_b64 } => {
                if let Some(p) = path {
                    self.log_info(&format!("[MEMDUMP] 0x{:x}  {} bytes  -> {}", addr, size, p));
                } else if let Some(b64) = data_b64 {
                    match BASE64.decode(&b64) {
                        Ok(bytes) => {
                            self.log_info(&format!("[MEMDUMP] 0x{:x}  {} bytes", addr, bytes.len()));
                            format_hexdump(&bytes, |line| self.log_info(line));
                        }
                        Err(e) => self.log_error(&format!("memdump: base64 decode failed: {}", e)),
                    }
                }
            }

            AgentMessage::DexLoaded { source, path, size, dex_b64 } => {
                let path_str = path.as_deref().unwrap_or("(memory)");
                self.log_info(&format!("[DEX] Received dynamic DEX: source={}, path={}, size={}",
                    source, path_str, size));
                match BASE64.decode(&dex_b64) {
                    Ok(bytes) => {
                        match crate::dex_parser::parse_dex_bytes(&bytes) {
                            Ok(new_dex) => {
                                let mut total_classes = 0;
                                let mut total_methods = 0;
                                let mut total_strings = 0;
                                for d in &new_dex {
                                    total_classes += d.class_defs.len();
                                    total_methods += d.methods.len();
                                    total_strings += d.strings.len();
                                }
                                let dex_count = new_dex.len();
                                for _d in &new_dex {
                                    self.dynamic_dex_count += 1;
                                    self.dex_labels.push(format!("dynamic-{}", self.dynamic_dex_count));
                                }
                                self.dex_data.extend(new_dex);
                                self.log_info(&format!(
                                    "[DEX] Dynamic DEX loaded ({}): {} file(s), {} classes, {} methods, {} strings",
                                    source, dex_count, total_classes, total_methods, total_strings
                                ));
                            }
                            Err(e) => {
                                self.log_error(&format!("[DEX] Failed to parse dynamic DEX: {}", e));
                            }
                        }
                    }
                    Err(e) => {
                        self.log_error(&format!("[DEX] base64 decode failed: {}", e));
                    }
                }
            }

            AgentMessage::CallEntry { seq, ts: _, thread, class, method, sig: _, args } => {
                let category = classify_call(&class);
                let depth = if self.trace_flat {
                    0
                } else {
                    let d = *self.trace_depth.get(&thread).unwrap_or(&0);
                    *self.trace_depth.entry(thread.clone()).or_insert(0) += 1;
                    d
                };
                let record = CallRecord {
                    seq,
                    thread,
                    class,
                    method,
                    args,
                    ret: None,
                    exception: false,
                    category,
                    depth,
                    is_exit: false,
                };
                // Save to file if active
                let short = short_class(&record.class);
                let args_str = if record.args.is_empty() {
                    String::new()
                } else {
                    record.args.join(", ")
                };
                if self.trace_save_active {
                    let entry_line = format!("{}.{}({})", short, record.method, args_str);
                    self.trace_write_line(&format!("[CALL] {}", entry_line));
                }

                self.call_records.push(record);
                // Ring buffer: max 10000 records
                if self.call_records.len() > 10000 {
                    self.call_records.drain(0..self.call_records.len() - 10000);
                }
                self.trace_auto_scroll = true;
            }

            AgentMessage::CallExit { thread, class, method, ret, exception } => {
                if !self.trace_flat {
                    // Decrement depth
                    if let Some(d) = self.trace_depth.get_mut(&thread) {
                        *d = d.saturating_sub(1);
                    }

                    if !self.trace_onenter {
                        let depth = *self.trace_depth.get(&thread).unwrap_or(&0);
                        // Add exit record to trace
                        let category = classify_call(&class);
                        let exit_record = CallRecord {
                            seq: -1,
                            thread: thread.clone(),
                            class: class.clone(),
                            method: method.clone(),
                            args: Vec::new(),
                            ret: ret.clone(),
                            exception,
                            category,
                            depth,
                            is_exit: true,
                        };
                        self.call_records.push(exit_record);
                    }
                }

                // Match to most recent entry by class+method+thread (backwards search)
                if let Some(pos) = self.call_records.iter().rposition(|r| {
                    r.class == class && r.method == method && r.thread == thread && r.ret.is_none() && !r.is_exit
                }) {
                    self.call_records[pos].ret = ret.clone();
                    self.call_records[pos].exception = exception;
                }

                if !self.trace_onenter {
                    // Save to file if active
                    if self.trace_save_active {
                        let short = short_class(&class);
                        if exception {
                            self.trace_write_line(&format!("[RET]  {}.{} !EXCEPTION", short, method));
                        } else if let Some(rv) = &ret {
                            self.trace_write_line(&format!("[RET]  {}.{} -> {}", short, method, rv));
                        }
                    }
                }

                // Ring buffer
                if self.call_records.len() > 10000 {
                    self.call_records.drain(0..self.call_records.len() - 10000);
                }
                self.trace_auto_scroll = true;
            }

            AgentMessage::JniMonitorStarted {} => {
                self.jni_monitoring = true;
                self.left_tab = LeftTab::JniMonitor;
                self.log_info("JNI monitor started - watching RegisterNatives");
            }

            AgentMessage::JniMonitorStopped { count } => {
                self.jni_monitoring = false;
                self.log_info(&format!("JNI monitor stopped ({} bindings captured)", count));
            }

            AgentMessage::JniRegisterNative { class_sig, method_name, method_sig, native_addr, lib_name, lib_offset } => {
                // Update existing entry or append
                let key_match = self.jni_natives.iter().position(|e| {
                    e.class_sig == class_sig && e.method_name == method_name && e.method_sig == method_sig
                });
                if let Some(idx) = key_match {
                    // Update address in case it changed (re-registration)
                    self.jni_natives[idx].native_addr = native_addr;
                    self.jni_natives[idx].lib_name    = lib_name;
                    self.jni_natives[idx].lib_offset  = lib_offset;
                } else {
                    self.jni_natives.push(JniNativeEntry {
                        class_sig, method_name, method_sig,
                        native_addr, lib_name, lib_offset,
                        redirected: false, redirect_action: None,
                    });
                }
            }

            AgentMessage::JniRedirectOk { class_sig, method_name, method_sig } => {
                if let Some(e) = self.jni_natives.iter_mut().find(|e| {
                    e.class_sig == class_sig && e.method_name == method_name && e.method_sig == method_sig
                }) {
                    e.redirected = true;
                }
                self.log_info(&format!("JNI redirect installed: {}.{}", class_sig, method_name));
            }

            AgentMessage::JniRedirectCleared { class_sig, method_name, method_sig } => {
                if let Some(e) = self.jni_natives.iter_mut().find(|e| {
                    e.class_sig == class_sig && e.method_name == method_name && e.method_sig == method_sig
                }) {
                    e.redirected = false;
                    e.redirect_action = None;
                }
                self.log_info(&format!("JNI redirect cleared: {}.{}", class_sig, method_name));
            }

            AgentMessage::RecordStarted {} => {
                self.recording_active = true;
                self.left_tab = LeftTab::Trace;
                self.log_info("Call recording started");
            }

            AgentMessage::RecordStopped { total } => {
                self.recording_active = false;
                self.log_info(&format!("Call recording stopped ({} calls)", total));
            }

            AgentMessage::CallOverflow { dropped, window_ms } => {
                self.log_error(&format!("Call overflow: {} dropped in {}ms window (rate limit)", dropped, window_ms));
            }

            AgentMessage::Error { msg } => {
                self.log_error(&format!("Agent error: {}", msg));
                // If a follow-invoke dis failed, restore previous view
                if self.pending_follow {
                    self.pending_follow = false;
                    self.nav_back();
                }
                // If a bp_set failed, discard pending conditions
                if msg.contains("bp_set failed") || msg.contains("bp_set:") {
                    if self.pending_bp_cond.is_some() {
                        self.pending_bp_cond = None;
                    } else if !self.pending_bp_conditions.is_empty() {
                        self.pending_bp_conditions.pop_front();
                    }
                    if self.pending_anti_count > 0 {
                        self.pending_anti_count -= 1;
                    }
                }
                // If waiting for condition eval and got an error (e.g. locals/regs failed),
                // mark as received so we can still evaluate with whatever data we have
                if self.pending_cond_eval.is_some() {
                    if let Some(ref mut pending) = self.pending_cond_eval {
                        if !pending.got_locals { pending.got_locals = true; }
                        else if !pending.got_regs { pending.got_regs = true; }
                    }
                    self.try_complete_cond_eval();
                }
            }

            AgentMessage::TmClasses { classes } => {
                if classes.is_empty() {
                    self.log_info("[bypass-ssl] SSLContext.init: TrustManager[] is null/empty (system default - no custom pinning here)");
                } else {
                    let mut patched = 0;
                    for class_sig in &classes {
                        // Skip framework classes already handled by the auto-bypass bps
                        if class_sig.contains("conscrypt") || class_sig.contains("NetworkSecurity") {
                            continue;
                        }
                        self.log_info(&format!("[bypass-ssl] Found TrustManager: {} - patching checkServerTrusted...", class_sig));
                        let args = format!("{} checkServerTrusted void", class_sig);
                        self.do_patch(&args);
                        patched += 1;
                    }
                    if patched == 0 {
                        self.log_info("[bypass-ssl] SSLContext.init: all TrustManagers are framework classes (already bypassed)");
                    }
                }
                self.send_command(OutboundCommand::Continue {});
            }

            AgentMessage::RedefineOk { class_sig } => {
                self.log_info(&format!("[PATCH] RedefineClasses OK: {}", class_sig));
                // JVMTI spec: RedefineClasses clears all breakpoints in the redefined class.
                // Re-set them so they remain active, preserving any conditions.
                let to_restore: Vec<(String, String, i64, i32)> = self.bp_manager.breakpoints.iter()
                    .filter(|bp| bp.class == class_sig)
                    .map(|bp| (bp.class.clone(), bp.method.clone(), bp.location, bp.id))
                    .collect();
                for (class, method, location, old_id) in &to_restore {
                    let cond = self.bp_manager.get_condition(*old_id).cloned();
                    self.redefine_restore.push((class.clone(), method.clone(), *location, cond));
                    self.bp_manager.remove(*old_id);
                    self.send_command(OutboundCommand::BpSet {
                        class: class.clone(),
                        method: method.clone(),
                        sig: None,
                        location: Some(*location),
                    });
                }
            }

            AgentMessage::RedefineError { class_sig, err } => {
                let desc = match err {
                    19 => "JVMTI_ERROR_UNMODIFIABLE_CLASS",
                    40 => "JVMTI_ERROR_UNSUPPORTED_OPERATION",
                    62 => "JVMTI_ERROR_FAILS_VERIFICATION",
                    79 => "JVMTI_ERROR_NAMES_DONT_MATCH",
                    _ => "JVMTI_ERROR",
                };
                let hint = if err == 62 {
                    " (ART rejected patched DEX - try a different target BCI)"
                } else {
                    ""
                };
                self.log_error(&format!("[PATCH] RedefineClasses failed for {}: {} (err={}){}", class_sig, desc, err, hint));
            }

            AgentMessage::Exception {
                exception_class, message, class, method, location,
                caught, catch_class, catch_method,
            } => {
                let exc = short_class(&exception_class);
                let cls = short_class(&class);
                let caught_str = if caught {
                    if let (Some(cc), Some(cm)) = (&catch_class, &catch_method) {
                        format!(" caught in {}.{}", short_class(cc), cm)
                    } else {
                        " (caught)".into()
                    }
                } else {
                    " (uncaught)".into()
                };
                self.log_exception(&format!("{}: \"{}\" in {}.{} @{}{}",
                    exc, message, cls, method, location, caught_str));
            }

        }
    }

    // -------------------------------------------------------------------
    // Auto-refresh: on suspend, send dis + locals + stack
    // -------------------------------------------------------------------

    fn auto_refresh(&mut self) {
        self.bytecodes_auto_scroll = true;
        // Skip dis/locals/regs for native methods (location == -1)
        let is_native = self.current_loc == Some(-1);
        if !is_native {
            if let (Some(cls), Some(meth)) = (&self.current_class, &self.current_method) {
                self.send_command(OutboundCommand::Dis {
                    class: cls.clone(),
                    method: meth.clone(),
                    sig: None,
                });
            }
            self.send_command(OutboundCommand::Locals {});
            self.send_command(OutboundCommand::Regs {});
        } else {
            // Clear stale bytecodes from the previous Java frame so the panel
            // reflects the current state (native method, no bytecodes to show).
            self.bytecodes.clear();
            self.bytecodes_scroll = 0;
            self.bytecodes_cursor = None;
            self.locals.clear();
            self.regs.clear();
        }
        self.send_command(OutboundCommand::Stack {});
        self.send_command(OutboundCommand::Threads {});
        // Re-evaluate all eval-based watches (name/slot watches update via LocalsResult)
        let eval_exprs: Vec<String> = self.watches.iter()
            .filter(|w| w.expr.contains('.') || w.expr.contains('('))
            .map(|w| w.expr.clone())
            .collect();
        for expr in eval_exprs {
            self.send_command(OutboundCommand::Eval { expr, depth: None });
        }
    }

    /// Update watches that reference a local by name ("key") or slot ("v3").
    /// Called from LocalsResult handler and when a new watch is added while suspended.
    fn refresh_watches_from_locals(&mut self) {
        // Snapshot locals to avoid borrow conflict with self.watches
        let snapshot: Vec<(i32, String, String, String)> = self.locals.iter()
            .map(|l| (l.slot, l.name.clone(), l.value.clone(), l.var_type.clone()))
            .collect();
        for watch in &mut self.watches {
            if watch.expr.contains('.') || watch.expr.contains('(') {
                continue; // eval-based, handled by EvalResult
            }
            let slot_from_expr = watch.expr.strip_prefix('v')
                .and_then(|s| s.parse::<i32>().ok());
            if let Some((_, _, value, ty)) = snapshot.iter().find(|(slot, name, _, _)| {
                *name == watch.expr || slot_from_expr == Some(*slot)
            }) {
                watch.last_value = Some(value.clone());
                watch.last_type  = Some(ty.clone());
            }
        }
    }

    /// Send dis + stack commands only (locals/regs already received during condition eval).
    fn send_dis_and_stack(&mut self) {
        self.bytecodes_auto_scroll = true;
        let is_native = self.current_loc == Some(-1);
        if !is_native {
            if let (Some(cls), Some(meth)) = (&self.current_class, &self.current_method) {
                self.send_command(OutboundCommand::Dis {
                    class: cls.clone(),
                    method: meth.clone(),
                    sig: None,
                });
            }
        } else {
            self.bytecodes.clear();
            self.bytecodes_scroll = 0;
            self.bytecodes_cursor = None;
        }
        self.send_command(OutboundCommand::Stack {});
    }

    /// Try to complete a pending conditional breakpoint evaluation.
    /// Called when LocalsResult or RegsResult arrives.
    fn try_complete_cond_eval(&mut self) {
        let pending = match &self.pending_cond_eval {
            Some(p) => p,
            None => return,
        };

        // Wait until we have both locals and regs
        if !pending.got_locals || !pending.got_regs {
            return;
        }

        // Take ownership of pending state
        let pending = self.pending_cond_eval.take().unwrap();
        let cls = short_class(&pending.class);

        // Get the condition
        let cond = match self.bp_manager.get_condition(pending.bp_id) {
            Some(c) => c.clone(),
            None => {
                // Condition was removed while waiting  - just suspend normally
                self.state = AppState::Suspended;
                let line_str = if pending.line >= 0 { format!(":{}", pending.line) } else { String::new() };
                self.log_info(&format!("Breakpoint #{} hit: {}.{}{} @{:04x}",
                    pending.bp_id, cls, pending.method, line_str, pending.location));
                self.send_dis_and_stack();
                return;
            }
        };

        // Evaluate variable condition
        if let Some(ref expr) = cond.var_condition {
            // Log available data for debugging
            let locals_summary: Vec<String> = self.locals.iter()
                .map(|l| format!("{}={}", l.name, l.value))
                .collect();
            self.log_debug(&format!("BP#{} evaluating: {} (locals: [{}], regs: {} slots)",
                pending.bp_id, expr,
                locals_summary.join(", "),
                self.regs.len()));
            let result = condition::evaluate_var_condition(expr, &self.locals, &self.regs);
            if !result {
                self.log_debug(&format!("BP#{} condition not met, auto-continuing: {}.{}",
                    pending.bp_id, cls, pending.method));
                self.send_command(OutboundCommand::Continue {});
                return;
            }
        }

        // Condition passed  - normal suspend flow
        self.state = AppState::Suspended;
        let line_str = if pending.line >= 0 { format!(":{}", pending.line) } else { String::new() };
        self.log_info(&format!("Breakpoint #{} hit: {}.{}{} @{:04x} (condition met)",
            pending.bp_id, cls, pending.method, line_str, pending.location));
        // Already have locals/regs, just need dis + stack
        self.send_dis_and_stack();

        // Auto-dump DEX when hitting DexClassLoader/InMemoryDexClassLoader breakpoints
        if pending.class.contains("DexClassLoader") || pending.class.contains("InMemoryDexClassLoader") {
            self.log_info("[DEX] Auto-dumping DEX from DexClassLoader...");
            self.send_command(OutboundCommand::DexDump {});
        }
    }

    // -------------------------------------------------------------------
    // Keyboard input handling
    // -------------------------------------------------------------------

    // -------------------------------------------------------------------
    // Mouse event handling
    // -------------------------------------------------------------------

    fn handle_mouse(&mut self, mouse: MouseEvent) {
        let col = mouse.column;
        let row = mouse.row;

        match mouse.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                // Context menu click handling (must be first).
                // Use the same clamping logic as the renderer so that menus near
                // screen edges (e.g. command area at the bottom) hit-test correctly.
                if let Some(menu) = &self.context_menu {
                    let max_item = menu.items.iter().map(|s| s.len()).max().unwrap_or(14);
                    let menu_w = (max_item as u16 + 4).max(18);
                    let menu_h = menu.items.len() as u16 + 2;
                    let (total_w, total_h) = self.layout_geom.as_ref()
                        .map(|g| (g.total_width, g.total_height))
                        .unwrap_or((200, 50));
                    let mx = menu.x.min(total_w.saturating_sub(menu_w));
                    let my = menu.y.min(total_h.saturating_sub(menu_h));
                    let items_y_start = my + 1;
                    let items_y_end   = my + 1 + menu.items.len() as u16;
                    if col >= mx && col < mx + menu_w
                        && row >= items_y_start && row < items_y_end
                    {
                        let item_idx = (row - items_y_start) as usize;
                        self.handle_context_menu_click(item_idx);
                    } else {
                        self.context_menu = None;
                    }
                    return;
                }

                if let Some(geom) = &self.layout_geom {
                    // 1. Status bar button click
                    if let Some(action) = statusbar::get_clicked_action(col, row, geom.statusbar_area, self) {
                        self.handle_statusbar_action(action);
                        return;
                    }

                    let ba = geom.bytecodes_area;
                    let la = geom.locals_area;
                    let ta = geom.tabbed_area;
                    let lga = geom.log_area;
                    let ca = geom.command_area;

                    // 2. Title bar tab clicks (must be before drag borders,
                    //    since tabbed title row == right_hsplit_y)
                    if row == ba.y && col > ba.x && col < ba.x + ba.width {
                        self.focus = 0;
                        self.command_focused = false;
                        self.handle_title_tab_click(col, ba.x, 0);
                        return;
                    }
                    if row == la.y && col > la.x && col < la.x + la.width {
                        self.focus = 1;
                        self.command_focused = false;
                        self.handle_title_tab_click(col, la.x, 1);
                        return;
                    }
                    if row == ta.y && col > ta.x && col < ta.x + ta.width {
                        self.focus = 2;
                        self.command_focused = false;
                        self.handle_title_tab_click(col, ta.x, 2);
                        return;
                    }

                    // 3. Draggable borders
                    const TOLERANCE: u16 = 1;

                    if col.abs_diff(geom.vsplit_x) <= TOLERANCE
                        && row >= geom.vsplit_y_start
                        && row < geom.vsplit_y_end
                    {
                        self.drag = DragTarget::VerticalSplit;
                        return;
                    }

                    // Only extend tolerance upward so row = hsplit_y + 1 (first log
                    // content row) is never intercepted as a drag start.
                    if row <= geom.hsplit_y
                        && geom.hsplit_y.saturating_sub(row) <= TOLERANCE
                        && col >= geom.hsplit_x_start
                        && col < geom.hsplit_x_end
                    {
                        self.drag = DragTarget::HorizontalSplit;
                        return;
                    }

                    // For the right panel split, only extend tolerance upward (not downward),
                    // so row = right_hsplit_y + 1 (first content row of tabbed panel) is
                    // never intercepted as a drag start.
                    if row <= geom.right_hsplit_y
                        && geom.right_hsplit_y.saturating_sub(row) <= TOLERANCE
                        && col >= geom.right_hsplit_x_start
                        && col < geom.right_hsplit_x_end
                    {
                        self.drag = DragTarget::RightHorizontalSplit;
                        return;
                    }

                    // 4. Panel body click  - focus + cursor selection
                    if in_rect(col, row, ba) {
                        self.focus = 0;
                        self.command_focused = false;

                        // Click in bytecodes panel: select instruction
                        if self.left_tab == LeftTab::Bytecodes && !self.bytecodes.is_empty() {
                            let inner_y = (row.saturating_sub(ba.y + 1)) as usize;
                            if inner_y > 0 { // skip header line
                                let scroll = self.effective_bytecodes_scroll(ba.height);
                                let bc_idx = scroll + (inner_y - 1);
                                if bc_idx < self.bytecodes.len() {
                                    // Double-click detection (same row, within 500ms)
                                    let now = std::time::Instant::now();
                                    let elapsed = now.duration_since(self.last_click_time);
                                    let same_row = self.last_click_pos.1 == row;
                                    self.last_click_time = now;
                                    self.last_click_pos = (col, row);

                                    let click_col = col.saturating_sub(ba.x + 1) as usize;
                                    if elapsed.as_millis() < 500 && same_row {
                                        // Double-click: follow invoke method
                                        self.bytecodes_cursor = Some(bc_idx);
                                        self.bytecodes_sel_anchor = None;
                                        self.bytecodes_sel_head = None;
                                        self.follow_at_cursor();
                                    } else {
                                        self.bytecodes_cursor = Some(bc_idx);
                                        // Extract word under cursor for highlight
                                        if let Some(instr) = self.bytecodes.get(bc_idx) {
                                            // Build display line matching render: "  XXXX: text"
                                            let display = format!("  {:04x}: {}", instr.offset, instr.text);
                                            self.bytecodes_highlight = word_at_col(&display, click_col)
                                                .map(|w| w.to_string());
                                        }
                                        // Start selection drag
                                        self.bytecodes_sel_anchor = Some((bc_idx, click_col));
                                        self.bytecodes_sel_head = Some((bc_idx, click_col));
                                        self.drag = DragTarget::BytecodesArea;
                                    }
                                }
                            }
                        }
                    } else if in_rect(col, row, la) {
                        self.focus = 1;
                        self.command_focused = false;
                    } else if in_rect(col, row, ta) {
                        self.focus = 2;
                        self.command_focused = false;
                        // Double-click on Stack/BP/Bookmarks rows: navigate to that location
                        // Guard: row > ta.y skips the title border row, preventing it from
                        // poisoning last_click_pos and breaking double-click on the first row.
                        if row > ta.y
                            && (self.right_tab == RightTab::Stack
                                || self.right_tab == RightTab::Breakpoints
                                || self.right_tab == RightTab::Bookmarks)
                        {
                            // row - (ta.y + 1) gives 0-based index into visible content
                            let inner_y = (row - (ta.y + 1)) as usize;
                            let row_idx = self.tabbed_scroll + inner_y;
                            let now = std::time::Instant::now();
                            let elapsed = now.duration_since(self.last_click_time);
                            let same_row = self.last_click_pos.1 == row;
                            self.last_click_time = now;
                            self.last_click_pos = (col, row);
                            // Single click: move bookmarks cursor
                            if self.right_tab == RightTab::Bookmarks {
                                if row_idx < self.bookmarks.len() {
                                    self.bookmarks_cursor = row_idx;
                                }
                            }
                            // Double click: navigate
                            if elapsed.as_millis() < 500 && same_row {
                                if self.right_tab == RightTab::Stack {
                                    if let Some(frame) = self.stack.get(row_idx) {
                                        let cls = frame.class.clone();
                                        let meth = frame.method.clone();
                                        let loc = frame.location;
                                        self.navigate_to_method(&cls, &meth, Some(loc));
                                    }
                                } else if self.right_tab == RightTab::Breakpoints {
                                    if let Some(bp) = self.bp_manager.breakpoints.get(row_idx) {
                                        let cls = bp.class.clone();
                                        let meth = bp.method.clone();
                                        let loc = bp.location;
                                        self.navigate_to_method(&cls, &meth, Some(loc));
                                    }
                                } else if self.right_tab == RightTab::Bookmarks {
                                    if let Some(bm) = self.bookmarks.get(row_idx) {
                                        let cls = bm.class.clone();
                                        let meth = bm.method.clone();
                                        let offset = bm.offset;
                                        self.navigate_to_method(&cls, &meth, Some(offset));
                                    }
                                }
                            }
                        }
                    } else if in_rect(col, row, lga) {
                        self.focus = 3;
                        self.command_focused = false;
                        // Start a new selection on click inside the content area.
                        if row > lga.y && row < lga.y + lga.height.saturating_sub(1)
                            && !self.log.is_empty()
                        {
                            let inner_y = (row - lga.y - 1) as usize;
                            let inner_height = lga.height.saturating_sub(2) as usize;
                            let total = self.log.len();
                            let scroll = if self.log_auto_scroll {
                                total.saturating_sub(inner_height)
                            } else {
                                self.log_scroll
                            };
                            let log_idx = (scroll + inner_y).min(total.saturating_sub(1));
                            let click_c = col.saturating_sub(lga.x + 1) as usize;
                            self.log_sel_anchor = Some((log_idx, click_c));
                            self.log_sel_head = Some((log_idx, click_c));
                            self.drag = DragTarget::LogArea;
                        } else {
                            self.log_sel_anchor = None;
                            self.log_sel_head = None;
                        }
                    } else if in_rect(col, row, ca) {
                        self.focus = 4;
                        self.command_focused = true;
                        // Position cursor at click column. " > " prefix is 3 chars after the
                        // left border, so text starts at ca.x + 1 + 3 = ca.x + 4.
                        let text_col = col.saturating_sub(ca.x + 4) as usize;
                        let input = self.command_input.clone();
                        self.command_cursor = Self::col_to_cmd_byte(&input, text_col);
                        self.command_sel_anchor = None;
                        self.drag = DragTarget::CommandArea;
                    }
                }
            }

            MouseEventKind::Drag(MouseButton::Left) => {
                if let Some(geom) = &self.layout_geom {
                    match self.drag {
                        DragTarget::VerticalSplit => {
                            if geom.total_width > 0 {
                                self.split_h = (col as f32) / (geom.total_width as f32);
                                self.split_h = self.split_h.clamp(0.15, 0.85);
                            }
                        }
                        DragTarget::HorizontalSplit => {
                            let available_h = geom.total_height.saturating_sub(2);
                            if available_h > 0 {
                                self.split_v = (row as f32) / (available_h as f32);
                                self.split_v = self.split_v.clamp(0.15, 0.85);
                            }
                        }
                        DragTarget::RightHorizontalSplit => {
                            // Row relative to the top of the top panels area
                            let top_start = geom.vsplit_y_start;
                            let top_h = geom.hsplit_y.saturating_sub(top_start);
                            if top_h > 0 {
                                let rel = row.saturating_sub(top_start) as f32;
                                self.split_right_v = rel / (top_h as f32);
                                self.split_right_v = self.split_right_v.clamp(0.15, 0.85);
                            }
                        }
                        DragTarget::CommandArea => {
                            // Extend selection to current drag column
                            let ca = geom.command_area;
                            let text_col = col.saturating_sub(ca.x + 4) as usize;
                            let input = self.command_input.clone();
                            let byte_off = Self::col_to_cmd_byte(&input, text_col);
                            // Anchor was set to cursor position at the initial Down event
                            if self.command_sel_anchor.is_none() {
                                self.command_sel_anchor = Some(self.command_cursor);
                            }
                            self.command_cursor = byte_off;
                        }
                        DragTarget::BytecodesArea => {
                            let ba = geom.bytecodes_area;
                            if row > ba.y && row < ba.y + ba.height.saturating_sub(1)
                                && !self.bytecodes.is_empty()
                            {
                                let inner_y = (row.saturating_sub(ba.y + 1)) as usize;
                                if inner_y > 0 {
                                    let scroll = self.effective_bytecodes_scroll(ba.height);
                                    let bc_idx = (scroll + (inner_y - 1))
                                        .min(self.bytecodes.len().saturating_sub(1));
                                    let drag_c = col.saturating_sub(ba.x + 1) as usize;
                                    self.bytecodes_sel_head = Some((bc_idx, drag_c));
                                }
                            }
                        }
                        DragTarget::LogArea => {
                            let lga = geom.log_area;
                            if row > lga.y && row < lga.y + lga.height.saturating_sub(1)
                                && !self.log.is_empty()
                            {
                                let inner_y = (row - lga.y - 1) as usize;
                                let inner_height = lga.height.saturating_sub(2) as usize;
                                let total = self.log.len();
                                let scroll = if self.log_auto_scroll {
                                    total.saturating_sub(inner_height)
                                } else {
                                    self.log_scroll
                                };
                                let log_idx = (scroll + inner_y).min(total.saturating_sub(1));
                                let drag_c = col.saturating_sub(lga.x + 1) as usize;
                                self.log_sel_head = Some((log_idx, drag_c));
                            }
                        }
                        DragTarget::None => {}
                    }
                }
            }

            MouseEventKind::Up(MouseButton::Left) => {
                self.drag = DragTarget::None;
            }

            MouseEventKind::Down(MouseButton::Right) => {
                if let Some(geom) = &self.layout_geom {
                    let ba = geom.bytecodes_area;
                    let lga = geom.log_area;

                    // Right-click in Bytecodes/Decompiler panel (left panel)
                    if (self.left_tab == LeftTab::Bytecodes || self.left_tab == LeftTab::Decompiler)
                        && col > ba.x && col < ba.x + ba.width.saturating_sub(1)
                        && row > ba.y && row < ba.y + ba.height.saturating_sub(1)
                    {
                        let inner_y = (row - ba.y - 1) as usize;
                        let inner_height = ba.height.saturating_sub(2) as usize;
                        let code_height = inner_height.saturating_sub(1); // header line
                        if inner_y == 0 {
                            // Right-click on header line: copy class/method symbol
                            let click_c = col.saturating_sub(ba.x + 1) as usize;
                            let short = self.current_class.as_deref()
                                .map(|s| crate::commands::short_class(s).to_string())
                                .unwrap_or_else(|| "?".to_string());
                            let meth = self.current_method.as_deref().unwrap_or("?");
                            self.context_menu = Some(ContextMenu {
                                x: col,
                                y: row,
                                items: vec![
                                    format!("  Copy: {}.{}", short, meth),
                                    "  Copy: class sig ".into(),
                                ],
                                selected: 0,
                                source: ContextMenuSource::Bytecodes,
                                line_idx: usize::MAX, // sentinel: header menu
                                click_col: click_c,
                                keyboard_navigable: false,
                            });
                            self.focus = 0;
                            self.command_focused = false;
                        } else if inner_y <= code_height {
                            let scroll = if self.bytecodes_auto_scroll {
                                let current_idx = self.current_loc.and_then(|loc| {
                                    self.bytecodes.iter().position(|i| i.offset == loc as u32)
                                });
                                if let Some(idx) = current_idx {
                                    idx.saturating_sub(2)
                                } else {
                                    self.bytecodes_scroll
                                }
                            } else {
                                self.bytecodes_scroll
                            };
                            let bc_idx = scroll + (inner_y - 1);
                            let click_c = col.saturating_sub(ba.x + 1) as usize;

                            // Build dynamic "Copy: word" label
                            let word_label = self.bytecodes.get(bc_idx)
                                .map(|i| format!("  {:04x}: {}", i.offset, i.text))
                                .and_then(|line| word_at_col(&line, click_c).map(|w| w.to_string()))
                                .map(|w| copy_word_label(&w))
                                .unwrap_or_else(|| "  Copy Word    ".into());

                            let mut items: Vec<String> = Vec::new();
                            if self.bytecodes_has_selection() {
                                items.push("  Copy Sel     ".into());
                            }
                            items.push("  Copy Line    ".into());
                            items.push("  Copy View    ".into());
                            items.push(word_label);
                            if self.state == AppState::Suspended && self.cap_force_early_return {
                                items.push("─────────────".into());
                                items.push("  Return true  ".into());
                                items.push("  Return false ".into());
                            }
                            if self.current_class.is_some() && self.current_method.is_some() {
                                items.push("─────────────".into());
                                items.push("  Patch method ".into());
                            }
                            // Jump flip: offer only the opposite of the current branch state
                            if self.state == AppState::Suspended {
                                if let Some(instr) = self.bytecodes.get(bc_idx) {
                                    let at_pc = self.current_loc
                                        .map(|loc| loc as u32 == instr.offset)
                                        .unwrap_or(false);
                                    if at_pc {
                                        if let Some((slot, _, _, ref target)) = parse_cond_jump(&instr.text) {
                                            let currently_taken = instr.branch.as_ref().and_then(|meta| {
                                                disassembler::eval_branch(meta, &|reg| {
                                                    self.regs.iter().find(|r| r.slot == reg as i32).map(|r| r.value)
                                                })
                                            });
                                            items.push("─────────────".into());
                                            match currently_taken {
                                                Some(true)  => items.push("  Jump not taken   ".into()),
                                                Some(false) => items.push(format!("  Jump taken  >{}", target)),
                                                None => {
                                                    // regs not yet available — show both
                                                    items.push(format!("  Jump taken  >{}", target));
                                                    items.push("  Jump not taken   ".into());
                                                }
                                            }
                                            let _ = slot; // used in handler
                                        }
                                    }
                                }
                            }
                            // Show "Jump to PC" when user has scrolled away from current PC
                            if self.current_loc.is_some() && !self.bytecodes_auto_scroll {
                                let pc_visible = self.current_loc
                                    .and_then(|loc| self.bytecodes.iter().position(|i| i.offset == loc as u32))
                                    .map(|idx| idx >= scroll && idx < scroll + code_height)
                                    .unwrap_or(false);
                                if !pc_visible {
                                    items.push("─────────────".into());
                                    items.push("  Jump to PC  ".into());
                                }
                            }
                            // "Rename X" — class under cursor or current class
                            {
                                let sig = self.class_at_bc_idx(bc_idx)
                                    .or_else(|| self.current_class.clone());
                                if let Some(ref sig) = sig {
                                    let name = crate::commands::short_class(sig);
                                    let label = if name.len() > 16 { &name[..16] } else { name };
                                    items.push("─────────────".into());
                                    items.push(format!("  Rename {}", label));
                                }
                            }
                            self.context_menu = Some(ContextMenu {
                                x: col,
                                y: row,
                                items,
                                selected: 0,
                                source: ContextMenuSource::Bytecodes,
                                line_idx: bc_idx,
                                click_col: click_c,
                                keyboard_navigable: false,
                            });
                            self.focus = 0;
                            self.command_focused = false;
                        }
                    }
                    // Right-click in Trace panel (left panel when Trace tab active)
                    else if self.left_tab == LeftTab::Trace
                        && col > ba.x && col < ba.x + ba.width.saturating_sub(1)
                        && row > ba.y && row < ba.y + ba.height.saturating_sub(1)
                    {
                        let inner_y = (row - ba.y - 1) as usize;
                        let inner_height = ba.height.saturating_sub(2) as usize;
                        let code_height = inner_height.saturating_sub(1); // header line
                        if inner_y > 0 && inner_y <= code_height {
                            let scroll = if self.trace_auto_scroll {
                                self.call_records.len().saturating_sub(code_height)
                            } else {
                                self.trace_scroll
                            };
                            let trace_idx = scroll + (inner_y - 1);
                            let click_c = col.saturating_sub(ba.x + 1) as usize;

                            let save_label = if self.trace_save_active {
                                "  [x] Save trace"
                            } else {
                                "  [ ] Save trace"
                            };

                            let word_label = self.call_records.get(trace_idx)
                                .map(|r| format_call_record(r))
                                .and_then(|line| word_at_col(&line, click_c).map(|w| w.to_string()))
                                .map(|w| copy_word_label(&w))
                                .unwrap_or_else(|| "  Copy Word    ".into());

                            let line_text = self.call_records.get(trace_idx)
                                .map(|r| format_call_record(r))
                                .unwrap_or_default();

                            let mut trace_items: Vec<String> = vec![
                                "  Copy Line    ".into(),
                                "  Copy View    ".into(),
                                word_label,
                                save_label.into(),
                                "  Clear Trace  ".into(),
                            ];
                            if line_text.len() > 120 {
                                trace_items.push("  Split to Log ".into());
                            }

                            self.context_menu = Some(ContextMenu {
                                x: col,
                                y: row,
                                items: trace_items,
                                selected: 0,
                                source: ContextMenuSource::Trace,
                                line_idx: trace_idx,
                                click_col: click_c,
                                keyboard_navigable: false,
                            });
                            self.focus = 0;
                            self.command_focused = false;
                        }
                    }
                    // Right-click in AI panel (left panel when AI tab active)
                    else if self.left_tab == LeftTab::Ai
                        && col > ba.x && col < ba.x + ba.width.saturating_sub(1)
                        && row > ba.y && row < ba.y + ba.height.saturating_sub(1)
                    {
                        let inner_y = (row - ba.y - 1) as usize;
                        let inner_height = ba.height.saturating_sub(2) as usize;
                        if inner_y < inner_height {
                            let scroll = if self.ai_auto_scroll {
                                self.ai_output.len().saturating_sub(inner_height)
                            } else {
                                self.ai_scroll
                            };
                            let ai_idx = scroll + inner_y;
                            let click_c = col.saturating_sub(ba.x + 1) as usize;

                            let word_label = self.ai_output.get(ai_idx)
                                .and_then(|l| word_at_col(&l.text, click_c).map(|w| w.to_string()))
                                .map(|w| copy_word_label(&w))
                                .unwrap_or_else(|| "  Copy Word    ".into());

                            self.context_menu = Some(ContextMenu {
                                x: col,
                                y: row,
                                items: vec![
                                    "  Copy Line    ".into(),
                                    "  Copy View    ".into(),
                                    word_label,
                                    "  Copy All     ".into(),
                                    "  Save to File ".into(),
                                ],
                                selected: 0,
                                source: ContextMenuSource::Ai,
                                line_idx: ai_idx,
                                click_col: click_c,
                                keyboard_navigable: false,
                            });
                            self.focus = 0;
                            self.command_focused = false;
                        }
                    }
                    // Right-click in JNI Monitor panel
                    else if self.left_tab == LeftTab::JniMonitor
                        && col > ba.x && col < ba.x + ba.width.saturating_sub(1)
                        && row > ba.y && row < ba.y + ba.height.saturating_sub(1)
                    {
                        let inner_y = (row - ba.y - 1) as usize;
                        let inner_height = ba.height.saturating_sub(2) as usize;
                        let list_height = inner_height.saturating_sub(1); // subtract header row
                        let monitor_label = if self.jni_monitoring {
                            "  Stop monitoring   "
                        } else {
                            "  Start monitoring  "
                        };
                        let mut entry_menu = false;
                        if inner_y > 0 && inner_y <= list_height && !self.jni_natives.is_empty() {
                            let scroll = self.jni_monitor_scroll.min(
                                self.jni_natives.len().saturating_sub(1)
                            );
                            let jni_idx = scroll + (inner_y - 1);
                            if let Some(entry) = self.jni_natives.get(jni_idx) {
                                entry_menu = true;
                                let already_redirected = entry.redirected;
                                let readable = crate::tui::bytecodes::demangle_jni_sig(
                                    &entry.method_name, &entry.method_sig,
                                );
                                let short_class = {
                                    let inner = entry.class_sig.trim_start_matches('L').trim_end_matches(';');
                                    inner.split('/').last().unwrap_or(inner).to_string()
                                };
                                let fn_label_full = format!("  {}.{}", short_class, readable);
                                let fn_label = if fn_label_full.len() > 34 {
                                    format!("{}…", &fn_label_full[..33])
                                } else {
                                    fn_label_full
                                };
                                let mut items: Vec<String> = vec![
                                    fn_label,
                                    "─────────────────────".into(),
                                    "  Redirect: block   ".into(),
                                    "  Redirect: true    ".into(),
                                    "  Redirect: false   ".into(),
                                    "  Redirect: 0       ".into(),
                                    "─────────────────────".into(),
                                    "  Copy address      ".into(),
                                    "  Copy class sig    ".into(),
                                    "─────────────────────".into(),
                                    monitor_label.into(),
                                ];
                                if already_redirected {
                                    items.insert(2, "  Restore original  ".into());
                                }
                                self.context_menu = Some(ContextMenu {
                                    x: col,
                                    y: row,
                                    items,
                                    selected: 0,
                                    source: ContextMenuSource::JniMonitor,
                                    line_idx: jni_idx,
                                    click_col: 0,
                                    keyboard_navigable: false,
                                });
                                self.focus = 0;
                                self.command_focused = false;
                            }
                        }
                        if !entry_menu {
                            // Empty panel or header row — show monitor toggle only
                            self.context_menu = Some(ContextMenu {
                                x: col,
                                y: row,
                                items: vec![monitor_label.into()],
                                selected: 0,
                                source: ContextMenuSource::JniMonitor,
                                line_idx: usize::MAX,
                                click_col: 0,
                                keyboard_navigable: false,
                            });
                            self.focus = 0;
                            self.command_focused = false;
                        }
                    }
                    // Right-click in Locals panel (panel 1)
                    else if col > geom.locals_area.x && col < geom.locals_area.x + geom.locals_area.width.saturating_sub(1)
                        && row > geom.locals_area.y && row < geom.locals_area.y + geom.locals_area.height.saturating_sub(1)
                    {
                        let inner_y = (row - geom.locals_area.y - 1) as usize;
                        let line_idx = self.locals_scroll + inner_y;
                        let click_c = col.saturating_sub(geom.locals_area.x + 1) as usize;

                        let line_text = self.format_locals_line(line_idx);
                        let word_label = line_text.as_ref()
                            .and_then(|line| word_at_col(line, click_c).map(|w| w.to_string()))
                            .map(|w| copy_word_label(&w))
                            .unwrap_or_else(|| "  Copy Word    ".into());

                        // Check if the local's value contains hex that decodes to ASCII
                        let ascii_label = self.locals.get(line_idx)
                            .and_then(|l| find_hex_ascii_in(&l.value))
                            .map(|ascii| {
                                let display = if ascii.len() > 14 {
                                    format!("{}...", &ascii[..11])
                                } else {
                                    ascii
                                };
                                format!("  Copy: \"{}\"", display)
                            });

                        let mut locals_items = vec![
                            "  Copy Line    ".into(),
                            "  Copy View    ".into(),
                            word_label,
                        ];
                        if let Some(label) = ascii_label {
                            locals_items.push(label);
                        }
                        // Show Set Value only for primitive types (not objects/arrays/strings)
                        let can_set = matches!(self.state, AppState::Suspended | AppState::Stepping)
                            && self.get_local_at_line(line_idx)
                                .map(|v| is_primitive_type(&v.var_type))
                                .unwrap_or(false);
                        if can_set {
                            locals_items.push("  Set Value    ".into());
                        }

                        self.context_menu = Some(ContextMenu {
                            x: col,
                            y: row,
                            items: locals_items,
                            selected: 0,
                            source: ContextMenuSource::Locals,
                            line_idx,
                            click_col: click_c,
                            keyboard_navigable: false,
                        });
                        self.focus = 1;
                        self.command_focused = false;
                    }
                    // Right-click in Tabbed panel (panel 2: Stack/BP/Thd/Watch/Heap)
                    else if col > geom.tabbed_area.x && col < geom.tabbed_area.x + geom.tabbed_area.width.saturating_sub(1)
                        && row > geom.tabbed_area.y && row < geom.tabbed_area.y + geom.tabbed_area.height.saturating_sub(1)
                    {
                        let inner_y = (row - geom.tabbed_area.y - 1) as usize;
                        let line_idx = if self.right_tab == RightTab::Heap {
                            let scroll = if self.heap_selected >= (geom.tabbed_area.height.saturating_sub(2) as usize) {
                                self.heap_selected.saturating_sub(geom.tabbed_area.height.saturating_sub(2) as usize - 1)
                            } else { 0 };
                            scroll + inner_y
                        } else {
                            self.tabbed_scroll + inner_y
                        };
                        let click_c = col.saturating_sub(geom.tabbed_area.x + 1) as usize;

                        // Watch tab gets a custom context menu
                        let (tabbed_items, tabbed_line_idx) = if self.right_tab == RightTab::Watch {
                            let inner_height = geom.tabbed_area.height.saturating_sub(2) as usize;
                            let cursor = self.watch_selected.min(self.watches.len().saturating_sub(1));
                            let scroll = if cursor >= inner_height { cursor.saturating_sub(inner_height - 1) } else { 0 };
                            let w_idx = (scroll + inner_y).min(self.watches.len().saturating_sub(1));
                            let has_value = self.watches.get(w_idx).and_then(|w| w.last_value.as_ref()).is_some();
                            let mut items: Vec<String> = vec!["  Copy Expr    ".into()];
                            if has_value {
                                items.push("  Copy Value   ".into());
                            }
                            items.push("  Remove       ".into());
                            (items, w_idx)
                        } else {
                            let line_text = self.format_tabbed_line(line_idx);
                            let word_label = line_text.as_ref()
                                .and_then(|line| word_at_col(line, click_c).map(|w| w.to_string()))
                                .map(|w| copy_word_label(&w))
                                .unwrap_or_else(|| "  Copy Word    ".into());
                            (vec![
                                "  Copy Line    ".into(),
                                "  Copy View    ".into(),
                                word_label,
                            ], line_idx)
                        };

                        self.context_menu = Some(ContextMenu {
                            x: col,
                            y: row,
                            items: tabbed_items,
                            selected: 0,
                            source: ContextMenuSource::Tabbed,
                            line_idx: tabbed_line_idx,
                            click_col: click_c,
                            keyboard_navigable: false,
                        });
                        self.focus = 2;
                        self.command_focused = false;
                    }
                    // Right-click in log panel body (not border)
                    else if col > lga.x && col < lga.x + lga.width.saturating_sub(1)
                        && row > lga.y && row < lga.y + lga.height.saturating_sub(1)
                    {
                        let inner_y = (row - lga.y - 1) as usize;
                        let inner_height = lga.height.saturating_sub(2) as usize;
                        let total = self.log.len();
                        let scroll = if self.log_auto_scroll {
                            total.saturating_sub(inner_height)
                        } else {
                            self.log_scroll
                        };
                        let log_idx = scroll + inner_y;
                        let click_c = col.saturating_sub(lga.x + 1) as usize;

                        let word_label = self.log.get(log_idx)
                            .map(|e| format_log_entry(e))
                            .and_then(|line| word_at_col(&line, click_c).map(|w| w.to_string()))
                            .map(|w| copy_word_label(&w))
                            .unwrap_or_else(|| "  Copy Word    ".into());

                        let mut log_items: Vec<String> = Vec::new();
                        if self.log_has_selection() {
                            log_items.push("  Copy Sel     ".into());
                        }
                        log_items.push("  Copy Line    ".into());
                        log_items.push("  Copy View    ".into());
                        log_items.push(word_label);

                        self.context_menu = Some(ContextMenu {
                            x: col,
                            y: row,
                            items: log_items,
                            selected: 0,
                            source: ContextMenuSource::Log,
                            line_idx: log_idx,
                            click_col: click_c,
                            keyboard_navigable: false,
                        });
                        self.focus = 3;
                        self.command_focused = false;
                    } else if in_rect(col, row, geom.command_area) {
                        // Right-click in command area → Copy/Cut/Paste menu
                        let has_sel = self.command_sel_anchor
                            .map(|a| a != self.command_cursor)
                            .unwrap_or(false);
                        let copy_label = if has_sel { "  Copy         " } else { "  Copy All     " };
                        self.context_menu = Some(ContextMenu {
                            x: col,
                            y: row,
                            items: vec![
                                copy_label.into(),
                                "  Cut          ".into(),
                                "  Paste        ".into(),
                            ],
                            selected: 0,
                            source: ContextMenuSource::CommandInput,
                            line_idx: 0,
                            click_col: col.saturating_sub(geom.command_area.x + 4) as usize,
                            keyboard_navigable: false,
                        });
                        self.focus = 4;
                        self.command_focused = true;
                    } else {
                        self.context_menu = None;
                    }
                }
            }

            MouseEventKind::ScrollUp => {
                self.scroll_panel_at(col, row, -3);
            }

            MouseEventKind::ScrollDown => {
                self.scroll_panel_at(col, row, 3);
            }

            _ => {}
        }
    }

    fn handle_context_menu_click(&mut self, item_idx: usize) {
        let menu = match self.context_menu.take() {
            Some(m) => m,
            None => return,
        };

        match menu.source {
            ContextMenuSource::Log => self.handle_log_context_menu(item_idx, &menu),
            ContextMenuSource::Trace => self.handle_trace_context_menu(item_idx, &menu),
            ContextMenuSource::Ai => self.handle_ai_context_menu(item_idx, &menu),
            ContextMenuSource::Bytecodes => self.handle_bytecodes_context_menu(item_idx, &menu),
            ContextMenuSource::Locals => self.handle_locals_context_menu(item_idx, &menu),
            ContextMenuSource::Tabbed => self.handle_tabbed_context_menu(item_idx, &menu),
            ContextMenuSource::PatchSubmenu => self.handle_patch_submenu(item_idx, &menu),
            ContextMenuSource::CommandInput => self.handle_command_context_menu(item_idx),
            ContextMenuSource::JniMonitor => self.handle_jni_context_menu(item_idx, &menu),
        }
    }

    fn handle_command_context_menu(&mut self, item_idx: usize) {
        match item_idx {
            0 => {
                // Copy: selection if active, else entire input
                let text = if let Some(anchor) = self.command_sel_anchor {
                    let sel_min = anchor.min(self.command_cursor);
                    let sel_max = anchor.max(self.command_cursor);
                    self.command_input[sel_min..sel_max].to_string()
                } else {
                    self.command_input.clone()
                };
                if !text.is_empty() { copy_to_clipboard(&text); }
            }
            1 => {
                // Cut: copy selection then delete it
                if let Some(anchor) = self.command_sel_anchor {
                    let sel_min = anchor.min(self.command_cursor);
                    let sel_max = anchor.max(self.command_cursor);
                    if sel_min < sel_max {
                        let text = self.command_input[sel_min..sel_max].to_string();
                        copy_to_clipboard(&text);
                        self.cmd_sel_delete();
                    }
                }
            }
            2 => {
                // Paste: replace selection (if any) then insert clipboard text
                if let Some(pasted) = paste_from_clipboard() {
                    self.cmd_sel_delete();
                    self.command_input.insert_str(self.command_cursor, &pasted);
                    self.command_cursor += pasted.len();
                }
            }
            _ => {}
        }
    }

    fn handle_log_context_menu(&mut self, item_idx: usize, menu: &ContextMenu) {
        let label = menu.items.get(item_idx).map(|s| s.trim()).unwrap_or("");
        match label {
            "Copy Sel" => {
                self.copy_log_selection();
            }
            "Copy Line" => {
                if let Some(entry) = self.log.get(menu.line_idx) {
                    copy_to_clipboard(&format_log_entry(entry));
                }
            }
            "Copy View" => {
                let inner_height = self.layout_geom.as_ref()
                    .map(|g| g.log_area.height.saturating_sub(2) as usize)
                    .unwrap_or(20);
                let total = self.log.len();
                let scroll = if self.log_auto_scroll {
                    total.saturating_sub(inner_height)
                } else {
                    self.log_scroll
                };
                let text: String = self.log.iter()
                    .skip(scroll)
                    .take(inner_height)
                    .map(|e| format_log_entry(e))
                    .collect::<Vec<_>>()
                    .join("\n");
                copy_to_clipboard(&text);
            }
            _ => {
                // Copy Word under cursor (last item, regardless of position)
                if let Some(entry) = self.log.get(menu.line_idx) {
                    let line = format_log_entry(entry);
                    if let Some(word) = word_at_col(&line, menu.click_col) {
                        copy_to_clipboard(word);
                    }
                }
            }
        }
    }

    fn log_has_selection(&self) -> bool {
        match (self.log_sel_anchor, self.log_sel_head) {
            (Some(a), Some(h)) => a != h,
            _ => false,
        }
    }

    fn bytecodes_has_selection(&self) -> bool {
        match (self.bytecodes_sel_anchor, self.bytecodes_sel_head) {
            (Some(a), Some(h)) => a != h,
            _ => false,
        }
    }

    fn copy_bytecodes_selection(&self) {
        let (anchor, head) = match (self.bytecodes_sel_anchor, self.bytecodes_sel_head) {
            (Some(a), Some(h)) => (a, h),
            _ => return,
        };
        if anchor == head {
            return;
        }
        let (r0, c0, r1, c1) = if anchor.0 < head.0 || (anchor.0 == head.0 && anchor.1 <= head.1) {
            (anchor.0, anchor.1, head.0, head.1)
        } else {
            (head.0, head.1, anchor.0, anchor.1)
        };
        let mut parts: Vec<String> = Vec::new();
        for row in r0..=r1 {
            if let Some(instr) = self.bytecodes.get(row) {
                // Flat display: 2-char gutter + "xxxx: " + text  (matches render layout)
                let flat = format!("  {:04x}: {}", instr.offset, instr.text);
                let chars: Vec<char> = flat.chars().collect();
                let start = if row == r0 { c0.min(chars.len()) } else { 0 };
                let end   = if row == r1 { c1.min(chars.len()) } else { chars.len() };
                let (start, end) = (start.min(end), start.max(end));
                parts.push(chars[start..end].iter().collect());
            }
        }
        copy_to_clipboard(&parts.join("\n"));
    }

    fn copy_log_selection(&self) {
        let (anchor, head) = match (self.log_sel_anchor, self.log_sel_head) {
            (Some(a), Some(h)) => (a, h),
            _ => return,
        };
        if anchor == head {
            return;
        }
        // Normalize: (r0, c0) is top-left, (r1, c1) is bottom-right
        let (r0, c0, r1, c1) = if anchor.0 < head.0 || (anchor.0 == head.0 && anchor.1 <= head.1) {
            (anchor.0, anchor.1, head.0, head.1)
        } else {
            (head.0, head.1, anchor.0, anchor.1)
        };
        let mut parts: Vec<String> = Vec::new();
        for row in r0..=r1 {
            if let Some(entry) = self.log.get(row) {
                let flat = format_log_entry(entry);
                let chars: Vec<char> = flat.chars().collect();
                let start = if row == r0 { c0.min(chars.len()) } else { 0 };
                let end   = if row == r1 { c1.min(chars.len()) } else { chars.len() };
                let (start, end) = (start.min(end), start.max(end));
                parts.push(chars[start..end].iter().collect());
            }
        }
        copy_to_clipboard(&parts.join("\n"));
    }

    fn handle_trace_context_menu(&mut self, item_idx: usize, menu: &ContextMenu) {
        match item_idx {
            0 => {
                // Copy Line
                if let Some(record) = self.call_records.get(menu.line_idx) {
                    copy_to_clipboard(&format_call_record(record));
                }
            }
            1 => {
                // Copy View
                let inner_height = self.layout_geom.as_ref()
                    .map(|g| g.bytecodes_area.height.saturating_sub(3) as usize) // -2 border -1 header
                    .unwrap_or(20);
                let scroll = if self.trace_auto_scroll {
                    self.call_records.len().saturating_sub(inner_height)
                } else {
                    self.trace_scroll
                };
                let text: String = self.call_records.iter()
                    .skip(scroll)
                    .take(inner_height)
                    .map(|r| format_call_record(r))
                    .collect::<Vec<_>>()
                    .join("\n");
                copy_to_clipboard(&text);
            }
            2 => {
                // Copy Word under cursor
                if let Some(record) = self.call_records.get(menu.line_idx) {
                    let line = format_call_record(record);
                    if let Some(word) = word_at_col(&line, menu.click_col) {
                        copy_to_clipboard(word);
                    }
                }
            }
            3 => {
                // Toggle Save trace
                self.toggle_trace_save();
            }
            4 => {
                // Clear trace
                self.call_records.clear();
                self.trace_depth.clear();
                self.trace_scroll = 0;
                self.trace_auto_scroll = true;
                self.log_info("Trace cleared");
            }
            5 => {
                // Split to Log (only present when line > 120 chars)
                if menu.items.len() > 5 {
                    if let Some(record) = self.call_records.get(menu.line_idx) {
                        let line = format_call_record(record);
                        // Use log panel width if available, else 80
                        let log_width = self.layout_geom.as_ref()
                            .map(|g| g.log_area.width.saturating_sub(11) as usize) // -2 border -8 prefix -1 pad
                            .unwrap_or(80);
                        let width = log_width.max(40);
                        for chunk in split_long_line(&line, width) {
                            self.log_info(&chunk);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn handle_jni_context_menu(&mut self, item_idx: usize, menu: &ContextMenu) {
        let label = menu.items.get(item_idx).map(|s| s.trim()).unwrap_or("");

        // Monitor toggle works even with no entry selected
        match label {
            "Start monitoring" => { self.do_jni_monitor_start(); return; }
            "Stop monitoring"  => { self.do_jni_monitor_stop();  return; }
            _ => {}
        }

        let entry = match self.jni_natives.get(menu.line_idx) {
            Some(e) => e.clone(),
            None => return,
        };
        let addr_str = if entry.lib_name.is_empty() || entry.lib_name == "[anon]" {
            format!("0x{:x}", entry.native_addr as u64)
        } else {
            format!("{}+0x{:x}", entry.lib_name, entry.lib_offset as u64)
        };

        let label = menu.items.get(item_idx).map(|s| s.trim()).unwrap_or("");
        match label {
            // header / separators — no-op
            l if l.starts_with('─') => {}
            // entry function label — no-op (display only)
            l if l.contains('.') && !l.starts_with("Redirect") && !l.starts_with("Restore")
                && !l.starts_with("Copy") && !l.starts_with("Stop") && !l.starts_with("Start") => {}
            "Restore original" => {
                self.send_command(crate::protocol::OutboundCommand::JniRedirectClear {
                    class_sig:   entry.class_sig.clone(),
                    method_name: entry.method_name.clone(),
                    method_sig:  entry.method_sig.clone(),
                });
            }
            "Redirect: block" => {
                self.do_jni_redirect_inner(
                    entry.class_sig.clone(), entry.method_name.clone(), entry.method_sig.clone(),
                    "block",
                );
            }
            "Redirect: true" => {
                self.do_jni_redirect_inner(
                    entry.class_sig.clone(), entry.method_name.clone(), entry.method_sig.clone(),
                    "true",
                );
            }
            "Redirect: false" => {
                self.do_jni_redirect_inner(
                    entry.class_sig.clone(), entry.method_name.clone(), entry.method_sig.clone(),
                    "false",
                );
            }
            "Redirect: 0" => {
                self.do_jni_redirect_inner(
                    entry.class_sig.clone(), entry.method_name.clone(), entry.method_sig.clone(),
                    "spoof 0",
                );
            }
            "Copy address" => {
                copy_to_clipboard(&addr_str);
            }
            "Copy class sig" => {
                let sig = format!("{} {} {}", entry.class_sig, entry.method_name, entry.method_sig);
                copy_to_clipboard(&sig);
            }
            _ => {}
        }
    }

    fn handle_ai_context_menu(&mut self, item_idx: usize, menu: &ContextMenu) {
        match item_idx {
            0 => {
                // Copy Line
                if let Some(line) = self.ai_output.get(menu.line_idx) {
                    copy_to_clipboard(&line.text);
                }
            }
            1 => {
                // Copy View (visible lines)
                let inner_height = self.layout_geom.as_ref()
                    .map(|g| g.bytecodes_area.height.saturating_sub(2) as usize)
                    .unwrap_or(20);
                let scroll = if self.ai_auto_scroll {
                    self.ai_output.len().saturating_sub(inner_height)
                } else {
                    self.ai_scroll
                };
                let text: String = self.ai_output.iter()
                    .skip(scroll)
                    .take(inner_height)
                    .map(|l| l.text.as_str())
                    .collect::<Vec<_>>()
                    .join("\n");
                copy_to_clipboard(&text);
            }
            2 => {
                // Copy Word under cursor
                if let Some(line) = self.ai_output.get(menu.line_idx) {
                    if let Some(word) = word_at_col(&line.text, menu.click_col) {
                        copy_to_clipboard(word);
                    }
                }
            }
            3 => {
                // Copy All
                let text: String = self.ai_output.iter()
                    .map(|l| l.text.as_str())
                    .collect::<Vec<_>>()
                    .join("\n");
                copy_to_clipboard(&text);
            }
            4 => {
                // Save to File
                let text: String = self.ai_output.iter()
                    .map(|l| l.text.as_str())
                    .collect::<Vec<_>>()
                    .join("\n");
                match std::fs::write("ai_analysis.txt", &text) {
                    Ok(_) => self.log_info(&format!(
                        "AI output saved to ai_analysis.txt ({} lines)",
                        self.ai_output.len()
                    )),
                    Err(e) => self.log_info(&format!("Failed to save: {}", e)),
                }
            }
            _ => {}
        }
    }

    fn handle_bytecodes_context_menu(&mut self, item_idx: usize, menu: &ContextMenu) {
        let label = menu.items.get(item_idx).map(|s| s.trim()).unwrap_or("");
        match label {
            "Copy Sel" => {
                self.copy_bytecodes_selection();
            }
            "Copy Line" => {
                if let Some(instr) = self.bytecodes.get(menu.line_idx) {
                    let line = format!("{:04x}: {}", instr.offset, instr.text);
                    copy_to_clipboard(&line);
                }
            }
            "Copy View" => {
                let inner_height = self.layout_geom.as_ref()
                    .map(|g| g.bytecodes_area.height.saturating_sub(3) as usize)
                    .unwrap_or(20);
                let current_idx = self.current_loc.and_then(|loc| {
                    self.bytecodes.iter().position(|i| i.offset == loc as u32)
                });
                let scroll = if self.bytecodes_auto_scroll {
                    if let Some(idx) = current_idx {
                        idx.saturating_sub(2)
                    } else {
                        self.bytecodes_scroll
                    }
                } else {
                    self.bytecodes_scroll
                };
                let text: String = self.bytecodes.iter()
                    .skip(scroll)
                    .take(inner_height)
                    .map(|i| format!("{:04x}: {}", i.offset, i.text))
                    .collect::<Vec<_>>()
                    .join("\n");
                copy_to_clipboard(&text);
            }
            "Return true"  => self.execute_command("fr true"),
            "Return false" => self.execute_command("fr false"),
            "Patch method" => self.open_patch_submenu(),
            l if l.starts_with("Jump taken") || l == "Jump not taken" => {
                let taken = l.starts_with("Jump taken");
                if let Some(instr) = self.bytecodes.get(menu.line_idx) {
                    if let Some((slot, taken_val, not_taken_val, _)) = parse_cond_jump(&instr.text) {
                        let value = if taken { taken_val } else { not_taken_val };
                        self.send_command(OutboundCommand::SetLocal { slot, value, type_hint: Some("I".into()) });
                        self.send_command(OutboundCommand::Regs {});
                        self.log_info(&format!(
                            "Set v{} = {} => jump {}",
                            slot, value, if taken { "taken" } else { "not taken" }
                        ));
                    }
                }
            }
            "Jump to PC"   => self.jump_to_pc(),
            l if l.starts_with("Rename") => {
                let sig = self.class_at_bc_idx(menu.line_idx)
                    .or_else(|| self.current_class.clone());
                if let Some(sig) = sig {
                    let existing = self.aliases.get(&sig).cloned().unwrap_or_default();
                    self.comment_input = existing;
                    self.comment_cursor = self.comment_input.len();
                    self.alias_target = Some(sig);
                    self.alias_open = true;
                }
            }
            "Copy: class sig" => {
                if let Some(cls) = &self.current_class.clone() {
                    copy_to_clipboard(cls);
                }
            }
            l if l.starts_with("Copy:") && menu.line_idx == usize::MAX => {
                // Header menu: copy "ShortClass.method"
                let short = self.current_class.as_deref()
                    .map(|s| crate::commands::short_class(s).to_string())
                    .unwrap_or_else(|| "?".to_string());
                let meth = self.current_method.as_deref().unwrap_or("?");
                copy_to_clipboard(&format!("{}.{}", short, meth));
            }
            l if l.starts_with("Copy:") => {
                // Copy Word under cursor
                if let Some(instr) = self.bytecodes.get(menu.line_idx) {
                    let line = format!("  {:04x}: {}", instr.offset, instr.text);
                    if let Some(word) = word_at_col(&line, menu.click_col) {
                        copy_to_clipboard(word);
                    }
                }
            }
            _ => {} // separator or unknown
        }
    }

    // -------------------------------------------------------------------
    // Keyboard-navigable context menu (patch submenu)
    // -------------------------------------------------------------------

    /// Handle key events when a keyboard_navigable context menu is open.
    fn handle_context_menu_key(&mut self, key: KeyEvent) {
        let items_len = self.context_menu.as_ref().map(|m| m.items.len()).unwrap_or(0);

        let is_sep = |menu: &ContextMenu, i: usize| -> bool {
            menu.items.get(i).map(|s| s.contains('\u{2500}')).unwrap_or(false)
        };

        match key.code {
            KeyCode::Up => {
                if let Some(ref mut menu) = self.context_menu {
                    let mut i = menu.selected;
                    loop {
                        if i == 0 { break; }
                        i -= 1;
                        if !is_sep(menu, i) { menu.selected = i; break; }
                    }
                }
            }
            KeyCode::Down => {
                if let Some(ref mut menu) = self.context_menu {
                    let mut i = menu.selected;
                    loop {
                        if i + 1 >= items_len { break; }
                        i += 1;
                        if !is_sep(menu, i) { menu.selected = i; break; }
                    }
                }
            }
            KeyCode::Enter => {
                if let Some(menu) = self.context_menu.take() {
                    let idx = menu.selected;
                    match menu.source {
                        ContextMenuSource::PatchSubmenu =>
                            self.handle_patch_submenu(idx, &menu),
                        ContextMenuSource::Bytecodes =>
                            self.handle_bytecodes_context_menu(idx, &menu),
                        _ => {}
                    }
                }
            }
            _ => {
                // Esc or any other key: dismiss
                self.context_menu = None;
            }
        }
    }

    /// Open the patch-method submenu centered in the bytecodes area.
    fn open_patch_submenu(&mut self) {
        let sep = "\u{2500}".repeat(13);
        let mut items: Vec<String> = vec![
            "  void      ".into(),
            "  true      ".into(),
            "  false     ".into(),
            "  null      ".into(),
            "  0         ".into(),
            "  1         ".into(),
            sep.clone(),
            "  edit...   ".into(),
        ];

        // Add "Nop range from..to" when suspended and cursor is ahead of current PC
        if self.state == AppState::Suspended {
            if let (Some(from_loc), Some(cur_idx)) = (self.current_loc, self.bytecodes_cursor) {
                if let Some(instr) = self.bytecodes.get(cur_idx) {
                    let from_bci = from_loc as u32;
                    let to_bci = instr.offset;
                    if to_bci > from_bci {
                        items.push(sep.clone());
                        items.push(format!("  Nop {:04x}..{:04x}  ", from_bci, to_bci));
                    }
                }
            }
        }

        // Add "Branch taken/not taken" patch when cursor is on a conditional jump
        if let Some(cur_idx) = self.bytecodes_cursor {
            if let Some(instr) = self.bytecodes.get(cur_idx) {
                if let Some(ref meta) = instr.branch {
                    if meta.cond != disassembler::BranchCond::Always {
                        items.push(sep);
                        items.push(format!("  Branch taken >{:04x}  ", meta.target));
                        items.push("  Branch not taken  ".into());
                    }
                }
            }
        }

        let (x, y) = self.layout_geom.as_ref().map(|g| {
            let a = g.bytecodes_area;
            (a.x + a.width / 2, a.y + a.height / 2)
        }).unwrap_or((10, 10));

        self.context_menu = Some(ContextMenu {
            x,
            y,
            items,
            selected: 0,
            source: ContextMenuSource::PatchSubmenu,
            line_idx: self.bytecodes_cursor.unwrap_or(0),
            click_col: 0,
            keyboard_navigable: true,
        });
    }

    /// Dispatch a patch submenu selection.
    fn handle_patch_submenu(&mut self, item_idx: usize, menu: &ContextMenu) {
        let cls = match &self.current_class { Some(c) => c.clone(), None => return };
        let meth = match &self.current_method { Some(m) => m.clone(), None => return };

        match item_idx {
            0 => self.execute_command(&format!("patch {} {} void",  cls, meth)),
            1 => self.execute_command(&format!("patch {} {} true",  cls, meth)),
            2 => self.execute_command(&format!("patch {} {} false", cls, meth)),
            3 => self.execute_command(&format!("patch {} {} null",  cls, meth)),
            4 => self.execute_command(&format!("patch {} {} 0",     cls, meth)),
            5 => self.execute_command(&format!("patch {} {} 1",     cls, meth)),
            // 6 = separator
            7 => {
                // Pre-fill command line with "patch <class> <method> " — user types the value
                let prefill = format!("patch {} {} ", cls, meth);
                self.command_cursor = prefill.len();
                self.command_sel_anchor = None;
                self.command_input = prefill;
                self.focus = 4;
                self.command_focused = true;
            }
            _ => {
                let label = menu.items.get(item_idx).map(|s| s.trim()).unwrap_or("");
                if label.starts_with("Nop ") {
                    if let Some(instr) = self.bytecodes.get(menu.line_idx) {
                        self.do_nop_range_patch(instr.offset);
                    }
                } else if label.starts_with("Branch taken") || label == "Branch not taken" {
                    let taken = label.starts_with("Branch taken");
                    if let Some(instr) = self.bytecodes.get(menu.line_idx) {
                        if instr.branch.is_some() {
                            self.do_patch_branch_force(instr.offset, taken);
                        }
                    }
                }
            }
        }
    }

    /// Format a locals/registers line at the given index (for context menu).
    /// Format a locals line for clipboard copy.
    /// Matches the display layout (so click columns align for "Copy Word")
    /// but uses the FULL untruncated value.
    fn format_locals_line(&self, idx: usize) -> Option<String> {
        match self.locals_tab {
            LocalsTab::Locals => {
                self.locals.get(idx).map(|l| {
                    let t = commands::short_type(&l.var_type);
                    format!("{}: {} = {}", l.name, t, l.value)
                })
            }
            LocalsTab::Registers => {
                // Registers display is sorted by slot  - mirror that order
                let mut sorted: Vec<_> = self.locals.iter().collect();
                sorted.sort_by_key(|v| v.slot);
                sorted.get(idx).map(|var| {
                    let type_str = commands::short_type(&var.var_type);
                    let name_hint = if var.name.is_empty() || var.name == "?" {
                        String::new()
                    } else {
                        format!(" ({})", var.name)
                    };
                    format!("v{:<3}{} = {}{}", var.slot, type_str, var.value, name_hint)
                })
            }
        }
    }

    /// Format a tabbed panel line at the given index (for context menu).
    fn format_tabbed_line(&self, idx: usize) -> Option<String> {
        match self.right_tab {
            RightTab::Stack => {
                self.stack.get(idx).map(|f| {
                    let cls = commands::short_class(&f.class);
                    let line_info = if f.line >= 0 { format!(":{}", f.line) } else { String::new() };
                    format!("#{} {}.{}{}", f.depth, cls, f.method, line_info)
                })
            }
            RightTab::Breakpoints => {
                self.bp_manager.breakpoints.get(idx).map(|bp| {
                    let cls = commands::short_class(&bp.class);
                    format!("#{} {}.{} @{:04x}", bp.id, cls, bp.method, bp.location)
                })
            }
            RightTab::Threads => {
                self.threads.get(idx).map(|t| {
                    let daemon = if t.daemon { " (daemon)" } else { "" };
                    format!("{} pri={}{}", t.name, t.priority, daemon)
                })
            }
            RightTab::Watch => {
                self.watches.get(idx).map(|w| {
                    match (&w.last_value, &w.last_type) {
                        (Some(val), Some(ty)) => {
                            let short_ty = commands::short_type(ty);
                            format!("{} = ({}) {}", w.expr, short_ty, val)
                        }
                        _ => format!("{}  (not yet evaluated)", w.expr),
                    }
                })
            }
            RightTab::Bookmarks => {
                self.bookmarks.get(idx).map(|bm| {
                    let cls = commands::short_class(&bm.class);
                    format!("{}.{}+{:#x}  {}", cls, bm.method, bm.offset, bm.label)
                })
            }
            RightTab::Heap => {
                self.heap_rows.get(idx).map(|row| {
                    match row {
                        HeapRow::Header(text) => text.clone(),
                        HeapRow::Object { index, value } => format!("[{}] {}", index, value),
                        HeapRow::StringMatch { index, value } => format!("[{}] \"{}\"", index, value),
                    }
                })
            }
        }
    }

    fn handle_locals_context_menu(&mut self, item_idx: usize, menu: &ContextMenu) {
        // Match by label for the last items so ascii_label offset doesn't break things
        let label = menu.items.get(item_idx).map(|s| s.trim()).unwrap_or("");
        if label == "Set Value" {
            self.open_setreg_for_line(menu.line_idx);
            return;
        }
        match item_idx {
            0 => {
                // Copy Line
                if let Some(line) = self.format_locals_line(menu.line_idx) {
                    copy_to_clipboard(&line);
                }
            }
            1 => {
                // Copy View
                let inner_height = self.layout_geom.as_ref()
                    .map(|g| g.locals_area.height.saturating_sub(2) as usize)
                    .unwrap_or(20);
                let scroll = self.locals_scroll;
                let len = self.locals.len();
                let text: String = (scroll..len.min(scroll + inner_height))
                    .filter_map(|i| self.format_locals_line(i))
                    .collect::<Vec<_>>()
                    .join("\n");
                copy_to_clipboard(&text);
            }
            2 => {
                // Copy Word
                if let Some(line) = self.format_locals_line(menu.line_idx) {
                    if let Some(word) = word_at_col(&line, menu.click_col) {
                        copy_to_clipboard(word);
                    }
                }
            }
            3 => {
                // Copy full ASCII decode from raw value (not dependent on click column)
                if let Some(l) = self.locals.get(menu.line_idx) {
                    if let Some(ascii) = find_hex_ascii_in(&l.value) {
                        copy_to_clipboard(&ascii);
                    }
                }
            }
            _ => {}
        }
    }

    /// Get the LocalVar at the given display line index, accounting for Locals vs Registers sort.
    fn get_local_at_line(&self, line_idx: usize) -> Option<&crate::protocol::LocalVar> {
        match self.locals_tab {
            LocalsTab::Locals => self.locals.get(line_idx),
            LocalsTab::Registers => {
                let mut sorted: Vec<_> = self.locals.iter().collect();
                sorted.sort_by_key(|v| v.slot);
                sorted.into_iter().nth(line_idx)
            }
        }
    }

    /// Pre-fill the command bar with "setreg vN " for the local at display line_idx.
    fn open_setreg_for_line(&mut self, line_idx: usize) {
        if let Some(var) = self.get_local_at_line(line_idx) {
            let slot = var.slot;
            self.command_input = format!("setreg v{} ", slot);
            self.command_cursor = self.command_input.len();
            self.focus = 4;
            self.command_focused = true;
        }
    }

    fn handle_tabbed_context_menu(&mut self, item_idx: usize, menu: &ContextMenu) {
        // Watch tab has its own context menu items matched by label
        if self.right_tab == RightTab::Watch {
            let label = menu.items.get(item_idx).map(|s| s.trim()).unwrap_or("");
            match label {
                "Copy Expr" => {
                    if let Some(w) = self.watches.get(menu.line_idx) {
                        copy_to_clipboard(&w.expr);
                    }
                }
                "Copy Value" => {
                    if let Some(w) = self.watches.get(menu.line_idx) {
                        if let Some(ref val) = w.last_value {
                            copy_to_clipboard(val);
                        }
                    }
                }
                "Remove" => {
                    if menu.line_idx < self.watches.len() {
                        let removed = self.watches.remove(menu.line_idx);
                        self.watch_selected = self.watch_selected.min(self.watches.len().saturating_sub(1));
                        self.log_info(&format!("Watch: removed '{}'", removed.expr));
                    }
                }
                _ => {}
            }
            return;
        }

        match item_idx {
            0 => {
                // Copy Line
                if let Some(line) = self.format_tabbed_line(menu.line_idx) {
                    copy_to_clipboard(&line);
                }
            }
            1 => {
                // Copy View
                let inner_height = self.layout_geom.as_ref()
                    .map(|g| g.tabbed_area.height.saturating_sub(2) as usize)
                    .unwrap_or(20);
                let scroll = if self.right_tab == RightTab::Heap {
                    if self.heap_selected >= inner_height {
                        self.heap_selected.saturating_sub(inner_height - 1)
                    } else { 0 }
                } else {
                    self.tabbed_scroll
                };
                let len = match self.right_tab {
                    RightTab::Stack => self.stack.len(),
                    RightTab::Breakpoints => self.bp_manager.breakpoints.len(),
                    RightTab::Threads => self.threads.len(),
                    RightTab::Watch => self.watches.len(),
                    RightTab::Heap => self.heap_rows.len(),
                    RightTab::Bookmarks => self.bookmarks.len(),
                };
                let text: String = (scroll..len.min(scroll + inner_height))
                    .filter_map(|i| self.format_tabbed_line(i))
                    .collect::<Vec<_>>()
                    .join("\n");
                copy_to_clipboard(&text);
            }
            2 => {
                // Copy Word
                if let Some(line) = self.format_tabbed_line(menu.line_idx) {
                    if let Some(word) = word_at_col(&line, menu.click_col) {
                        copy_to_clipboard(word);
                    }
                }
            }
            _ => {}
        }
    }

    /// Scroll whichever panel the mouse cursor is over.
    fn scroll_panel_at(&mut self, col: u16, row: u16, delta: i32) {
        if let Some(geom) = &self.layout_geom {
            if row >= geom.hsplit_y && row < geom.total_height.saturating_sub(2) {
                // Log panel area
                self.log_auto_scroll = false;
                self.log_scroll = apply_scroll(self.log_scroll, delta, self.log.len());
            } else if row < geom.hsplit_y {
                if col < geom.vsplit_x {
                    // Left panel (Bytecodes or Trace or AI or JNI)
                    if self.left_tab == LeftTab::Trace {
                        self.trace_auto_scroll = false;
                        self.trace_scroll = apply_scroll(self.trace_scroll, delta, self.call_records.len());
                    } else if self.left_tab == LeftTab::JniMonitor {
                        self.jni_monitor_scroll = apply_scroll(self.jni_monitor_scroll, delta, self.jni_natives.len());
                    } else if self.left_tab == LeftTab::Ai {
                        self.ai_auto_scroll = false;
                        self.ai_scroll = apply_scroll(self.ai_scroll, delta, self.ai_output.len());
                    } else {
                        // Sync stored scroll to current displayed position before switching to manual
                        if self.bytecodes_auto_scroll {
                            if let Some(loc) = self.current_loc {
                                if let Some(idx) = self.bytecodes.iter().position(|i| i.offset == loc as u32) {
                                    self.bytecodes_scroll = idx.saturating_sub(2);
                                }
                            }
                        }
                        self.bytecodes_auto_scroll = false;
                        self.bytecodes_scroll = apply_scroll(self.bytecodes_scroll, delta, self.bytecodes.len());
                    }
                } else if row < geom.right_hsplit_y {
                    // Locals panel (top-right upper)
                    self.locals_scroll = apply_scroll(self.locals_scroll, delta, self.locals.len());
                } else {
                    // Tabbed panel (top-right lower)
                    if self.right_tab == RightTab::Heap {
                        let len = self.heap_display_len();
                        if len > 0 {
                            let new = (self.heap_selected as i32 + delta).max(0).min(len as i32 - 1) as usize;
                            self.heap_selected = new;
                        }
                    } else {
                        let len = match self.right_tab {
                            RightTab::Stack => self.stack.len(),
                            RightTab::Breakpoints => self.bp_manager.breakpoints.len(),
                            RightTab::Threads => self.threads.len(),
                            RightTab::Watch => 0,
                            RightTab::Heap => 0,
                            RightTab::Bookmarks => self.bookmarks.len(),
                        };
                        self.tabbed_scroll = apply_scroll(self.tabbed_scroll, delta, len);
                    }
                }
            }
        }
    }

    fn handle_statusbar_action(&mut self, action: StatusBarAction) {
        match action {
            StatusBarAction::Connect => self.execute_command("connect"),
            StatusBarAction::ToggleBp => self.toggle_bp_at_cursor(),
            StatusBarAction::Run => self.execute_command("c"),
            StatusBarAction::Pause => self.execute_command("pause"),
            StatusBarAction::StepIn => self.execute_command("si"),
            StatusBarAction::StepOver => self.execute_command("s"),
            StatusBarAction::StepOut => { let cmd = self.sout_cmd(); self.execute_command(cmd); }
            StatusBarAction::Rec => self.execute_command("record"),
            StatusBarAction::Quit => { self.running = false; }
        }
    }

    /// Handle a click on a panel's title bar to switch sub-tabs.
    /// `col` is the absolute click column, `area_x` is the panel rect's x,
    /// `panel` is 0=bytecodes, 1=locals, 2=tabbed.
    /// Handle a click on a panel's title bar to switch sub-tabs.
    /// `col` is the absolute click column, `area_x` is the panel rect's x,
    /// `panel` is 0=bytecodes, 1=locals, 2=tabbed.
    fn handle_title_tab_click(&mut self, col: u16, area_x: u16, panel: usize) {
        // Block title is drawn starting at area_x + 1 (after left border char).
        let rel = col.saturating_sub(area_x + 1) as usize;

        match panel {
            0 => {
                // Styled tabs: " Bytecodes  Decompiler  Trace   AI   JNI "
                let names = &["Bytecodes", "Decompiler", "Trace", " AI ", "JNI"];
                if let Some(idx) = find_styled_tab_click(rel, names) {
                    self.left_tab = match idx {
                        0 => LeftTab::Bytecodes,
                        1 => LeftTab::Decompiler,
                        2 => LeftTab::Trace,
                        3 => LeftTab::Ai,
                        _ => LeftTab::JniMonitor,
                    };
                }
            }
            1 => {
                let names = &["Locals", "Registers"];
                let active = match self.locals_tab {
                    LocalsTab::Locals => 0,
                    LocalsTab::Registers => 1,
                };
                if let Some(idx) = find_tab_click(rel, names, active) {
                    self.locals_tab = match idx {
                        0 => LocalsTab::Locals,
                        _ => LocalsTab::Registers,
                    };
                }
            }
            2 => {
                let names = &["Stack", "BP", "Thd", "Watch", "Heap", "Bookmarks"];
                let active = match self.right_tab {
                    RightTab::Stack => 0,
                    RightTab::Breakpoints => 1,
                    RightTab::Threads => 2,
                    RightTab::Watch => 3,
                    RightTab::Heap => 4,
                    RightTab::Bookmarks => 5,
                };
                if let Some(idx) = find_tab_click(rel, names, active) {
                    self.tabbed_scroll = 0;
                    self.right_tab = match idx {
                        0 => RightTab::Stack,
                        1 => RightTab::Breakpoints,
                        2 => RightTab::Threads,
                        3 => RightTab::Watch,
                        4 => RightTab::Heap,
                        _ => RightTab::Bookmarks,
                    };
                }
            }
            _ => {}
        }
    }

    // -------------------------------------------------------------------
    // Keyboard input handling
    // -------------------------------------------------------------------

    fn handle_key(&mut self, key: KeyEvent) {
        // Comment dialog absorbs all keys
        if self.comment_open {
            self.handle_comment_key(key);
            return;
        }
        // Alias dialog absorbs all keys
        if self.alias_open {
            self.handle_alias_key(key);
            return;
        }

        // Session picker dialog absorbs all keys
        if self.session_picker_open {
            self.handle_session_picker_key(key);
            return;
        }

        // Dismiss context menu on any key, or navigate if keyboard_navigable
        if self.context_menu.is_some() {
            if self.context_menu.as_ref().map(|m| m.keyboard_navigable).unwrap_or(false) {
                self.handle_context_menu_key(key);
                return;
            }
            self.context_menu = None;
            return;
        }

        // AI approval keys (y/n when waiting for approval)
        if self.ai_state == AiState::WaitingApproval {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    self.handle_ai_approval(true);
                    return;
                }
                KeyCode::Char('n') | KeyCode::Char('N') => {
                    self.handle_ai_approval(false);
                    return;
                }
                KeyCode::Esc => {
                    self.do_ai_cancel();
                    return;
                }
                _ => {} // fall through to normal handling
            }
        }

        // Escape cancels AI when AI tab focused and AI running
        if key.code == KeyCode::Esc
            && self.left_tab == LeftTab::Ai
            && self.focus == 0
            && self.ai_state == AiState::Running
        {
            self.do_ai_cancel();
            return;
        }

        // Global keys (always active)
        match (key.modifiers, key.code) {
            (KeyModifiers::CONTROL, KeyCode::Char('c')) => {
                self.running = false;
                return;
            }
            (KeyModifiers::CONTROL, KeyCode::Char('s')) => {
                self.do_save_session();
            }
            (KeyModifiers::CONTROL, KeyCode::Char('l')) => {
                self.open_session_picker();
                return;
            }
            (KeyModifiers::CONTROL, KeyCode::Char('t')) => {
                self.theme_index = (self.theme_index + 1) % self.themes.len();
                self.theme = self.themes[self.theme_index].clone();
                self.log_info(&format!("Theme: {}", self.theme.name));
                return;
            }
            (KeyModifiers::CONTROL, KeyCode::Char('b')) => {
                self.toggle_bookmark_at_cursor();
                return;
            }
            (_, KeyCode::F(1)) => {
                self.execute_command("connect");
                return;
            }
            (_, KeyCode::F(6)) => {
                self.execute_command("pause");
                return;
            }
            (KeyModifiers::SHIFT, KeyCode::F(10)) => {
                self.execute_command("record");
                return;
            }
            (_, KeyCode::F(12)) => {
                self.mouse_enabled = !self.mouse_enabled;
                self.mouse_toggled = true;
                return;
            }
            _ => {}
        }

        if self.command_focused {
            self.handle_command_key(key);
        } else {
            self.handle_panel_key(key);
        }
        // Keep command_focused in sync with focus index
        self.command_focused = self.focus == 4;
    }

    fn handle_command_key(&mut self, key: KeyEvent) {
        let shift = key.modifiers.contains(KeyModifiers::SHIFT);
        let ctrl  = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Enter => {
                self.command_sel_anchor = None;
                let input = self.command_input.trim().to_string();
                if !input.is_empty() {
                    if !matches!(input.as_str(), "ss" | "save settings") {
                        self.command_history.push(input.clone());
                    }
                    self.history_idx = None;
                    self.execute_command(&input);
                }
                self.command_input.clear();
                self.command_cursor = 0;
            }
            KeyCode::Esc => {
                self.command_sel_anchor = None;
                self.focus = 0;
                self.command_focused = false;
            }
            KeyCode::Backspace => {
                if !self.cmd_sel_delete() && self.command_cursor > 0 {
                    let prev = self.command_input[..self.command_cursor]
                        .char_indices()
                        .next_back()
                        .map(|(i, _)| i)
                        .unwrap_or(0);
                    self.command_input.remove(prev);
                    self.command_cursor = prev;
                }
            }
            KeyCode::Delete => {
                if !self.cmd_sel_delete() && self.command_cursor < self.command_input.len() {
                    self.command_input.remove(self.command_cursor);
                }
            }
            // Ctrl+A: select all
            KeyCode::Char('a') if ctrl => {
                self.command_sel_anchor = Some(0);
                self.command_cursor = self.command_input.len();
            }
            KeyCode::Char(c) if !ctrl => {
                // Replace selection (if any), then insert
                self.cmd_sel_delete();
                self.command_input.insert(self.command_cursor, c);
                self.command_cursor += c.len_utf8();
            }
            KeyCode::Left => {
                if shift {
                    // Extend/start selection leftward
                    if self.command_sel_anchor.is_none() {
                        self.command_sel_anchor = Some(self.command_cursor);
                    }
                    if self.command_cursor > 0 {
                        self.command_cursor = self.command_input[..self.command_cursor]
                            .char_indices().next_back().map(|(i,_)| i).unwrap_or(0);
                    }
                } else if let Some(anchor) = self.command_sel_anchor.take() {
                    // Collapse to left edge of selection
                    self.command_cursor = anchor.min(self.command_cursor);
                } else if self.command_cursor > 0 {
                    self.command_cursor = self.command_input[..self.command_cursor]
                        .char_indices().next_back().map(|(i,_)| i).unwrap_or(0);
                }
            }
            KeyCode::Right => {
                if shift {
                    // Extend/start selection rightward
                    if self.command_sel_anchor.is_none() {
                        self.command_sel_anchor = Some(self.command_cursor);
                    }
                    if self.command_cursor < self.command_input.len() {
                        self.command_cursor = self.command_input[self.command_cursor..]
                            .char_indices().nth(1)
                            .map(|(i,_)| self.command_cursor + i)
                            .unwrap_or(self.command_input.len());
                    }
                } else if let Some(anchor) = self.command_sel_anchor.take() {
                    // Collapse to right edge of selection
                    self.command_cursor = anchor.max(self.command_cursor);
                } else if self.command_cursor < self.command_input.len() {
                    self.command_cursor = self.command_input[self.command_cursor..]
                        .char_indices().nth(1)
                        .map(|(i,_)| self.command_cursor + i)
                        .unwrap_or(self.command_input.len());
                }
            }
            KeyCode::Home => {
                if shift {
                    if self.command_sel_anchor.is_none() {
                        self.command_sel_anchor = Some(self.command_cursor);
                    }
                    self.command_cursor = 0;
                } else {
                    self.command_sel_anchor = None;
                    self.command_cursor = 0;
                }
            }
            KeyCode::End => {
                if shift {
                    if self.command_sel_anchor.is_none() {
                        self.command_sel_anchor = Some(self.command_cursor);
                    }
                    self.command_cursor = self.command_input.len();
                } else {
                    self.command_sel_anchor = None;
                    self.command_cursor = self.command_input.len();
                }
            }
            KeyCode::Up => {
                // History navigation
                if !self.command_history.is_empty() {
                    let idx = match self.history_idx {
                        Some(i) if i > 0 => i - 1,
                        Some(i) => i,
                        None => self.command_history.len() - 1,
                    };
                    self.history_idx = Some(idx);
                    self.command_sel_anchor = None;
                    self.command_input = self.command_history[idx].clone();
                    self.command_cursor = self.command_input.len();
                }
            }
            KeyCode::Down => {
                if let Some(idx) = self.history_idx {
                    self.command_sel_anchor = None;
                    if idx + 1 < self.command_history.len() {
                        let new_idx = idx + 1;
                        self.history_idx = Some(new_idx);
                        self.command_input = self.command_history[new_idx].clone();
                        self.command_cursor = self.command_input.len();
                    } else {
                        self.history_idx = None;
                        self.command_input.clear();
                        self.command_cursor = 0;
                    }
                }
            }
            // Tab: cycle to next panel
            KeyCode::Tab => {
                self.command_sel_anchor = None;
                self.focus = 0;
                self.command_focused = false;
            }
            // Shift+Tab: cycle to previous panel
            KeyCode::BackTab => {
                self.command_sel_anchor = None;
                self.focus = crate::tui::PANEL_COUNT - 2; // log panel (index 3)
                self.command_focused = false;
            }
            // F-key shortcuts work even in command mode
            KeyCode::F(5) => self.execute_command("c"),
            KeyCode::F(7) => self.execute_command("si"),
            KeyCode::F(8) => self.execute_command("s"),
            KeyCode::F(9) => { let cmd = self.sout_cmd(); self.execute_command(cmd); }
            _ => {}
        }
    }

    // ------------------------------------------------------------------
    // Command-line selection helpers
    // ------------------------------------------------------------------

    /// Convert a visible character column (0-based) to a byte offset in `s`.
    fn col_to_cmd_byte(s: &str, col: usize) -> usize {
        let mut n = 0usize;
        for (byte_idx, _) in s.char_indices() {
            if n >= col { return byte_idx; }
            n += 1;
        }
        s.len()
    }

    /// Delete the active selection from command_input, returning true if anything was deleted.
    fn cmd_sel_delete(&mut self) -> bool {
        if let Some(anchor) = self.command_sel_anchor.take() {
            let sel_min = anchor.min(self.command_cursor);
            let sel_max = anchor.max(self.command_cursor);
            if sel_min < sel_max {
                self.command_input.drain(sel_min..sel_max);
                self.command_cursor = sel_min;
                return true;
            }
        }
        false
    }

    fn handle_comment_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.comment_open = false;
                self.comment_input.clear();
                self.comment_cursor = 0;
            }
            KeyCode::Enter => {
                if let (Some(bci), Some(cls), Some(meth)) = (
                    self.comment_address,
                    self.current_class.clone(),
                    self.current_method.clone(),
                ) {
                    let k = (cls, meth, bci);
                    if self.comment_input.is_empty() {
                        self.comments.remove(&k);
                    } else {
                        self.comments.insert(k, self.comment_input.clone());
                    }
                }
                self.comment_open = false;
                self.comment_input.clear();
                self.comment_cursor = 0;
            }
            KeyCode::Backspace => {
                if self.comment_cursor > 0 {
                    let prev_len = self.comment_input[..self.comment_cursor]
                        .chars().next_back().map_or(1, |c| c.len_utf8());
                    self.comment_cursor -= prev_len;
                    self.comment_input.remove(self.comment_cursor);
                }
            }
            KeyCode::Delete => {
                if self.comment_cursor < self.comment_input.len() {
                    self.comment_input.remove(self.comment_cursor);
                }
            }
            KeyCode::Left => {
                if self.comment_cursor > 0 {
                    let prev_len = self.comment_input[..self.comment_cursor]
                        .chars().next_back().map_or(1, |c| c.len_utf8());
                    self.comment_cursor -= prev_len;
                }
            }
            KeyCode::Right => {
                if self.comment_cursor < self.comment_input.len() {
                    let next_len = self.comment_input[self.comment_cursor..]
                        .chars().next().map_or(1, |c| c.len_utf8());
                    self.comment_cursor += next_len;
                }
            }
            KeyCode::Home => { self.comment_cursor = 0; }
            KeyCode::End  => { self.comment_cursor = self.comment_input.len(); }
            KeyCode::Char(c) if self.comment_input.len() < 256 => {
                self.comment_input.insert(self.comment_cursor, c);
                self.comment_cursor += c.len_utf8();
            }
            _ => {}
        }
    }

    /// Return the class sig of the invoke target at the bytecodes cursor, if any.
    fn class_at_cursor(&self) -> Option<String> {
        self.bytecodes_cursor.and_then(|i| self.class_at_bc_idx(i))
    }

    /// Return the class sig of the invoke target at a specific bytecodes index, if any.
    fn class_at_bc_idx(&self, idx: usize) -> Option<String> {
        let instr = self.bytecodes.get(idx)?;
        let mid = instr.method_idx?;
        let current_cls = self.current_class.as_deref().unwrap_or("");
        // Try the DEX that owns the current class first, then all DEX
        let dex_iter = self.find_dex_for_class(current_cls)
            .into_iter()
            .chain(self.dex_data.iter());
        for dex in dex_iter {
            if let Some(mref) = dex.methods.get(mid as usize) {
                return Some(mref.class_name.clone());
            }
        }
        None
    }

    fn handle_alias_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.alias_open = false;
                self.alias_target = None;
                self.comment_input.clear();
                self.comment_cursor = 0;
            }
            KeyCode::Enter => {
                if let Some(sig) = self.alias_target.take() {
                    if self.comment_input.is_empty() {
                        self.aliases.remove(&sig);
                        let short = short_class(&sig);
                        self.log_info(&format!("Alias removed: {}", short));
                    } else {
                        let label = self.comment_input.clone();
                        self.aliases.insert(sig.clone(), label.clone());
                        let short = short_class(&sig);
                        self.log_info(&format!("Alias set: {} = {}  (Ctrl+S to save)", short, label));
                    }
                }
                self.alias_open = false;
                self.comment_input.clear();
                self.comment_cursor = 0;
            }
            KeyCode::Backspace => {
                if self.comment_cursor > 0 {
                    let prev_len = self.comment_input[..self.comment_cursor]
                        .chars().next_back().map_or(1, |c| c.len_utf8());
                    self.comment_cursor -= prev_len;
                    self.comment_input.remove(self.comment_cursor);
                }
            }
            KeyCode::Delete => {
                if self.comment_cursor < self.comment_input.len() {
                    self.comment_input.remove(self.comment_cursor);
                }
            }
            KeyCode::Left => {
                if self.comment_cursor > 0 {
                    let prev_len = self.comment_input[..self.comment_cursor]
                        .chars().next_back().map_or(1, |c| c.len_utf8());
                    self.comment_cursor -= prev_len;
                }
            }
            KeyCode::Right => {
                if self.comment_cursor < self.comment_input.len() {
                    let next_len = self.comment_input[self.comment_cursor..]
                        .chars().next().map_or(1, |c| c.len_utf8());
                    self.comment_cursor += next_len;
                }
            }
            KeyCode::Home  => { self.comment_cursor = 0; }
            KeyCode::End   => { self.comment_cursor = self.comment_input.len(); }
            KeyCode::Char(c) if self.comment_input.len() < 64 => {
                self.comment_input.insert(self.comment_cursor, c);
                self.comment_cursor += c.len_utf8();
            }
            _ => {}
        }
    }

    fn handle_panel_key(&mut self, key: KeyEvent) {
        match key.code {
            // Quit
            KeyCode::Char('q') => {
                self.running = false;
                return;
            }
            // Enter command mode
            KeyCode::Char(':') | KeyCode::Char('/') => {
                self.focus = 4;
                self.command_focused = true;
            }
            // Open comment dialog at cursor line
            KeyCode::Char(';')
                if self.focus == 0 && self.left_tab == LeftTab::Bytecodes =>
            {
                let idx = self.bytecodes_cursor.or_else(|| {
                    self.current_loc.and_then(|loc| {
                        self.bytecodes.iter().position(|i| i.offset == loc as u32)
                    })
                });
                if let Some(idx) = idx {
                    if let Some(instr) = self.bytecodes.get(idx) {
                        let bci = instr.offset;
                        self.comment_address = Some(bci);
                        let existing = self.current_class.as_ref()
                            .zip(self.current_method.as_ref())
                            .and_then(|(cls, meth)| {
                                self.comments.get(&(cls.clone(), meth.clone(), bci))
                            })
                            .cloned()
                            .unwrap_or_default();
                        self.comment_input = existing;
                        self.comment_cursor = self.comment_input.len();
                        self.comment_open = true;
                    }
                }
            }
            // Open patch submenu in bytecodes panel
            KeyCode::Char('p')
                if self.focus == 0
                    && self.left_tab == LeftTab::Bytecodes
                    && self.current_class.is_some()
                    && self.current_method.is_some() =>
            {
                self.open_patch_submenu();
            }
            // n: rename name under cursor (IDA-style alias dialog)
            KeyCode::Char('n')
                if self.focus == 0
                    && self.left_tab == LeftTab::Bytecodes
                    && self.current_class.is_some() =>
            {
                // Prefer the invoke target class at cursor; fall back to current class
                let sig = self.class_at_cursor()
                    .or_else(|| self.current_class.clone())
                    .unwrap();
                let existing = self.aliases.get(&sig).cloned().unwrap_or_default();
                self.comment_input = existing;
                self.comment_cursor = self.comment_input.len();
                self.alias_target = Some(sig);
                self.alias_open = true;
            }
            // Focus command line on any letter (start typing)
            KeyCode::Char(c) if c.is_alphanumeric() => {
                self.focus = 4;
                self.command_focused = true;
                self.command_input.push(c);
                self.command_cursor = self.command_input.len();
            }
            // Tab: cycle focus between panels (including command line)
            KeyCode::Tab => {
                self.focus = (self.focus + 1) % crate::tui::PANEL_COUNT;
                self.command_focused = self.focus == 4;
            }
            // Shift+Tab: cycle focus backwards
            KeyCode::BackTab => {
                self.focus = if self.focus == 0 {
                    crate::tui::PANEL_COUNT - 1
                } else {
                    self.focus - 1
                };
                self.command_focused = self.focus == 4;
            }
            // 1-5: switch sub-tabs within focused panel
            KeyCode::Char('1') => {
                match self.focus {
                    0 => self.left_tab = LeftTab::Bytecodes,
                    1 => self.locals_tab = LocalsTab::Locals,
                    2 => { self.tabbed_scroll = 0; self.right_tab = RightTab::Stack; }
                    _ => {}
                }
            }
            KeyCode::Char('2') => {
                match self.focus {
                    0 => self.left_tab = LeftTab::Decompiler,
                    1 => self.locals_tab = LocalsTab::Registers,
                    2 => { self.tabbed_scroll = 0; self.right_tab = RightTab::Breakpoints; }
                    _ => {}
                }
            }
            KeyCode::Char('3') => {
                match self.focus {
                    0 => self.left_tab = LeftTab::Trace,
                    2 => { self.tabbed_scroll = 0; self.right_tab = RightTab::Threads; }
                    _ => {}
                }
            }
            KeyCode::Char('4') => {
                match self.focus {
                    0 => self.left_tab = LeftTab::Ai,
                    2 => { self.tabbed_scroll = 0; self.right_tab = RightTab::Watch; }
                    _ => {}
                }
            }
            KeyCode::Char('5') => {
                match self.focus {
                    0 => self.left_tab = LeftTab::JniMonitor,
                    2 => { self.tabbed_scroll = 0; self.right_tab = RightTab::Heap; }
                    _ => {}
                }
            }
            KeyCode::Char('6') => {
                match self.focus {
                    2 => { self.tabbed_scroll = 0; self.right_tab = RightTab::Bookmarks; }
                    _ => {}
                }
            }
            // Arrow keys: move cursor in bytecodes panel, scroll others
            KeyCode::Up => {
                if self.focus == 0 && self.left_tab == LeftTab::Bytecodes && !self.bytecodes.is_empty() {
                    let cur = self.bytecodes_cursor.unwrap_or(0);
                    self.bytecodes_cursor = Some(cur.saturating_sub(1));
                    self.ensure_cursor_visible();
                } else {
                    self.scroll_active(-1);
                }
            }
            KeyCode::Down => {
                if self.focus == 0 && self.left_tab == LeftTab::Bytecodes && !self.bytecodes.is_empty() {
                    let cur = self.bytecodes_cursor.unwrap_or(0);
                    self.bytecodes_cursor = Some((cur + 1).min(self.bytecodes.len() - 1));
                    self.ensure_cursor_visible();
                } else {
                    self.scroll_active(1);
                }
            }
            KeyCode::PageUp => self.scroll_active(-10),
            KeyCode::PageDown => self.scroll_active(10),
            // Left/Right: also switch panels
            KeyCode::Left => {
                self.focus = if self.focus == 0 {
                    crate::tui::PANEL_COUNT - 1
                } else {
                    self.focus - 1
                };
                self.command_focused = self.focus == 4;
            }
            KeyCode::Right => {
                self.focus = (self.focus + 1) % crate::tui::PANEL_COUNT;
                self.command_focused = self.focus == 4;
            }
            // Enter: follow invoke in bytecodes, or expand/collapse in heap browser
            KeyCode::Enter => {
                if self.focus == 0 && self.left_tab == LeftTab::Bytecodes {
                    self.follow_at_cursor();
                } else if self.focus == 2 && self.right_tab == RightTab::Heap {
                    self.heap_enter();
                } else if self.focus == 2 && self.right_tab == RightTab::Watch {
                    // Pre-fill command line to add a new watch expression
                    self.command_input = "watch ".to_string();
                    self.command_cursor = self.command_input.len();
                    self.command_sel_anchor = None;
                    self.focus = 4;
                    self.command_focused = true;
                } else if self.focus == 2 && self.right_tab == RightTab::Bookmarks {
                    // Pre-fill command to rename the selected bookmark
                    if let Some(bm) = self.bookmarks.get(self.bookmarks_cursor) {
                        let prefill = format!("bm {}", bm.label);
                        self.command_input = prefill;
                        self.command_cursor = self.command_input.len();
                        self.command_sel_anchor = None;
                        self.focus = 4;
                        self.command_focused = true;
                    }
                }
            }
            // Delete: remove selected watch when Watch tab is focused
            KeyCode::Delete => {
                if self.focus == 2 && self.right_tab == RightTab::Watch && !self.watches.is_empty() {
                    let idx = self.watch_selected.min(self.watches.len() - 1);
                    let removed = self.watches.remove(idx);
                    self.watch_selected = self.watch_selected.min(self.watches.len().saturating_sub(1));
                    self.log_info(&format!("Watch: removed '{}'", removed.expr));
                }
            }
            // F2: toggle breakpoint at cursor line
            KeyCode::F(2) => {
                if self.focus == 0 && self.left_tab == LeftTab::Bytecodes {
                    self.toggle_bp_at_cursor();
                }
            }
            // F-keys for stepping
            KeyCode::F(5) => self.execute_command("c"),
            KeyCode::F(7) => self.execute_command("si"),
            KeyCode::F(8) => self.execute_command("s"),
            KeyCode::F(9) => { let cmd = self.sout_cmd(); self.execute_command(cmd); }
            KeyCode::Esc => {
                // Esc in bytecodes panel with nav history: go back
                if self.focus == 0 && self.left_tab == LeftTab::Bytecodes && !self.nav_stack.is_empty() {
                    self.nav_back();
                } else {
                    self.focus = 4;
                    self.command_focused = true;
                }
            }
            _ => {}
        }
    }

    fn scroll_active(&mut self, delta: i32) {
        match self.focus {
            0 => {
                if self.left_tab == LeftTab::Trace {
                    self.trace_auto_scroll = false;
                    self.trace_scroll = apply_scroll(self.trace_scroll, delta, self.call_records.len());
                } else if self.left_tab == LeftTab::JniMonitor {
                    self.jni_monitor_scroll = apply_scroll(self.jni_monitor_scroll, delta, self.jni_natives.len());
                } else if self.left_tab == LeftTab::Ai {
                    self.ai_auto_scroll = false;
                    self.ai_scroll = apply_scroll(self.ai_scroll, delta, self.ai_output.len());
                } else {
                    self.bytecodes_auto_scroll = false;
                    self.bytecodes_scroll = apply_scroll(self.bytecodes_scroll, delta, self.bytecodes.len());
                }
            }
            1 => {
                self.locals_scroll = apply_scroll(self.locals_scroll, delta, self.locals.len());
            }
            2 => {
                if self.right_tab == RightTab::Heap {
                    let len = self.heap_display_len();
                    if len > 0 {
                        let new = (self.heap_selected as i32 + delta).max(0).min(len as i32 - 1) as usize;
                        self.heap_selected = new;
                    }
                } else if self.right_tab == RightTab::Bookmarks {
                    let len = self.bookmarks.len();
                    if len > 0 {
                        let new = (self.bookmarks_cursor as i32 + delta).max(0).min(len as i32 - 1) as usize;
                        self.bookmarks_cursor = new;
                    }
                } else if self.right_tab == RightTab::Watch {
                    let len = self.watches.len();
                    if len > 0 {
                        let new = (self.watch_selected as i32 + delta).max(0).min(len as i32 - 1) as usize;
                        self.watch_selected = new;
                    }
                } else {
                    let len = match self.right_tab {
                        RightTab::Stack => self.stack.len(),
                        RightTab::Breakpoints => self.bp_manager.breakpoints.len(),
                        RightTab::Threads => self.threads.len(),
                        RightTab::Watch | RightTab::Heap | RightTab::Bookmarks => 0,
                    };
                    self.tabbed_scroll = apply_scroll(self.tabbed_scroll, delta, len);
                }
            }
            3 => {
                self.log_auto_scroll = false;
                self.log_scroll = apply_scroll(self.log_scroll, delta, self.log.len());
            }
            _ => {}
        }
    }

    // -------------------------------------------------------------------
    // Command execution
    // -------------------------------------------------------------------

    fn execute_command(&mut self, input: &str) {
        let input = input.trim();

        // Special local commands
        match input {
            "connect" => {
                self.do_connect();
                return;
            }
            "disconnect" | "dc" => {
                self.do_disconnect();
                return;
            }
            "kill" => {
                self.do_kill();
                return;
            }
            "use sout2" => {
                self.use_sout2 = true;
                self.log_info("sout2 enabled: F9/sout now uses FramePop step-out");
                return;
            }
            "use sout" => {
                self.use_sout2 = false;
                self.log_info("sout2 disabled: F9/sout uses single-step step-out");
                return;
            }
            "quit" | "q" | "exit" => {
                self.running = false;
                return;
            }
            "help" | "?" => {
                self.show_help();
                return;
            }
            "save" => {
                self.do_save_log(None);
                return;
            }
            "ss" | "save settings" => {
                self.do_save_settings();
                return;
            }
            "r" | "regs" => {
                self.do_log_regs();
                return;
            }
            "procs" | "ps" => {
                self.do_procs();
                return;
            }
            _ => {}
        }

        if input.starts_with("save ") {
            let filename = input.splitn(2, ' ').nth(1).unwrap_or("").trim();
            self.do_save_log(Some(filename));
            return;
        }

        if input.starts_with("r ") || input.starts_with("regs ") {
            let arg = input.splitn(2, ' ').nth(1).unwrap_or("").trim();
            self.do_log_reg(arg);
            return;
        }

        // setreg vN VALUE  — set Dalvik register vN to integer/long value while suspended
        if input.starts_with("setreg ") || input.starts_with("sr ") {
            let rest = input.splitn(2, ' ').nth(1).unwrap_or("").trim();
            self.do_setreg(rest);
            return;
        }

        if input.starts_with("attach ") {
            let pkg = input.splitn(2, ' ').nth(1).unwrap_or("").trim();
            self.do_attach(pkg);
            return;
        }

        // Alias commands (pure server-side, no connection needed)
        if input == "alias" {
            self.log_info("usage: alias <class> <label>  |  alias list  |  alias clear <class|*>");
            return;
        }
        if input == "alias list" || input == "aliases" {
            if self.aliases.is_empty() {
                self.log_info("No aliases defined.");
            } else {
                let mut lines: Vec<String> = self.aliases.iter()
                    .map(|(k, v)| format!("  {} = {}", k, v))
                    .collect();
                lines.sort();
                self.log_info(&format!("{} aliases:", lines.len()));
                for line in lines {
                    self.log_info(&line);
                }
            }
            return;
        }
        if input.starts_with("alias clear ") {
            let sig = input["alias clear ".len()..].trim();
            if sig == "*" {
                self.aliases.clear();
                self.log_info("All aliases cleared.");
            } else {
                let jni = self.resolve_class(sig)
                    .unwrap_or_else(|| commands::to_jni_sig(sig));
                if self.aliases.remove(&jni).is_some() {
                    self.log_info(&format!("Alias removed: {}", jni));
                } else {
                    self.log_error(&format!("No alias for: {}", jni));
                }
            }
            return;
        }
        if input.starts_with("alias ") {
            let rest = input["alias ".len()..].trim();
            let parts: Vec<&str> = rest.splitn(2, ' ').collect();
            if parts.len() < 2 || parts[1].trim().is_empty() {
                self.log_error("usage: alias <class> <label>  e.g. alias MainActivity CertPinner");
            } else {
                let raw = parts[0].trim();
                let sig = self.resolve_class(raw)
                    .unwrap_or_else(|| commands::to_jni_sig(raw));
                let label = parts[1].trim().to_string();
                self.aliases.insert(sig.clone(), label.clone());
                self.log_info(&format!("Alias set: {} = {}  (Ctrl+S to save)", sig, label));
            }
            return;
        }

        // Hook commands (app-specific intercept rules)
        if input == "hook list" || input == "hooks" {
            if self.hooks.is_empty() {
                self.log_info("No app-specific hooks defined.");
            } else {
                let lines: Vec<String> = self.hooks.iter()
                    .map(|h| format!("  {} {} -> {}", h.class, h.method, h.action))
                    .collect();
                self.log_info(&format!("{} hooks:", lines.len()));
                for line in lines {
                    self.log_info(&line);
                }
            }
            return;
        }
        if input.starts_with("hook clear ") {
            let rest = input["hook clear ".len()..].trim();
            if rest == "*" {
                self.hooks.clear();
                self.log_info("All hooks cleared.");
            } else {
                let parts: Vec<&str> = rest.splitn(2, ' ').collect();
                if parts.len() < 2 {
                    self.log_error("usage: hook clear <class> <method>");
                } else {
                    let cls = commands::to_jni_sig(parts[0].trim());
                    let meth = parts[1].trim();
                    let before = self.hooks.len();
                    self.hooks.retain(|h| !(h.class == cls && h.method == meth));
                    if self.hooks.len() < before {
                        self.log_info(&format!("Hook removed: {} {}", cls, meth));
                    } else {
                        self.log_error(&format!("No hook for: {} {}", cls, meth));
                    }
                }
            }
            return;
        }
        if input.starts_with("hook ") {
            let rest = input["hook ".len()..].trim();
            let parts: Vec<&str> = rest.splitn(3, ' ').collect();
            if parts.len() < 3 {
                self.log_error("usage: hook <class> <method> <action>");
                self.log_error(&format!("  actions: {}", crate::session::VALID_ACTIONS.join(", ")));
            } else {
                let cls = commands::to_jni_sig(parts[0].trim());
                let meth = parts[1].trim().to_string();
                let act = parts[2].trim().to_string();
                if !crate::session::VALID_ACTIONS.contains(&act.as_str()) {
                    self.log_error(&format!("Unknown action '{}'. Use: {}", act, crate::session::VALID_ACTIONS.join(", ")));
                    return;
                }
                if let Some(existing) = self.hooks.iter_mut().find(|h| h.class == cls && h.method == meth) {
                    existing.action = act.clone();
                    self.log_info(&format!("Hook updated: {} {} -> {}  (Ctrl+S to save)", cls, meth, act));
                } else {
                    self.hooks.push(crate::session::HookRule { class: cls.clone(), method: meth.clone(), action: act.clone() });
                    self.log_info(&format!("Hook added: {} {} -> {}  (Ctrl+S to save)", cls, meth, act));
                    if self.state != AppState::Disconnected {
                        if let Some(bp_action) = condition::parse_action(&act) {
                            self.pending_bp_conditions.push_back(BreakpointCondition::for_action(bp_action));
                        }
                        self.send_command(OutboundCommand::BpSet {
                            class: cls,
                            method: meth,
                            sig: None,
                            location: None,
                        });
                    }
                }
            }
            return;
        }

        if input.starts_with("launch ") {
            let pkg = input.splitn(2, ' ').nth(1).unwrap_or("").trim();
            self.do_launch(pkg);
            return;
        }

        // Local commands with arguments
        if input.starts_with("apk ") || input.starts_with("dex ") {
            let arg = input.splitn(2, ' ').nth(1).unwrap_or("").trim();
            self.do_load_apk(arg);
            return;
        }

        // u / dis <Class.method>[:offset]  — unassemble (WinDbg-style navigate to method)
        if input.starts_with("u ") || input == "u"
            || input.starts_with("dis ") || input == "dis"
        {
            let arg = input.splitn(2, ' ').nth(1).unwrap_or("").trim();
            if arg.eq_ignore_ascii_case("pc") {
                self.jump_to_pc();
                return;
            }
            self.do_unassemble(arg);
            return;
        }

        if input.starts_with("watch ") || input == "watch" {
            let arg = input["watch".len()..].trim();
            if arg.is_empty() {
                self.log_error("usage: watch <expr>   e.g. watch key  or  watch v3.getAlgorithm()");
                self.log_error("       watch clear    remove all watches");
            } else if arg == "clear" {
                self.watches.clear();
                self.watch_selected = 0;
                self.log_info("Watch: cleared");
            } else if self.watches.iter().any(|w| w.expr == arg) {
                self.log_info(&format!("Watch: already watching '{}'", arg));
            } else {
                self.watches.push(WatchEntry { expr: arg.to_string(), last_value: None, last_type: None });
                self.log_info(&format!("Watch: added '{}'", arg));
                self.right_tab = RightTab::Watch;
                // Evaluate immediately if suspended
                if self.state == AppState::Suspended {
                    if arg.contains('.') || arg.contains('(') {
                        self.send_command(OutboundCommand::Eval { expr: arg.to_string(), depth: None });
                    } else {
                        self.refresh_watches_from_locals();
                    }
                }
            }
            return;
        }

        if input.starts_with("unwatch ") || input == "unwatch" {
            let arg = input["unwatch".len()..].trim();
            if arg.is_empty() || arg == "*" {
                let n = self.watches.len();
                self.watches.clear();
                self.watch_selected = 0;
                self.log_info(&format!("Watch: cleared ({} removed)", n));
            } else if let Ok(n) = arg.parse::<usize>() {
                if n < self.watches.len() {
                    let removed = self.watches.remove(n);
                    self.watch_selected = self.watch_selected.min(self.watches.len().saturating_sub(1));
                    self.log_info(&format!("Watch: removed #{} '{}'", n, removed.expr));
                } else {
                    self.log_error(&format!("unwatch: no watch at index {}", n));
                }
            } else if let Some(pos) = self.watches.iter().position(|w| w.expr == arg) {
                let removed = self.watches.remove(pos);
                self.watch_selected = self.watch_selected.min(self.watches.len().saturating_sub(1));
                self.log_info(&format!("Watch: removed '{}'", removed.expr));
            } else {
                self.log_error(&format!("unwatch: not watching '{}'", arg));
            }
            return;
        }

        if input.starts_with("bm ") {
            let label = input.splitn(2, ' ').nth(1).unwrap_or("").trim();
            if let Some(bm) = self.bookmarks.get_mut(self.bookmarks_cursor) {
                bm.label = label.to_string();
                self.log_info(&format!("Bookmark renamed: {}", label));
            } else {
                self.log_error("bm: no bookmark selected");
            }
            return;
        }

        if input.starts_with("nop-range ") {
            let arg = input.splitn(2, ' ').nth(1).unwrap_or("").trim();
            let parsed = if let Some(hex) = arg.strip_prefix("0x").or_else(|| arg.strip_prefix("0X")) {
                u32::from_str_radix(hex, 16).ok()
            } else {
                arg.parse::<u32>().ok()
            };
            match parsed {
                Some(bci) => self.do_nop_range_patch(bci),
                None => self.log_error("usage: nop-range 0xOFFSET"),
            }
            return;
        }

        if input.starts_with("strings ") || input.starts_with("str ") {
            let pattern = input.splitn(2, ' ').nth(1).unwrap_or("").trim();
            self.do_dex_string_search(pattern);
            return;
        }

        if input.starts_with("xref-bp ") {
            let pattern = input.splitn(2, ' ').nth(1).unwrap_or("").trim();
            self.do_xref(pattern, true);
            return;
        }

        if input.starts_with("xref ") {
            let pattern = input.splitn(2, ' ').nth(1).unwrap_or("").trim();
            self.do_xref(pattern, false);
            return;
        }

        if input == "dex-dump" {
            if self.state == AppState::Disconnected {
                self.log_error("Not connected. Use 'connect' first.");
            } else if self.state != AppState::Suspended {
                self.log_error("dex-dump: must be suspended at a DexClassLoader breakpoint");
            } else {
                self.log_info("[DEX] Sending dex-dump command...");
                self.send_command(OutboundCommand::DexDump {});
            }
            return;
        }

        // hexdump with optional "full" flag
        if input.starts_with("hexdump ") || input.starts_with("hd ") {
            let args = input.splitn(2, ' ').nth(1).unwrap_or("").trim();
            let full = args.ends_with(" full");
            let clean = if full { args.trim_end_matches(" full").trim() } else { args };
            self.hexdump_full = full;
            let synthetic = format!("hd {}", clean);
            match commands::parse_command(&synthetic) {
                Ok(cmd) => {
                    if self.state == AppState::Disconnected {
                        self.log_error("Not connected. Use 'connect' first.");
                    } else if self.state != AppState::Suspended {
                        self.log_error("Not suspended. hexdump requires a suspended thread.");
                    } else {
                        self.send_command(cmd);
                    }
                }
                Err(e) => self.log_error(&e),
            }
            return;
        }

        if input.starts_with("dex-read ") {
            let path = input.splitn(2, ' ').nth(1).unwrap_or("").trim();
            if path.is_empty() {
                self.log_error("usage: dex-read <path>");
            } else if self.state == AppState::Disconnected {
                self.log_error("Not connected. Use 'connect' first.");
            } else {
                self.log_info(&format!("[DEX] Sending dex-read for: {}", path));
                self.send_command(OutboundCommand::DexRead { path: path.to_string() });
            }
            return;
        }

        // Call recording commands
        if input == "record" || input == "rec" {
            // Toggle
            if self.recording_active {
                self.do_record_stop();
            } else {
                self.do_record_start();
            }
            return;
        }
        if input == "record start" || input == "rec start" {
            self.do_record_start();
            return;
        }
        if input == "record stop" || input == "rec stop" {
            self.do_record_stop();
            return;
        }

        // JNI monitor / redirect
        if input == "jni monitor" || input == "jni start" {
            self.do_jni_monitor_start();
            return;
        }
        if input == "jni stop" || input == "jni unhook" {
            self.do_jni_monitor_stop();
            return;
        }
        if input == "jni clear" {
            self.jni_natives.clear();
            self.jni_monitor_scroll = 0;
            self.log_info("JNI native list cleared");
            return;
        }
        if let Some(rest) = input.strip_prefix("jni redirect ") {
            self.do_jni_redirect(rest);
            return;
        }
        if let Some(rest) = input.strip_prefix("jni restore ") {
            self.do_jni_restore(rest);
            return;
        }
        if input == "record clear" || input == "rec clear" {
            self.call_records.clear();
            self.trace_depth.clear();
            self.trace_scroll = 0;
            self.log_info("Call records cleared");
            return;
        }
        if input == "record flat" || input == "rec flat"
            || input == "record simple" || input == "rec simple"
        {
            self.trace_flat = true;
            self.log_info("Trace mode: flat (no tree indentation)");
            return;
        }
        if input == "record tree" || input == "rec tree" {
            self.trace_flat = false;
            self.log_info("Trace mode: tree (indented call tree)");
            return;
        }
        if input == "record onenter" || input == "rec onenter" {
            self.trace_onenter = !self.trace_onenter;
            if self.trace_onenter {
                self.log_info("Trace: entry-only (no exit/return records)");
            } else {
                self.log_info("Trace: entry + exit records");
            }
            return;
        }

        // AI commands
        if input == "ai cancel" {
            self.do_ai_cancel();
            return;
        }
        if input.starts_with("ai ") || input == "ai" {
            self.parse_ai_command(input);
            return;
        }

        // Clear all breakpoints: bd * / bc *
        if input == "bd *" || input == "bc *" {
            self.do_clear_all_breakpoints();
            return;
        }

        if input == "bypass-ssl" {
            self.do_bypass_ssl();
            return;
        }

        if input.starts_with("anti") || input.starts_with("bypass-anti") {
            self.do_anti(input);
            return;
        }

        // Breakpoint profiles (may have trailing condition flags)
        if input.starts_with("bp-") {
            self.do_bp_profile(input);
            return;
        }

        // bp/break with possible condition flags (--hits, --every, --when)
        if input.starts_with("bp2 ") {
            let args = input.splitn(2, ' ').nth(1).unwrap_or("").trim();
            match condition::parse_condition_flags(args) {
                Ok((clean_args, cond)) => {
                    let synthetic = format!("bp {}", clean_args);
                    match commands::parse_command(&synthetic) {
                        Ok(cmd) => {
                            if self.state == AppState::Disconnected {
                                self.log_error("Not connected. Use 'connect' first.");
                                return;
                            }
                            // Convert BpSet -> BpSetDeopt
                            let cmd = if let OutboundCommand::BpSet { class, method, sig, location } = cmd {
                                OutboundCommand::BpSetDeopt { class, method, sig, location }
                            } else { cmd };
                            let cmd = self.resolve_bp_class(cmd, cond.clone());
                            if let Some(cmd) = cmd {
                                self.pending_bp_cond = cond;
                                self.send_command(cmd);
                            }
                        }
                        Err(e) => self.log_error(&e),
                    }
                }
                Err(e) => self.log_error(&format!("condition parse error: {}", e)),
            }
            return;
        }

        // Expand "bp here" / "break here" to "bp <class> <method> @<offset>"
        let input_owned;
        let input = if (input.starts_with("bp ") || input.starts_with("break "))
            && input.splitn(2, ' ').nth(1).unwrap_or("").trim() == "here"
        {
            match (&self.current_class.clone(), &self.current_method.clone()) {
                (Some(cls), Some(method)) => {
                    let offset = self.bytecodes_cursor
                        .and_then(|i| self.bytecodes.get(i))
                        .map(|instr| format!(" @0x{:04x}", instr.offset))
                        .unwrap_or_default();
                    input_owned = format!("bp {} {}{}", cls, method, offset);
                    input_owned.as_str()
                }
                _ => {
                    self.log_error("Not stopped in any method");
                    return;
                }
            }
        } else {
            input
        };

        if input.starts_with("bp ") || input.starts_with("break ") {
            let args = input.splitn(2, ' ').nth(1).unwrap_or("").trim();
            match condition::parse_condition_flags(args) {
                Ok((clean_args, cond)) => {
                    let synthetic = format!("bp {}", clean_args);
                    match commands::parse_command(&synthetic) {
                        Ok(cmd) => {
                            if self.state == AppState::Disconnected {
                                self.log_error("Not connected. Use 'connect' first.");
                                return;
                            }
                            // Resolve short class names before sending
                            let cmd = self.resolve_bp_class(cmd, cond.clone());
                            if let Some(cmd) = cmd {
                                self.pending_bp_cond = cond;
                                self.send_command(cmd);
                            }
                        }
                        Err(e) => self.log_error(&e),
                    }
                }
                Err(e) => self.log_error(&format!("condition parse error: {}", e)),
            }
            return;
        }

        // Patch method via JVMTI RedefineClasses
        if input.starts_with("patch ") {
            let args = input["patch ".len()..].trim();
            if args == "?" {
                self.log_info("patch <class> <method> <value>");
                self.log_info("  values:  void  true  false  null  0  1");
                self.log_info("  example: patch Lcom/example/MainActivity; testDetect void");
                self.log_info("  example: patch Lcom/example/MainActivity; testDetect true");
                self.log_info("  example: patch Lcom/example/MainActivity; testDetect 0");
                self.log_info("  nop:     patch Lcom/example/MainActivity; testDetect @0x002a:2 nop");
                self.log_info("  short:   patch MainActivity testDetect true  (partial class name ok)");
                return;
            }
            self.do_patch(args);
            return;
        }
        if input == "patch" {
            self.log_info("usage: patch <class> <method> <value>  -- type 'patch ?' for examples");
            return;
        }

        // Block step commands when suspended at a native method — JVMTI single-step
        // only fires on Java bytecodes, so stepping from native just resumes execution
        // until some arbitrary Java instruction fires, which is indistinguishable from
        // a plain continue.  Tell the user to press F5 instead.
        if self.current_loc == Some(-1) && self.state == AppState::Suspended
            && matches!(input, "si" | "step_into"
                             | "s" | "so" | "step_over" | "n" | "next"
                             | "sout" | "step_out" | "finish"
                             | "sout2" | "step_out2")
        {
            self.log_info("Stopped in native method - use F5 to resume");
            return;
        }

        // inspect/i by name: "inspect suPaths" → look up slot in app.locals
        if let Some(arg) = input.strip_prefix("inspect ").or_else(|| input.strip_prefix("i ")) {
            let arg = arg.trim();
            // Only intercept if arg is not already a slot (vN or plain number)
            let is_slot = arg.strip_prefix('v').unwrap_or(arg).parse::<i32>().is_ok();
            if !is_slot {
                if let Some(local) = self.locals.iter().find(|l| l.name == arg) {
                    let slot = local.slot;
                    self.send_command(OutboundCommand::Inspect { slot, depth: None });
                } else {
                    self.log_error(&format!("'{}' not found in locals", arg));
                }
                return;
            }
        }

        // here - print current class.method [@offset] in JADX dot notation
        if input == "here" {
            match (&self.current_class.clone(), &self.current_method.clone()) {
                (Some(cls), Some(method)) => {
                    let dot = cls
                        .strip_prefix('L').unwrap_or(cls)
                        .strip_suffix(';').unwrap_or(cls)
                        .replace('/', ".");
                    let loc = self.bytecodes_cursor
                        .and_then(|i| self.bytecodes.get(i))
                        .map(|instr| format!(" {:03x}", instr.offset));
                    self.log_info(&format!("{}.{}{}", dot, method, loc.unwrap_or_default()));
                }
                _ => self.log_info("Not stopped in any method"),
            }
            return;
        }

        // Gate release: set BP on GateWait.gateReleased then delete the gate file
        if input == "gate" {
            if self.state == AppState::Disconnected {
                self.log_error("Not connected.");
                return;
            }
            self.send_command(OutboundCommand::BpSet {
                class: "Lcom/dexbgd/GateWait;".to_string(),
                method: "gateReleased".to_string(),
                sig: Some("()V".to_string()),
                location: None,
            });
            self.send_command(OutboundCommand::GateRelease {});
            self.log_info("[gate] BP set on GateWait.gateReleased -- gate file deleted, app will resume");
            return;
        }

        // Parse as agent command
        match commands::parse_command(input) {
            Ok(cmd) => {
                if self.state == AppState::Disconnected {
                    self.log_error("Not connected. Use 'connect' first.");
                    return;
                }
                self.send_command(cmd);
            }
            Err(e) => {
                self.log_error(&e);
            }
        }
    }

    // -------------------------------------------------------------------
    // Bytecodes cursor, F2 breakpoint toggle, double-click follow, Esc back
    // -------------------------------------------------------------------

    /// Compute effective scroll position for bytecodes panel.
    pub fn effective_bytecodes_scroll(&self, panel_height: u16) -> usize {
        let inner_height = panel_height.saturating_sub(2) as usize;
        let code_height = inner_height.saturating_sub(1); // 1 for header
        if self.bytecodes_auto_scroll {
            if let Some(loc) = self.current_loc {
                if let Some(idx) = self.bytecodes.iter().position(|i| i.offset == loc as u32) {
                    return idx.saturating_sub(2);
                }
            }
            self.bytecodes_scroll
        } else {
            self.bytecodes_scroll
        }
    }

    /// Ensure the cursor is visible by adjusting scroll if needed.
    fn ensure_cursor_visible(&mut self) {
        if let Some(cursor) = self.bytecodes_cursor {
            // Estimate visible height (use layout_geom if available)
            let code_height = self.layout_geom.as_ref()
                .map(|g| g.bytecodes_area.height.saturating_sub(2).saturating_sub(1) as usize)
                .unwrap_or(20);
            if code_height == 0 { return; }

            // When cursor is moved, switch to manual scroll
            self.bytecodes_auto_scroll = false;
            if cursor < self.bytecodes_scroll {
                self.bytecodes_scroll = cursor;
            } else if cursor >= self.bytecodes_scroll + code_height {
                self.bytecodes_scroll = cursor.saturating_sub(code_height - 1);
            }
        }
    }

    /// Toggle breakpoint at the cursor line (F2).
    fn toggle_bp_at_cursor(&mut self) {
        let idx = match self.bytecodes_cursor {
            Some(i) => i,
            None => return,
        };
        let instr = match self.bytecodes.get(idx) {
            Some(i) => i,
            None => return,
        };
        let cls = match &self.current_class {
            Some(c) => c.clone(),
            None => return,
        };
        let meth = match &self.current_method {
            Some(m) => m.clone(),
            None => return,
        };

        // Check if a breakpoint already exists at this location → toggle off
        let offset = instr.offset as i64;
        if let Some(bp) = self.bp_manager.breakpoints.iter().find(|bp| {
            bp.class == cls && bp.method == meth && bp.location == offset
        }) {
            let id = bp.id;
            let cmd = format!("bd {}", id);
            self.execute_command(&cmd);
        } else {
            let cmd = format!("bp {} {} @0x{:04x}", cls, meth, instr.offset);
            self.execute_command(&cmd);
        }
    }

    /// Nop range patch: replace instructions in [current_loc..to_bci) with
    /// zero-initializers so execution falls through to `to_bci` (forward jump),
    /// or insert a goto for a backward jump. Takes effect at next method entry.
    fn do_nop_range_patch(&mut self, to_bci: u32) {
        let from_bci = match self.current_loc {
            Some(loc) => loc as u32,
            None => { self.log_error("nop-range: no suspended thread"); return; }
        };

        if from_bci == to_bci {
            self.log_error("nop-range: target is already the current PC");
            return;
        }

        // Validate that to_bci lands on a real instruction boundary (prevents jumping
        // into the middle of a multi-code-unit instruction, which ART rejects).
        if !self.bytecodes.iter().any(|i| i.offset == to_bci) {
            self.log_error(&format!(
                "nop-range: BCI={} is not a valid instruction start \
                 (not in disassembly — may be inside a multi-CU instruction)", to_bci));
            return;
        }

        // Width of the from_bci instruction (only used for backward goto).
        let instr_width = self.bytecodes.iter()
            .find(|i| i.offset == from_bci)
            .map(|i| i.width)
            .unwrap_or(1);

        let class_sig = match &self.current_class {
            Some(c) => c.clone(),
            None => { self.log_error("nop-range: no class loaded"); return; }
        };
        let method_name = match &self.current_method {
            Some(m) => m.clone(),
            None => { self.log_error("nop-range: no method loaded"); return; }
        };

        let raw_bytes = match self.dex_data.iter().find(|d| d.has_class(&class_sig)) {
            Some(d) => d.raw.clone(),
            None => { self.log_error("nop-range: DEX raw bytes not available"); return; }
        };

        match crate::dex_patcher::patch_goto(&raw_bytes, &class_sig, &method_name,
                                              from_bci, to_bci, instr_width) {
            Ok(patched) => {
                let (stored, computed) = crate::dex_patcher::check_adler32(&patched);
                if stored != computed {
                    self.log_error("[NOP RANGE] adler32 mismatch after patching - aborting");
                    return;
                }
                let _ = std::fs::write("patch_debug.dex", &patched);
                let dex_b64 = BASE64.encode(&patched);
                let delta = to_bci as i64 - from_bci as i64;
                let strategy = if delta > 0 { "preinit-sled" } else { "goto" };
                self.log_info(&format!(
                    "[NOP RANGE] @{:04x} -> @{:04x} (delta {:+})  {} redefining class...",
                    from_bci, to_bci, delta, strategy
                ));
                self.log_info("[NOP RANGE] takes effect at next method entry (not current frame)");
                self.send_command(crate::protocol::OutboundCommand::RedefineClass {
                    class_sig,
                    dex_b64,
                    return_value: None,
                });
            }
            Err(e) => {
                self.log_error(&format!("[NOP RANGE] {}", e));
            }
        }
    }

    /// Permanently patch a conditional branch to always be taken or not taken.
    /// Uses RedefineClasses; takes effect at next method entry.
    fn do_patch_branch_force(&mut self, bci: u32, taken: bool) {
        let class_sig = match &self.current_class {
            Some(c) => c.clone(),
            None => { self.log_error("patch branch: no class loaded"); return; }
        };
        let method_name = match &self.current_method {
            Some(m) => m.clone(),
            None => { self.log_error("patch branch: no method loaded"); return; }
        };
        let raw_bytes = match self.dex_data.iter().find(|d| d.has_class(&class_sig)) {
            Some(d) => d.raw.clone(),
            None => { self.log_error("patch branch: DEX not loaded"); return; }
        };
        match crate::dex_patcher::patch_branch_force(&raw_bytes, &class_sig, &method_name, bci) {
            Ok(patched) => {
                let (stored, computed) = crate::dex_patcher::check_adler32(&patched);
                if stored != computed {
                    self.log_error("[PATCH BRANCH] adler32 mismatch - aborting");
                    return;
                }
                let dex_b64 = BASE64.encode(&patched);
                self.log_info(&format!(
                    "[PATCH BRANCH] @{:04x}: opcode inverted => {} (permanent) - redefining class...",
                    bci, if taken { "forced taken" } else { "forced not taken" }
                ));
                self.log_info("[PATCH BRANCH] takes effect at next method entry");
                self.send_command(crate::protocol::OutboundCommand::RedefineClass {
                    class_sig,
                    dex_b64,
                    return_value: None,
                });
            }
            Err(e) => {
                self.log_error(&format!("[PATCH BRANCH] {}", e));
            }
        }
    }

    /// Follow instruction at cursor: invoke → disassemble target method,
    /// branch/goto → jump to target offset within current method.
    fn follow_at_cursor(&mut self) {
        let idx = match self.bytecodes_cursor {
            Some(i) => i,
            None => {
                self.log_debug("Follow: no cursor selected");
                return;
            }
        };
        let instr = match self.bytecodes.get(idx) {
            Some(i) => i.clone(),
            None => return,
        };

        // Branch/goto: jump to target offset within same method
        if let Some(ref branch) = instr.branch {
            let target_offset = branch.target;
            if let Some(target_idx) = self.bytecodes.iter().position(|i| i.offset == target_offset) {
                // Push current position to nav stack for Esc-back
                self.nav_stack.push(NavEntry {
                    class: self.current_class.clone(),
                    method: self.current_method.clone(),
                    bytecodes: self.bytecodes.clone(),
                    scroll: self.bytecodes_scroll,
                    cursor: self.bytecodes_cursor,
                    current_loc: self.current_loc,
                });
                // Place cursor 2 lines before target (context), clamped to 0
                self.bytecodes_cursor = Some(target_idx);
                self.bytecodes_auto_scroll = false;
                self.bytecodes_scroll = target_idx.saturating_sub(2);
            }
            return;
        }

        // Invoke: disassemble target method
        let mid = match instr.method_idx {
            Some(m) => m,
            None => {
                self.log_debug("Follow: not an invoke or branch instruction");
                return;
            }
        };

        // Look up class + method from the correct DexData (same one used for disassembly)
        let current_cls = self.current_class.clone().unwrap_or_default();
        let mut target_class = None;
        let mut target_method = None;

        // Use the DexData that defines the current class (same as used for disassembly)
        if let Some(dex) = self.find_dex_for_class(&current_cls) {
            if let Some(mref) = dex.methods.get(mid as usize) {
                target_class = Some(mref.class_name.clone());
                target_method = Some(mref.method_name.clone());
            }
        }

        // Fallback: try all dex_data
        if target_class.is_none() {
            for dex in &self.dex_data {
                if let Some(mref) = dex.methods.get(mid as usize) {
                    target_class = Some(mref.class_name.clone());
                    target_method = Some(mref.method_name.clone());
                    break;
                }
            }
        }

        let (target_cls, target_meth) = match (target_class, target_method) {
            (Some(c), Some(m)) => (c, m),
            _ => {
                self.log_error(&format!("Cannot follow: method_idx {} not found in DEX data", mid));
                return;
            }
        };

        // Check if the target class is defined in any loaded DEX (app class vs framework)
        let is_app_class = self.dex_data.iter().any(|d| d.has_class(&target_cls));
        if !is_app_class {
            let short = short_class(&target_cls);
            self.log_info(&format!("Cannot follow {}.{}  - framework/system class", short, target_meth));
            return;
        }

        // Push current view to nav stack
        self.nav_stack.push(NavEntry {
            class: self.current_class.clone(),
            method: self.current_method.clone(),
            bytecodes: self.bytecodes.clone(),
            scroll: self.bytecodes_scroll,
            cursor: self.bytecodes_cursor,
            current_loc: self.current_loc,
        });

        // Send dis command for the target method
        let short = short_class(&target_cls);
        self.log_debug(&format!("Following {}.{}...", short, target_meth));
        let cmd = format!("dis {} {}", target_cls, target_meth);
        self.execute_command(&cmd);
        self.bytecodes_cursor = None;
        self.pending_follow = true;
    }

    /// Navigate to a method by JNI class signature + method name, pushing the current
    /// view to the nav stack.  If `scroll_to` is `Some(offset)`, the disassembly will
    /// be scrolled to the instruction at that bytecode offset once it loads.
    fn navigate_to_method(&mut self, class_sig: &str, method_name: &str, scroll_to: Option<i64>) {
        self.nav_stack.push(NavEntry {
            class: self.current_class.clone(),
            method: self.current_method.clone(),
            bytecodes: self.bytecodes.clone(),
            scroll: self.bytecodes_scroll,
            cursor: self.bytecodes_cursor,
            current_loc: self.current_loc,
        });
        self.pending_dis_scroll_location = scroll_to;
        self.pending_follow = true;
        self.send_command(OutboundCommand::Dis {
            class: class_sig.to_string(),
            method: method_name.to_string(),
            sig: None,
        });
        self.bytecodes_cursor = None;
        self.focus = 0;
        self.left_tab = LeftTab::Bytecodes;
    }

    /// Toggle a bookmark at the current bytecodes cursor position (Ctrl+B).
    fn toggle_bookmark_at_cursor(&mut self) {
        let cls = match &self.current_class {
            Some(c) => c.clone(),
            None => { self.log_info("Bookmark: no method loaded"); return; }
        };
        let meth = match &self.current_method {
            Some(m) => m.clone(),
            None => { self.log_info("Bookmark: no method loaded"); return; }
        };
        let offset = match self.bytecodes_cursor.and_then(|i| self.bytecodes.get(i)) {
            Some(instr) => instr.offset as i64,
            None => 0,
        };

        // If a bookmark already exists at this exact location, remove it
        if let Some(pos) = self.bookmarks.iter().position(|bm| {
            bm.class == cls && bm.method == meth && bm.offset == offset
        }) {
            let removed = self.bookmarks.remove(pos);
            self.log_info(&format!("Bookmark removed: {}", removed.label));
        } else {
            let short = crate::commands::short_class(&cls);
            let label = format!("{}.{}+{:#x}", short, meth, offset);
            self.bookmarks.push(Bookmark { class: cls, method: meth, offset, label: label.clone() });
            self.log_info(&format!("Bookmark added: {}", label));
        }
    }

    /// Navigate back to previous disassembly view (Esc).
    fn nav_back(&mut self) {
        if let Some(entry) = self.nav_stack.pop() {
            self.current_class = entry.class;
            self.current_method = entry.method;
            self.bytecodes = entry.bytecodes;
            self.bytecodes_scroll = entry.scroll;
            self.bytecodes_cursor = entry.cursor;
            self.current_loc = entry.current_loc;
            self.bytecodes_auto_scroll = false;
        }
    }

    fn do_connect(&mut self) {
        if self.state != AppState::Disconnected {
            self.log_error("Already connected");
            return;
        }

        self.log_info("Connecting to 127.0.0.1:12345...");

        match TcpStream::connect("127.0.0.1:12345") {
            Ok(stream) => {
                stream.set_nodelay(true).ok();
                let (rx, tx) = connection::spawn_io_thread(stream);
                self.agent_rx = Some(rx);
                self.cmd_tx = Some(tx);
                self.retry_timer = None;
                self.log_info("TCP connected, waiting for agent handshake...");
            }
            Err(e) => {
                self.log_error(&format!("Connect failed: {}", e));
                if self.config.auto_connect_retry {
                    self.retry_timer = Some(std::time::Instant::now());
                }
            }
        }
    }

    fn do_save_session(&mut self) {
        let pkg = match self.current_package.clone() {
            Some(p) => p,
            None => {
                if self.state == AppState::Disconnected {
                    self.log_info("Not connected.");
                } else {
                    self.log_info("Package name not available -- rebuild agent to enable sessions.");
                }
                return;
            }
        };
        let session = crate::session::Session {
            aliases: self.aliases.clone(),
            comments: self.comments.iter().map(|((cls, meth, bci), val)| {
                (format!("{} {} {}", cls, meth, bci), val.clone())
            }).collect(),
            hooks: self.hooks.clone(),
            bookmarks: self.bookmarks.iter().map(|bm| crate::session::SessionBookmark {
                class: bm.class.clone(),
                method: bm.method.clone(),
                offset: bm.offset,
                label: bm.label.clone(),
            }).collect(),
            startup_commands: vec![
                "# Commands here run automatically after APK symbols load on connect".to_string(),
                "# anti com.example.Security isRooted false".to_string(),
                "# anti com.example.License check true".to_string(),
            ],
        };
        match session.save(&pkg) {
            Ok(path) => self.log_info(&format!("Session saved: {}", path.display())),
            Err(e)   => self.log_error(&format!("Session save failed: {}", e)),
        }
    }

    fn load_session(&mut self, pkg: &str) {
        let session = match crate::session::Session::load(pkg) {
            Ok(Some(s)) => s,
            Ok(None) => return,
            Err(e) => {
                self.log_error(&e);
                return;
            }
        };
        let ac = session.aliases.len();
        let cc = session.comments.len();
        let hc = session.hooks.len();
        let bc = session.bookmarks.len();

        self.aliases = session.aliases;
        for (key, val) in session.comments {
            let parts: Vec<&str> = key.splitn(3, ' ').collect();
            if parts.len() == 3 {
                if let Ok(bci) = parts[2].parse::<u32>() {
                    self.comments.insert((parts[0].to_string(), parts[1].to_string(), bci), val);
                }
            }
        }
        self.bookmarks = session.bookmarks.iter().map(|b| Bookmark {
            class: b.class.clone(),
            method: b.method.clone(),
            offset: b.offset,
            label: b.label.clone(),
        }).collect();
        self.hooks = session.hooks.clone();

        // Re-apply hooks as breakpoints with actions
        for hook in &session.hooks {
            if let Some(action) = condition::parse_action(&hook.action) {
                self.pending_bp_conditions.push_back(BreakpointCondition::for_action(action));
                self.send_command(OutboundCommand::BpSet {
                    class: hook.class.clone(),
                    method: hook.method.clone(),
                    sig: None,
                    location: None,
                });
            }
        }

        let cmds: Vec<String> = session.startup_commands.into_iter()
            .filter(|c| !c.trim_start().starts_with('#') && !c.trim().is_empty())
            .collect();
        let sc = cmds.len();

        self.log_info(&format!(
            "Session loaded: {} aliases, {} comments, {} hooks, {} bookmarks, {} startup commands",
            ac, cc, hc, bc, sc
        ));

        if !self.dex_data.is_empty() {
            // APK already loaded — execute now
            self.run_startup_commands(cmds);
        } else {
            // APK not loaded yet — defer until do_load_apk finishes
            self.session_startup_queue = cmds;
        }
    }

    fn sout_cmd(&self) -> &'static str {
        if self.use_sout2 && self.cap_frame_pop { "sout2" } else { "sout" }
    }

    fn run_startup_commands(&mut self, cmds: Vec<String>) {
        for cmd in cmds {
            self.log_info(&format!("[startup] > {}", cmd));
            self.execute_command(&cmd);
        }
    }

    fn open_session_picker(&mut self) {
        let dir = match crate::session::session_dir() {
            Some(d) => d,
            None => {
                self.log_error("Cannot determine sessions directory");
                return;
            }
        };
        let mut packages: Vec<String> = std::fs::read_dir(&dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|entry| {
                let name = entry.file_name().into_string().ok()?;
                name.strip_suffix(".json").map(|s| s.to_string())
            })
            .collect();
        packages.sort();
        self.session_picker_list = packages;
        self.session_picker_sel = 0;
        self.session_picker_open = true;
    }

    fn handle_session_picker_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.session_picker_open = false;
            }
            KeyCode::Up => {
                if self.session_picker_sel > 0 {
                    self.session_picker_sel -= 1;
                }
            }
            KeyCode::Down => {
                if self.session_picker_sel + 1 < self.session_picker_list.len() {
                    self.session_picker_sel += 1;
                }
            }
            KeyCode::Enter => {
                if let Some(pkg) = self.session_picker_list.get(self.session_picker_sel).cloned() {
                    self.session_picker_open = false;
                    self.do_launch(&pkg);
                }
            }
            _ => {}
        }
    }

    fn do_save_settings(&mut self) {
        match self.config.write_ini(
            self.theme_index,
            self.split_h,
            self.split_v,
            self.split_right_v,
            &self.command_history,
        ) {
            Ok(path) => self.log_info(&format!("Settings saved to {}", path.display())),
            Err(e) => self.log_error(&format!("Save settings failed: {}", e)),
        }
    }

    /// setreg vN VALUE — set Dalvik register vN to a value while suspended.
    /// Looks up the register's type from the current locals to determine the JVMTI call.
    fn do_setreg(&mut self, rest: &str) {
        // Parse: vN VALUE  (e.g. "v0 42" or "v3 -1")
        let parts: Vec<&str> = rest.splitn(2, ' ').collect();
        if parts.len() != 2 {
            self.log_error("Usage: setreg vN VALUE (e.g. setreg v0 42)");
            return;
        }
        let reg_str = parts[0].trim();
        let val_str = parts[1].trim();
        let slot: i32 = if let Some(n) = reg_str.strip_prefix('v') {
            match n.parse::<i32>() {
                Ok(v) => v,
                Err(_) => { self.log_error("Usage: setreg vN VALUE (e.g. setreg v0 42)"); return; }
            }
        } else {
            self.log_error("Usage: setreg vN VALUE (e.g. setreg v0 42)");
            return;
        };
        let value: i64 = match val_str.parse::<i64>() {
            Ok(v) => v,
            Err(_) => {
                // Try hex (0x...)
                if let Some(hex) = val_str.strip_prefix("0x").or_else(|| val_str.strip_prefix("0X")) {
                    match i64::from_str_radix(hex, 16) {
                        Ok(v) => v,
                        Err(_) => { self.log_error(&format!("Invalid value: {}", val_str)); return; }
                    }
                } else {
                    self.log_error(&format!("Invalid value: {}", val_str));
                    return;
                }
            }
        };
        if !matches!(self.state, AppState::Suspended | AppState::Stepping) {
            self.log_error("Not suspended - setreg only works while at a breakpoint or step");
            return;
        }
        // Look up type hint from locals
        let type_hint = self.locals.iter()
            .find(|v| v.slot == slot)
            .map(|v| {
                match v.var_type.as_str() {
                    "long" | "J"  => "J",
                    "float" | "F" => "F",
                    "double" | "D" => "D",
                    _ => "I",
                }
            })
            .unwrap_or("I")
            .to_string();
        self.log_info(&format!("setreg v{} = {} (type {})", slot, value, type_hint));
        self.send_command(OutboundCommand::SetLocal { slot, value, type_hint: Some(type_hint) });
        self.send_command(OutboundCommand::Locals {});
        self.send_command(OutboundCommand::Regs {});
    }

    fn do_kill(&mut self) {
        let pkg = match self.current_package.clone() {
            Some(p) => p,
            None => {
                self.log_error("No package connected");
                return;
            }
        };
        self.log_info(&format!("Killing {}...", pkg));
        match std::process::Command::new("adb")
            .args(["shell", "am", "force-stop", &pkg])
            .output()
        {
            Ok(_) => self.log_info("App terminated"),
            Err(e) => self.log_error(&format!("adb failed: {}", e)),
        }
        // Disconnect will happen automatically when the socket closes,
        // but call it now to update state immediately.
        self.do_disconnect();
    }

    fn do_disconnect(&mut self) {
        self.agent_rx = None;
        self.cmd_tx = None;
        self.state = AppState::Disconnected;
        self.pending_bp_cond = None;
        self.pending_bp_conditions.clear();
        self.pending_cond_eval = None;
        self.pending_bp_resolve = None;
        self.cls_auto_pending = false;
        self.anti_bps.clear();
        self.pending_anti_count = 0;
        self.threads.clear();
        self.log_info("Disconnected");
    }

    /// Total display lines for the heap browser.
    fn heap_display_len(&self) -> usize {
        self.heap_rows.len()
    }

    /// Handle Enter key on the heap browser: expand/collapse objects.
    fn heap_enter(&mut self) {
        if self.heap_selected >= self.heap_rows.len() { return; }

        match &self.heap_rows[self.heap_selected] {
            HeapRow::Object { index, value } => {
                self.log_info(&format!("[{}] {}", index, value));
            }
            HeapRow::StringMatch { index, value } => {
                self.log_info(&format!("[{}] {}", index, value));
            }
            HeapRow::Header(_) => {}
        }
    }

    fn do_log_regs(&mut self) {
        if self.state != AppState::Suspended {
            self.log_error("Not suspended. Registers only available when paused at a breakpoint.");
            return;
        }
        if self.regs.is_empty() {
            self.log_info("Requesting registers from agent...");
            self.pending_regs_log = true;
            self.send_command(OutboundCommand::Regs {});
            return;
        }
        self.log_regs_to_output();
    }

    fn log_regs_to_output(&mut self) {
        let regs: Vec<_> = self.regs.iter().map(|r| (r.slot, r.value)).collect();
        self.log_info(&format!("Registers ({} slots):", regs.len()));
        for (slot, value) in &regs {
            self.log_info(&format!("  v{} = {} (0x{:x})", slot, value, value));
        }
    }

    fn do_log_reg(&mut self, arg: &str) {
        if self.state != AppState::Suspended {
            self.log_error("Not suspended. Registers only available when paused at a breakpoint.");
            return;
        }

        // Parse arg: "v4" → slot 4, or a local variable name
        if let Some(slot_str) = arg.strip_prefix('v') {
            if let Ok(slot) = slot_str.parse::<i32>() {
                // Look up in locals first (has name + type + value)
                if let Some(local) = self.locals.iter().find(|l| l.slot == slot) {
                    self.log_info(&format!("v{} ({}: {}) = {}", slot, local.name, commands::short_type(&local.var_type), local.value));
                    return;
                }
                // Fall back to raw register value
                if let Some(reg) = self.regs.iter().find(|r| r.slot == slot) {
                    self.log_info(&format!("v{} = {} (0x{:x})", slot, reg.value, reg.value));
                    return;
                }
                // Neither found  - request from agent
                self.log_info(&format!("v{}: not in cached locals/regs. Requesting inspect...", slot));
                self.send_command(OutboundCommand::Inspect { slot, depth: None });
                return;
            }
        }

        // Try to find by local variable name
        if let Some(local) = self.locals.iter().find(|l| l.name == arg) {
            self.log_info(&format!("v{} ({}: {}) = {}", local.slot, local.name, commands::short_type(&local.var_type), local.value));
            return;
        }

        self.log_error(&format!("'{}' not found. Use 'r vN' for slot or 'r name' for local variable.", arg));
    }

    fn do_save_log(&mut self, filename: Option<&str>) {
        use std::io::Write;
        use std::time::SystemTime;

        let path = match filename {
            Some(f) if !f.is_empty() => f.to_string(),
            _ => {
                let secs = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                format!("dexbgd_{}.log", secs)
            }
        };

        let mut content = String::new();
        for entry in &self.log {
            let prefix = match entry.level {
                LogLevel::Info => "[INFO]",
                LogLevel::Error => "[ERR ]",
                LogLevel::Crypto => "[CRYP]",
                LogLevel::Exception => "[EXCP]",
                LogLevel::Debug => "[DBG ]",
                LogLevel::Agent => "[AGNT]",
                LogLevel::Call => "[CALL]",
            };
            content.push_str(prefix);
            content.push(' ');
            content.push_str(&entry.text);
            content.push('\n');
        }

        match std::fs::File::create(&path) {
            Ok(mut f) => {
                match f.write_all(content.as_bytes()) {
                    Ok(_) => self.log_info(&format!("Log saved to {} ({} lines)", path, self.log.len())),
                    Err(e) => self.log_error(&format!("Failed to write {}: {}", path, e)),
                }
            }
            Err(e) => self.log_error(&format!("Failed to create {}: {}", path, e)),
        }
    }

    // -------------------------------------------------------------------
    // ADB commands: procs, attach, launch
    // -------------------------------------------------------------------

    fn do_procs(&mut self) {
        use std::process::Command;
        self.log_info("Listing app processes...");

        match Command::new("adb").args(["shell", "ps", "-A"]).output() {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let mut entries: Vec<String> = Vec::new();

                for line in stdout.lines().skip(1) {
                    let cols: Vec<&str> = line.split_whitespace().collect();
                    // ps -A format: USER PID PPID VSZ RSS WCHAN ADDR S NAME
                    if cols.len() >= 9 {
                        let user = cols[0];
                        let pid = cols[1];
                        let name = cols[cols.len() - 1];

                        // Filter to app processes (u0_aXXX user = Android app UIDs)
                        if user.starts_with("u0_a") && !name.contains(':') {
                            entries.push(format!("  {:>6}  {}", pid, name));
                        }
                    }
                }

                if entries.is_empty() {
                    self.log_info("No app processes found");
                } else {
                    self.log_info(&format!("{} app processes running:", entries.len()));
                    self.log_info(&format!("  {:>6}  {}", "PID", "PACKAGE"));
                    for e in &entries {
                        self.log_info(e);
                    }
                    self.log_info("Use: attach <package> to inject agent and connect");
                }
            }
            Err(e) => {
                self.log_error(&format!("adb failed: {} (is adb in PATH?)", e));
            }
        }
    }

    fn do_attach(&mut self, pkg: &str) {
        use std::process::Command;

        if pkg.is_empty() {
            self.log_error("usage: attach <package>");
            return;
        }
        if self.state != AppState::Disconnected {
            self.log_error("Already connected. Disconnect first.");
            return;
        }

        // Step 1: Attach agent
        self.log_info(&format!("Attaching agent to {}...", pkg));
        let attach = Command::new("adb")
            .args(["shell", "cmd", "activity", "attach-agent", pkg, "libart_jit_tracer.so"])
            .output();

        match attach {
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let stdout = String::from_utf8_lossy(&output.stdout);
                if !output.status.success() {
                    self.log_error(&format!("attach-agent failed: {} {}", stdout.trim(), stderr.trim()));
                    return;
                }
                self.log_info("Agent attached");
            }
            Err(e) => {
                self.log_error(&format!("adb failed: {}", e));
                return;
            }
        }

        // Step 2: Set up port forwarding
        self.log_info("Setting up port forwarding...");
        let forward = Command::new("adb")
            .args(["forward", "tcp:12345", "localabstract:dexbgd"])
            .output();

        match forward {
            Ok(output) => {
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    self.log_error(&format!("adb forward failed: {}", stderr.trim()));
                    return;
                }
            }
            Err(e) => {
                self.log_error(&format!("adb forward failed: {}", e));
                return;
            }
        }

        // Step 3: Small delay for agent to start socket listener
        std::thread::sleep(Duration::from_millis(500));

        // Step 4: Connect
        self.do_connect();

        // Step 5: Auto-pull APK for symbol resolution
        self.log_info(&format!("Auto-loading APK for {}...", pkg));
        self.do_load_apk(pkg);
    }

    fn do_launch(&mut self, pkg: &str) {
        use std::process::Command;

        if pkg.is_empty() {
            self.log_error("usage: launch <package>");
            return;
        }

        // Find and start the main activity
        self.log_info(&format!("Starting {}...", pkg));
        let start = Command::new("adb")
            .args(["shell", "monkey", "-p", pkg, "-c", "android.intent.category.LAUNCHER", "1"])
            .output();

        match start {
            Ok(output) => {
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    self.log_error(&format!("Failed to start: {}", stderr.trim()));
                    return;
                }
            }
            Err(e) => {
                self.log_error(&format!("adb failed: {}", e));
                return;
            }
        }

        // Give app a moment to start, then attach
        self.log_info("App started, waiting for init...");
        std::thread::sleep(Duration::from_millis(1500));
        self.do_attach(pkg);
    }

    /// Resolve short class name in a BpSet command.
    /// 1. Try local DEX data (instant, no agent query)
    /// 2. Fall back to agent `cls` query (capped at 150 results)
    /// Returns None if resolution is pending (async), Some(cmd) if resolved or full name.
    fn resolve_bp_class(&mut self, cmd: OutboundCommand, cond: Option<BreakpointCondition>) -> Option<OutboundCommand> {
        // Extract fields from BpSet or BpSetDeopt
        let is_deopt = matches!(cmd, OutboundCommand::BpSetDeopt { .. });
        let bp_fields = match cmd {
            OutboundCommand::BpSet { ref class, ref method, ref sig, ref location } => Some((class, method, sig, location)),
            OutboundCommand::BpSetDeopt { ref class, ref method, ref sig, ref location } => Some((class, method, sig, location)),
            _ => None,
        };
        if let Some((class, method, sig, location)) = bp_fields {
            let inner = class.strip_prefix('L').unwrap_or(class);
            let inner = inner.strip_suffix(';').unwrap_or(inner);
            if !inner.contains('/') && !inner.contains('.') {
                // Short name  - try local DEX data first
                let suffix = format!("/{};\n", inner);
                let suffix = &suffix[..suffix.len() - 1]; // "/Cipher;"
                let exact = format!("L{};", inner);

                // Search loaded DEX/APK type tables
                let mut matches: Vec<String> = Vec::new();
                for dd in &self.dex_data {
                    for t in &dd.types {
                        if (t.ends_with(suffix) || *t == exact) && !matches.contains(t) {
                            matches.push(t.clone());
                        }
                    }
                }

                if matches.len() == 1 {
                    let resolved = matches.into_iter().next().unwrap();
                    self.log_debug(&format!("Resolved {} -> {} (from DEX)", inner, resolved));
                    self.pending_bp_cond = cond;
                    return Some(if is_deopt {
                        OutboundCommand::BpSetDeopt {
                            class: resolved,
                            method: method.clone(),
                            sig: sig.clone(),
                            location: *location,
                        }
                    } else {
                        OutboundCommand::BpSet {
                            class: resolved,
                            method: method.clone(),
                            sig: sig.clone(),
                            location: *location,
                        }
                    });
                } else if matches.len() > 1 {
                    self.log_error(&format!("Ambiguous class '{}'  - {} matches:", inner, matches.len()));
                    for (i, m) in matches.iter().enumerate() {
                        if i >= 10 {
                            self.log_error(&format!("  ... and {} more", matches.len() - 10));
                            break;
                        }
                        self.log_error(&format!("  {}", m));
                    }
                    self.log_info("Use full class name, e.g.: bp javax.crypto.Cipher init");
                    return None;
                }

                // No DEX data or no match  - fall back to agent cls query
                self.pending_bp_resolve = Some(PendingBpResolve {
                    short_name: inner.to_string(),
                    method: method.clone(),
                    sig: sig.clone(),
                    location: *location,
                    cond,
                    force_deopt: is_deopt,
                });
                self.cls_auto_pending = true;
                self.log_debug(&format!("Resolving class '{}' via agent...", inner));
                self.send_command(OutboundCommand::Cls { pattern: inner.to_string() });
                return None;
            }
        }
        Some(cmd)
    }

    fn send_command(&mut self, cmd: OutboundCommand) {
        if let Some(tx) = &self.cmd_tx {
            if tx.send(cmd).is_err() {
                self.log_error("Send failed  - connection lost");
                self.state = AppState::Disconnected;
                self.cmd_tx = None;
                self.agent_rx = None;
            }
        }
    }

    fn show_help(&mut self) {
        self.log_info("Commands:");
        self.log_info("  procs           - List running app processes");
        self.log_info("  attach <pkg>    - Inject agent + forward + connect + load APK");
        self.log_info("  launch <pkg>    - Start app + attach (one shot)");
        self.log_info("  gate            - Release early-attach gate (requires --gate repackage)");
        self.log_info("  connect         - Connect to agent (127.0.0.1:12345)");
        self.log_info("  disconnect      - Disconnect");
        self.log_info("  cls [pattern]   - List loaded classes");
        self.log_info("  methods <cls>   - List methods of a class");
        self.log_info("  fields <cls>    - List fields of a class");
        self.log_info("  threads         - List all threads");
        self.log_info("  dis/u <cls> <m> - Disassemble method (cls = partial name ok)");
        self.log_info("  bp <cls> <m>    - Set breakpoint");
        self.log_info("  bp2 <cls> <m>   - Set breakpoint + force deopt (for repacked APKs)");
        self.log_info("    --hits N      - Break on Nth hit only");
        self.log_info("    --every N     - Break every Nth hit");
        self.log_info("    --when \"expr\"  - Break when condition is true (e.g. name == \"AES\")");
        self.log_info("  bc/bd <id>      - Clear breakpoint");
        self.log_info("  bc/bd *         - Clear all breakpoints");
        self.log_info("  bl              - List breakpoints");
        self.log_info("  c / F5          - Continue (run)");
        self.log_info("  si / F7         - Step into");
        self.log_info("  s  / F8         - Step over");
        self.log_info("  s               - Step over");
        self.log_info("  sout / F9       - Step out");
        self.log_info("  fr <val>        - Force return (true/false/null/void/<int>)");
        self.log_info("  locals          - Show local variables");
        self.log_info("  r / regs        - Dump all register values to log");
        self.log_info("  r v4            - Read register v4 to log");
        self.log_info("  r <name>        - Read local variable by name to log");
        self.log_info("  here            - Print current class.method [@offset] (JADX notation); use in 'bp here'");
        self.log_info("  stack           - Show call stack");
        self.log_info("  inspect <slot>  - Inspect object at slot (e.g. inspect 3 or inspect v3)");
        self.log_info("  eval <expr>     - Eval: v3.getAlgorithm(), v5.length");
        self.log_info("  hexdump <vN>    - Hex dump byte[]/char[]/String (16 rows)");
        self.log_info("  hexdump <vN> full  - Extended hex dump (32 rows)");
        self.log_info("  memdump <addr> L<len>  - Dump native memory (e.g. memdump 0x7f1234 L256)");
        self.log_info("  memdump <addr> <end>   - Dump address range");
        self.log_info("  memdump ... [path]     - Write to file on device instead of TUI");
        self.log_info("  heap <cls>      - Search heap for instances (-> Heap tab)");
        self.log_info("  heapstr <pat>   - Search live String objects (-> Heap tab)");
        self.log_info("  strings <pat>   - Search DEX constant pool strings");
        self.log_info("  xref <pat>      - Find code that loads matching strings");
        self.log_info("  xref-bp <pat>   - Same + set breakpoints on those methods");
        self.log_info("  pause [thd]     - Suspend a thread");
        self.log_info("  apk <path|pkg>  - Load APK for symbol resolution");
        self.log_info("  bp-crypto       - Set breakpoints on crypto APIs");
        self.log_info("  bp-network      - Set breakpoints on network APIs");
        self.log_info("  bp-exec         - Set breakpoints on exec/loader APIs");
        self.log_info("  bp-exfil        - Set breakpoints on data exfiltration APIs");
        self.log_info("  bp-detect       - Set breakpoints on root/tamper detection APIs");
        self.log_info("  bp-ssl          - Set breakpoints on SSL/TLS pinning APIs");
        self.log_info("  bypass-ssl      - Auto-bypass SSL pinning (silent force-return void)");
        self.log_info("  anti <cls> <m>  - Silent ghost BP: ForceReturn neutral value on hit");
        self.log_info("  anti <cls> <m> <val>  - Same, explicit value (true/false/void/N)");
        self.log_info("  anti xref <pat>       - xref pattern, anti-hook all matching methods");
        self.log_info("  anti callers <cls> <m> - anti-hook all methods that invoke <cls>.<m>");
        self.log_info("  anti list       - Show active anti hooks");
        self.log_info("  anti clear      - Remove all anti hooks");
        self.log_info("  bp-all          - Set all API breakpoints");
        self.log_info("  record / rec    - Toggle call recording on/off");
        self.log_info("  rec start/stop  - Start/stop recording");
        self.log_info("  rec clear       - Clear recorded calls");
        self.log_info("  rec onenter     - Toggle entry-only (no exit/return lines)");
        self.log_info("  rec flat        - Flat trace (no tree indentation)");
        self.log_info("  rec tree        - Tree trace (indented call tree)");
        self.log_info("JNI monitor (key 5 -> JNI tab):");
        self.log_info("  jni monitor     - Hook JNIEnv::RegisterNatives on all threads");
        self.log_info("                    Captures: lib+offset, demangled Java signature");
        self.log_info("  jni stop        - Stop monitoring, restore original vtable");
        self.log_info("  jni clear       - Clear captured bindings list");
        self.log_info("  jni redirect <class_sig> <method> <sig> <action>");
        self.log_info("  jni redirect <lib+0xOFFSET|0xADDR> <action>  (address from JNI tab)");
        self.log_info("    actions: block (return 0/null/false/void)");
        self.log_info("             true  (return 1, for boolean methods)");
        self.log_info("             spoof N (return integer N)");
        self.log_info("    e.g.  jni redirect Lcom/guard/Shield; checkRoot ()Z block");
        self.log_info("          jni redirect libnative.so+0x2c40 block");
        self.log_info("          jni redirect 0x7f3a2b10 true");
        self.log_info("  jni restore <class_sig> <method> <sig>");
        self.log_info("  jni restore <lib+0xOFFSET|0xADDR>  (address from JNI tab)");
        self.log_info("    Restore original function pointer (requires prior jni monitor capture)");
        self.log_info("  dex-dump        - Extract DEX from DexClassLoader (while suspended)");
        self.log_info("  dex-read <p>    - Read DEX/JAR file from device by path");
        self.log_info("  alias <sig> <label>  - Set display alias for a class");
        self.log_info("  alias list      - List all aliases");
        self.log_info("  alias clear <sig>  - Remove alias (* for all)");
        self.log_info("  hook <cls> <m> <action>  - Add intercept hook (log-continue, force-return-void/0/1)");
        self.log_info("  hook list       - List hooks");
        self.log_info("  hook clear <cls> <m>  - Remove hook (* for all)");
        self.log_info("  watch <expr>    - Add expression to watch list (re-evaluated on suspend)");
        self.log_info("  unwatch <n|expr>  - Remove watch by index or expression");
        self.log_info("  bm <label>      - Rename selected bookmark (Bookmarks tab)");
        self.log_info("  Ctrl+B          - Toggle bookmark at bytecode cursor");
        self.log_info("  Ctrl+S          - Save session (aliases, comments, hooks, bookmarks)");
        self.log_info("  Ctrl+L          - Launch session (pick saved app, attach agent via adb)");
        self.log_info("  save [file]     - Save full log to file (default: dexbgd_<ts>.log)");
        self.log_info("  ss              - Save settings to dexbgd.ini (theme, layout, history)");
        self.log_info("  ai <prompt>     - AI analysis (full autonomy)");
        self.log_info("  ai ask <p>      - AI analysis (confirm execution tools)");
        self.log_info("  ai explain <p>  - AI analysis (read-only, no execution)");
        self.log_info("  ai cancel       - Cancel running AI analysis");
        self.log_info("  ai --ollama <p>  - Force Ollama backend");
        self.log_info("  ai --model X <p>  - Override model");
        self.log_info("  quit / exit / q - Exit");
        self.log_info("Keys: q=quit, Tab=cycle tabs, Esc=panels/back, Left/Right=focus, Up/Down=cursor");
        self.log_info("  F1=connect, F2=toggle BP at cursor, Shift-F10=record, F12=toggle mouse");
        self.log_info("  Ctrl+T=cycle color theme");
        self.log_info("  Enter/double-click on invoke to follow method (Esc to go back)");
        self.log_info("  y/n=approve AI tool (when AI? shown), Esc=cancel AI (in AI tab)");
    }

    // -------------------------------------------------------------------
    // APK / DEX loading for symbol resolution
    // -------------------------------------------------------------------

    fn do_load_apk(&mut self, arg: &str) {
        if arg.is_empty() {
            self.log_error("usage: apk <path_to_apk> or apk <package.name>");
            return;
        }

        // If it looks like a file path, load directly; otherwise try adb pull
        let local_path = if arg.contains('/') || arg.contains('\\') || arg.ends_with(".apk") {
            arg.to_string()
        } else {
            self.log_info(&format!("Pulling APK for {} via adb...", arg));
            match crate::dex_parser::adb_pull_apk(arg) {
                Ok(path) => {
                    self.log_info(&format!("APK pulled to {}", path));
                    path
                }
                Err(e) => {
                    self.log_error(&e);
                    return;
                }
            }
        };

        match crate::dex_parser::load_apk(&local_path) {
            Ok(dex_data) => {
                let mut total_methods = 0;
                let mut total_fields = 0;
                let mut total_strings = 0;
                let mut total_classes = 0;
                for d in &dex_data {
                    total_methods += d.methods.len();
                    total_fields += d.fields.len();
                    total_strings += d.strings.len();
                    total_classes += d.class_defs.len();
                }
                let dex_count = dex_data.len();
                self.dex_labels = (0..dex_count).map(|_| "apk".to_string()).collect();
                self.dynamic_dex_count = 0;
                self.dex_data = dex_data;
                self.log_info(&format!(
                    "Loaded {} DEX file(s): {} classes, {} methods, {} fields, {} strings",
                    dex_count, total_classes, total_methods, total_fields, total_strings
                ));
            }
            Err(e) => {
                self.log_error(&e);
            }
        }

        // Run session startup commands now that symbols are available
        let cmds = std::mem::take(&mut self.session_startup_queue);
        if !cmds.is_empty() {
            self.run_startup_commands(cmds);
        }
    }

    /// Find the DexData that defines the given class (JNI signature).
    fn find_dex_for_class(&self, class_sig: &str) -> Option<&crate::dex_parser::DexData> {
        for d in &self.dex_data {
            if d.has_class(class_sig) {
                return Some(d);
            }
        }
        // Don't fall back to an arbitrary DEX  - bytecode indices are per-DEX,
        // so using the wrong DEX would resolve to wrong strings/methods/fields.
        // Framework classes (Cipher, URL, etc.) are not in the app's DEX.
        None
    }

    // -------------------------------------------------------------------
    // Class-name resolution helper (for 'patch' command)
    // -------------------------------------------------------------------

    /// Resolve a class pattern to a full JNI signature (e.g. "Lcom/example/Foo;").
    ///
    /// Accepts:
    ///   - Full JNI sig:      "Lcom/example/Foo;"
    ///   - Dot-notation:      "com.example.Foo"
    ///   - Simple class name: "Foo"  (suffix match)
    fn resolve_class(&self, pattern: &str) -> Option<String> {
        // 1. Exact match in class_defs
        if self.dex_data.iter().any(|d| d.has_class(pattern)) {
            return Some(pattern.to_string());
        }

        // 2. Dot-notation → JNI sig
        let jni = if pattern.starts_with('L') && pattern.ends_with(';') {
            pattern.to_string()
        } else {
            format!("L{};", pattern.replace('.', "/"))
        };
        if self.dex_data.iter().any(|d| d.has_class(&jni)) {
            return Some(jni);
        }

        // 3. Suffix match: any class ending with /Pattern; or matching the simple name
        let slash_suffix = format!("/{};", pattern.replace('.', "/"));
        for d in &self.dex_data {
            for sig in &d.class_defs {
                if sig.ends_with(&slash_suffix) || sig == &jni {
                    return Some(sig.clone());
                }
            }
        }

        None
    }

    // -------------------------------------------------------------------
    // u command — unassemble at symbol (WinDbg-style)
    // -------------------------------------------------------------------

    /// `u [Class.]method[:offset]`  or  `u Class method[:offset]`
    ///
    /// Navigates the bytecodes panel to the named method, optionally scrolling
    /// to the instruction at a given bytecode offset (decimal or 0x-prefixed hex).
    ///
    /// Examples:
    ///   u testDetect                     — first method matching "testDetect" in any class
    ///   u MainActivity.testDetect        — dot-separated Class.method
    ///   u MainActivity testDetect        — space-separated Class method (same as bp syntax)
    ///   u testDetect:0x1a4               — navigate and scroll to offset 0x1a4
    ///   u MainActivity testDetect:0x1a4  — space-separated with offset
    fn jump_to_pc(&mut self) {
        // Scroll to show PC once and stay in manual mode — do NOT enable auto_scroll,
        // which would lock the highlight at the same visual row during stepping.
        if let Some(loc) = self.current_loc {
            if let Some(idx) = self.bytecodes.iter().position(|i| i.offset == loc as u32) {
                self.bytecodes_scroll = idx.saturating_sub(2);
            }
        }
    }

    fn do_unassemble(&mut self, arg: &str) {
        if arg.is_empty() {
            self.log_error("usage: u [Class.]method[:offset]  or  u Class method[:offset]");
            return;
        }

        // If there are two space-separated tokens and the first doesn't contain a dot,
        // treat it as "Class method" (same syntax as bp command).
        let normalized: String;
        let arg = {
            let parts: Vec<&str> = arg.splitn(2, ' ').collect();
            if parts.len() == 2 && !parts[0].contains('.') {
                // "MainActivity testDetect[:offset]" → "MainActivity.testDetect[:offset]"
                normalized = format!("{}.{}", parts[0], parts[1]);
                &normalized
            } else {
                arg
            }
        };

        // Split off optional trailing :offset
        let (sym, scroll_offset) = if let Some(colon) = arg.rfind(':') {
            // Distinguish  "Class:method" (no dot after colon) from "method:0x1a4"
            let after = arg[colon + 1..].trim();
            let looks_like_offset = after.starts_with("0x") || after.starts_with("0X")
                || after.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false);
            if looks_like_offset {
                let offset_str = after.trim_start_matches("0x").trim_start_matches("0X");
                let off = i64::from_str_radix(
                    if after.starts_with("0x") || after.starts_with("0X") { offset_str } else { after },
                    if after.starts_with("0x") || after.starts_with("0X") { 16 } else { 10 },
                ).ok();
                (&arg[..colon], off)
            } else {
                (arg, None)
            }
        } else {
            (arg, None)
        };

        // Split "Class.method" on the LAST dot
        let (class_pattern, method_name) = if let Some(dot) = sym.rfind('.') {
            (&sym[..dot], &sym[dot + 1..])
        } else {
            // No dot: treat as bare method name, search all loaded classes
            ("", sym)
        };

        // Resolve the class
        let class_sig = if class_pattern.is_empty() {
            // Search all dex_data for a class that has this method
            let mut found = None;
            'outer: for d in &self.dex_data {
                for sig in &d.class_defs {
                    if d.methods.iter().any(|m| m.class_name == *sig && m.method_name == method_name) {
                        found = Some(sig.clone());
                        break 'outer;
                    }
                }
            }
            match found {
                Some(s) => s,
                None => {
                    if self.dex_data.is_empty() {
                        self.log_error(&format!("dis: no DEX loaded - use 'apk <pkg>' or specify class: dis <class> {}", method_name));
                    } else {
                        self.log_error(&format!("dis: method {:?} not found in any loaded class", method_name));
                    }
                    return;
                }
            }
        } else {
            match self.resolve_class(class_pattern) {
                Some(s) => s,
                None => {
                    if self.cmd_tx.is_none() {
                        self.log_error(&format!("dis: class {:?} not found - connect to agent or load APK first", class_pattern));
                        return;
                    }
                    // No local DEX resolution - send best-effort JNI sig; agent does suffix matching
                    commands::to_jni_sig(class_pattern)
                }
            }
        };

        self.navigate_to_method(&class_sig, method_name, scroll_offset);
    }

    // -------------------------------------------------------------------
    // patch command — JVMTI RedefineClasses
    // -------------------------------------------------------------------

    /// Execute a `patch <class> <method> <value>` command.
    /// Resolves the class, patches the DEX bytes, and sends RedefineClass to the agent.
    fn do_patch(&mut self, args: &str) {
        // Split into exactly three parts: class, method, value/nop-spec
        let mut iter = args.splitn(3, |c: char| c.is_whitespace());
        let class_pattern = match iter.next() { Some(s) => s, None => {
            self.log_error("patch: missing class name");
            return;
        }};
        let method_name = match iter.next() { Some(s) => s, None => {
            self.log_error("patch: missing method name");
            return;
        }};
        let value_part = match iter.next() { Some(s) => s.trim(), None => {
            self.log_error("patch: missing value  (void/true/false/null/0/1 or @offset[:width] nop)");
            return;
        }};

        // Resolve class pattern → JNI sig
        let class_sig = match self.resolve_class(class_pattern) {
            Some(sig) => sig,
            None => {
                self.log_error(&format!(
                    "patch: class {:?} not found in loaded DEX - use 'apk <pkg>' to load symbols",
                    class_pattern
                ));
                return;
            }
        };

        // Clone raw bytes (ends the immutable borrow on self.dex_data)
        let raw_bytes = match self.dex_data.iter().find(|d| d.has_class(&class_sig)) {
            Some(d) => d.raw.clone(),
            None => {
                self.log_error("patch: DEX raw bytes not available for class");
                return;
            }
        };

        if self.state == AppState::Disconnected {
            self.log_error("patch: not connected - use 'connect' first");
            return;
        }

        // Dispatch to patcher.
        // Also compute the ForceEarlyReturn value to use after a successful RedefineClasses.
        // Nop patches don't change the return value so we don't force-return; full-method
        // return patches do, using 0 for void/false/null/0 and 1 for true/1.
        let (result, force_return_value) = if let Some(rest) = value_part.strip_prefix('@') {
            // Nop form: @0xOFFSET[:WIDTH] nop
            let token = rest.split_whitespace().next().unwrap_or("");
            let suffix = value_part[1 + token.len()..].trim();
            if suffix != "nop" {
                self.log_error("patch: expected 'nop' after @offset");
                return;
            }
            let (offset_str, width) = if let Some(ci) = token.find(':') {
                let w = token[ci + 1..].parse::<u32>().unwrap_or(1);
                (&token[..ci], w)
            } else {
                (token, 1u32)
            };
            let offset = u32::from_str_radix(
                offset_str.trim_start_matches("0x").trim_start_matches("0X"),
                16,
            ).unwrap_or(0);
            (crate::dex_patcher::patch_method_nop(&raw_bytes, &class_sig, method_name, offset, width),
             None)  // nop: don't auto-force-return
        } else {
            let fr_val = match value_part { "true" | "1" => 1, _ => 0 };
            (crate::dex_patcher::patch_method_return(&raw_bytes, &class_sig, method_name, value_part),
             Some(fr_val))
        };

        match result {
            Ok(patched) => {
                // Sanity-check the patched DEX checksum (silent on success; error if broken).
                let (stored, computed) = crate::dex_patcher::check_adler32(&patched);
                if stored != computed {
                    self.log_error(&format!("[PATCH] adler32 MISMATCH stored={:08x} computed={:08x} - aborting", stored, computed));
                    return;
                }

                // Write patched DEX for offline inspection (silent).
                let _ = std::fs::write("patch_debug.dex", &patched);

                let dex_b64 = BASE64.encode(&patched);

                self.log_info(&format!(
                    "[PATCH] Patching {}.{} -> {}  ({} bytes)",
                    short_class(&class_sig), method_name, value_part, patched.len()
                ));
                let immediate = force_return_value.is_some()
                    && self.state == AppState::Suspended;
                if immediate {
                    self.log_info("[PATCH]   Applying immediately via ForceEarlyReturn");
                } else {
                    self.log_info("[PATCH]   Change will take effect on next invocation");
                }

                self.send_command(crate::protocol::OutboundCommand::RedefineClass {
                    class_sig,
                    dex_b64,
                    return_value: force_return_value,
                });
            }
            Err(e) => {
                self.log_error(&format!("[PATCH] {}", e));
            }
        }
    }

    // -------------------------------------------------------------------
    // DEX string search (local  - searches constant pool, no agent call)
    // -------------------------------------------------------------------

    fn do_dex_string_search(&mut self, pattern: &str) {
        if pattern.is_empty() {
            self.log_error("usage: strings <pattern>");
            return;
        }
        if self.dex_data.is_empty() {
            self.log_error("No DEX loaded. Use 'apk <package>' first, or connect and hit a breakpoint.");
            return;
        }
        let pat = pattern.to_lowercase();
        const MAX_RESULTS: usize = 200;
        let multi_dex = self.dex_data.len() > 1;

        // Collect results first to avoid borrow conflict
        let mut results: Vec<String> = Vec::new();
        for (dex_idx, dex) in self.dex_data.iter().enumerate() {
            for (str_idx, s) in dex.strings.iter().enumerate() {
                if s.to_lowercase().contains(&pat) {
                    let label = self.dex_labels.get(dex_idx).map(|l| l.as_str()).unwrap_or("?");
                    let prefix = if multi_dex { format!("[{}]", label) } else { String::new() };
                    let display = if s.len() > 120 { format!("{}...", &s[..120]) } else { s.clone() };
                    results.push(format!("  {}#{}: {}", prefix, str_idx, display));
                    if results.len() >= MAX_RESULTS {
                        break;
                    }
                }
            }
            if results.len() >= MAX_RESULTS { break; }
        }

        self.log_info(&format!("Searching DEX strings for \"{}\"...", pattern));
        for line in &results {
            self.log_info(line);
        }
        if results.len() >= MAX_RESULTS {
            self.log_info(&format!("  ... (truncated at {} results)", MAX_RESULTS));
            self.log_info(&format!("Found {}+ matches for \"{}\"", MAX_RESULTS, pattern));
        } else {
            self.log_info(&format!("Found {} matches for \"{}\"", results.len(), pattern));
        }
    }

    // -------------------------------------------------------------------
    // String cross-references  - find code that loads a given string
    // -------------------------------------------------------------------

    fn do_xref(&mut self, pattern: &str, set_bp: bool) {
        if pattern.is_empty() {
            self.log_error("usage: xref <pattern>  or  xref-bp <pattern>");
            return;
        }
        if self.dex_data.is_empty() {
            self.log_error("No DEX loaded. Use 'apk <package>' first.");
            return;
        }
        if set_bp && self.state == AppState::Disconnected {
            self.log_error("Not connected. Use 'connect' first (needed for xref-bp).");
            return;
        }

        let pat = pattern.to_lowercase();
        const MAX_RESULTS: usize = 100;

        // Find matching string indices and collect xrefs
        let mut results: Vec<(String, String, String, String, u32)> = Vec::new(); // (string_val, class, method, proto, offset)
        let multi_dex = self.dex_data.len() > 1;

        for (dex_idx, dex) in self.dex_data.iter().enumerate() {
            for xref in &dex.string_xrefs {
                if let Some(s) = dex.strings.get(xref.string_idx as usize) {
                    if s.to_lowercase().contains(&pat) {
                        let label = self.dex_labels.get(dex_idx).map(|l| l.as_str()).unwrap_or("?");
                        let prefix = if multi_dex { format!("[{}]", label) } else { String::new() };
                        let cls_short = short_class(&xref.class_name);
                        let display_str = if s.len() > 80 { format!("{}...", &s[..80]) } else { s.clone() };
                        results.push((
                            format!("  {}{}.{} @{}: \"{}\"",
                                prefix, cls_short, xref.method_name, xref.code_offset, display_str),
                            xref.class_name.clone(),
                            xref.method_name.clone(),
                            xref.proto.clone(),
                            xref.code_offset,
                        ));
                        if results.len() >= MAX_RESULTS { break; }
                    }
                }
            }
            if results.len() >= MAX_RESULTS { break; }
        }

        if set_bp {
            self.log_info(&format!("Xref-BP \"{}\": {} references found, setting breakpoints...", pattern, results.len()));
        } else {
            self.log_info(&format!("Xref \"{}\": {} references found", pattern, results.len()));
        }

        // Deduplicate breakpoints by (class, method, proto)  - only one bp per method entry
        let mut bp_set = std::collections::HashSet::new();

        for (display, class_name, method_name, proto, _offset) in &results {
            self.log_info(display);

            if set_bp {
                let key = (class_name.clone(), method_name.clone(), proto.clone());
                if bp_set.insert(key) {
                    self.send_command(OutboundCommand::BpSet {
                        class: class_name.clone(),
                        method: method_name.clone(),
                        sig: Some(proto.clone()),
                        location: None,
                    });
                }
            }
        }

        if results.len() >= MAX_RESULTS {
            self.log_info(&format!("  ... (truncated at {} results)", MAX_RESULTS));
        }

        if set_bp && !bp_set.is_empty() {
            self.log_info(&format!("Set breakpoints on {} unique methods", bp_set.len()));
        }

        if results.is_empty() {
            self.log_info("  (no references found)");
        }
    }

    // -------------------------------------------------------------------
    // Breakpoint profiles  - predefined API breakpoint sets
    // -------------------------------------------------------------------

    fn do_clear_all_breakpoints(&mut self) {
        if self.state == AppState::Disconnected {
            self.log_error("Not connected. Use 'connect' first.");
            return;
        }
        // Flush any pending condition state to prevent desync
        self.pending_bp_cond = None;
        self.pending_bp_conditions.clear();
        self.pending_cond_eval = None;
        self.anti_bps.clear();
        self.pending_anti_count = 0;
        let ids: Vec<i32> = self.bp_manager.breakpoints.iter().map(|bp| bp.id).collect();
        if ids.is_empty() {
            self.log_info("No breakpoints to clear.");
            return;
        }
        let count = ids.len();
        for id in ids {
            self.send_command(crate::protocol::OutboundCommand::BpClear { id });
        }
        self.log_info(&format!("Clearing all {} breakpoints", count));
    }

    fn do_bp_profile(&mut self, input: &str) {
        if self.state == AppState::Disconnected {
            self.log_error("Not connected. Use 'connect' first.");
            return;
        }

        // Split profile name from trailing condition flags
        // e.g. "bp-crypto --every 3" → profile="bp-crypto", flags="--every 3"
        let (profile, cond) = {
            let parts: Vec<&str> = input.splitn(2, " --").collect();
            if parts.len() == 2 {
                let flags = format!("--{}", parts[1]);
                // Parse using a dummy arg so parse_condition_flags works
                match condition::parse_condition_flags(&flags) {
                    Ok((_, c)) => (parts[0].trim(), c),
                    Err(e) => {
                        self.log_error(&format!("condition parse error: {}", e));
                        return;
                    }
                }
            } else {
                (input.trim(), None)
            }
        };

        let crypto: &[(&str, &str)] = &[
            ("javax.crypto.Cipher", "doFinal"),
            ("javax.crypto.Cipher", "init"),
            ("javax.crypto.Cipher", "getInstance"),
            ("javax.crypto.Mac", "doFinal"),
            ("javax.crypto.Mac", "init"),
            ("javax.crypto.KeyGenerator", "generateKey"),
            ("javax.crypto.spec.SecretKeySpec", "<init>"),
            ("javax.crypto.spec.IvParameterSpec", "<init>"),
            ("java.security.MessageDigest", "digest"),
            ("java.security.MessageDigest", "update"),
            ("java.security.KeyStore", "load"),
        ];

        let network: &[(&str, &str)] = &[
            ("java.net.URL", "openConnection"),
            ("java.net.HttpURLConnection", "connect"),
            ("java.net.HttpURLConnection", "getInputStream"),
            ("java.net.HttpURLConnection", "getOutputStream"),
            ("java.net.Socket", "<init>"),
            ("java.net.Socket", "connect"),
            ("javax.net.ssl.HttpsURLConnection", "connect"),
            ("okhttp3.OkHttpClient", "newCall"),
            ("okhttp3.Call", "execute"),
        ];

        let exec: &[(&str, &str)] = &[
            ("java.lang.Runtime", "exec"),
            ("java.lang.ProcessBuilder", "start"),
            ("dalvik.system.DexClassLoader", "<init>"),
            ("dalvik.system.InMemoryDexClassLoader", "<init>"),
            ("dalvik.system.PathClassLoader", "<init>"),
            ("java.lang.reflect.Method", "invoke"),
            ("java.lang.Class", "forName"),
            ("java.lang.ClassLoader", "loadClass"),
        ];

        let exfil: &[(&str, &str)] = &[
            ("android.telephony.SmsManager", "sendTextMessage"),
            ("android.telephony.TelephonyManager", "getDeviceId"),
            ("android.telephony.TelephonyManager", "getLine1Number"),
            ("android.content.ContentResolver", "query"),
            ("android.location.LocationManager", "getLastKnownLocation"),
            ("android.content.pm.PackageManager", "getInstalledPackages"),
        ];

        let detect: &[(&str, &str)] = &[
            // SafetyNet / Play Integrity
            ("com.google.android.gms.safetynet.SafetyNetClient", "attest"),
            ("com.google.android.play.core.integrity.IntegrityManager", "requestIntegrityToken"),
            // Root detection: file existence checks
            ("java.io.File", "exists"),
            // Signature / package verification
            ("android.content.pm.PackageManager", "getPackageInfo"),
            ("android.content.pm.PackageManager", "getInstallerPackageName"),
            // Build property reads (test-keys, custom fingerprints)
            ("android.os.Build", "<clinit>"),
            ("android.os.SystemProperties", "get"),
            // Xposed / hooking framework detection
            ("java.lang.Class", "forName"),
            ("java.lang.ClassLoader", "loadClass"),
            // Process / environment inspection
            ("java.lang.Runtime", "exec"),
            ("android.app.ActivityManager", "getRunningAppProcesses"),
            // Debug detection
            ("android.os.Debug", "isDebuggerConnected"),
            ("android.provider.Settings$Secure", "getString"),
        ];

        let ssl: &[(&str, &str)] = &[
            // NSC (Network Security Config) — Android 7+ built-in pinning
            ("android.security.net.config.NetworkSecurityTrustManager", "checkServerTrusted"),
            // SSLContext.init — catch custom TrustManager/HostnameVerifier registration
            ("javax.net.ssl.SSLContext", "init"),
            // Custom socket factory / hostname verifier injection via HttpsURLConnection
            ("javax.net.ssl.HttpsURLConnection", "setSSLSocketFactory"),
            ("javax.net.ssl.HttpsURLConnection", "setHostnameVerifier"),
            // OkHttp certificate pinning (non-obfuscated builds)
            ("okhttp3.CertificatePinner", "check"),
            // Conscrypt deep hook — fires for all TLS cert chain validation
            ("com.android.org.conscrypt.TrustManagerImpl", "checkTrustedRecursive"),
        ];

        let targets: Vec<(&str, &str)> = match profile {
            "bp-crypto" => crypto.to_vec(),
            "bp-network" => network.to_vec(),
            "bp-exec" | "bp-loader" => exec.to_vec(),
            "bp-exfil" => exfil.to_vec(),
            "bp-detect" => detect.to_vec(),
            "bp-ssl" => ssl.to_vec(),
            "bp-all" => {
                let mut all = Vec::new();
                all.extend_from_slice(crypto);
                all.extend_from_slice(network);
                all.extend_from_slice(exec);
                all.extend_from_slice(exfil);
                all.extend_from_slice(detect);
                all.extend_from_slice(ssl);
                all
            }
            _ => {
                self.log_error(&format!("Unknown profile: {}. Use bp-crypto, bp-network, bp-exec, bp-exfil, bp-detect, bp-ssl, bp-all", profile));
                return;
            }
        };

        let cond_desc = cond.as_ref().map(|c| format!(" [{}]", c)).unwrap_or_default();
        self.log_info(&format!("Setting {} breakpoints ({}){}...", targets.len(), profile, cond_desc));
        for (class, method) in &targets {
            let class_jni = commands::to_jni_sig(class);
            if let Some(ref c) = cond {
                self.pending_bp_conditions.push_back(c.clone());
            }
            self.send_command(OutboundCommand::BpSet {
                class: class_jni,
                method: method.to_string(),
                sig: None,
                location: None,
            });
        }
        self.log_info(&format!("{} breakpoint requests sent", targets.len()));
    }

    // -------------------------------------------------------------------
    // SSL bypass
    // -------------------------------------------------------------------

    fn do_bypass_ssl(&mut self) {
        if self.state == AppState::Disconnected {
            self.log_error("Not connected. Use 'connect' first.");
            return;
        }

        // Methods to auto-bypass (all return void — force_return 0 works for all).
        // SSLContext.init and the HttpsURLConnection setters are intentionally excluded:
        // bypassing those breaks TLS entirely rather than just skipping pin checks.
        let targets: &[(&str, &str)] = &[
            ("android.security.net.config.NetworkSecurityTrustManager", "checkServerTrusted"),
            ("com.android.org.conscrypt.TrustManagerImpl",              "checkTrustedRecursive"),
            ("okhttp3.CertificatePinner",                               "check"),
        ];

        self.log_info(&format!("bypass-ssl: setting {} auto-bypass breakpoints...", targets.len()));
        self.pending_bypass_count += targets.len();
        for (class, method) in targets {
            self.send_command(OutboundCommand::BpSet {
                class: commands::to_jni_sig(class),
                method: method.to_string(),
                sig: None,
                location: None,
            });
        }

        // SSLContext.init interception — catches obfuscated custom TrustManagers.
        // NOT in auto-bypass set: we let init proceed normally but patch the TM class.
        self.send_command(OutboundCommand::BpSet {
            class: commands::to_jni_sig("javax.net.ssl.SSLContext"),
            method: "init".to_string(),
            sig: None,
            location: None,
        });
        self.bypass_ssl_active = true;
        self.log_info("bypass-ssl: active - SSL pin checks will be silently bypassed");
    }

    // -------------------------------------------------------------------
    // Anti-tamper bypass
    // -------------------------------------------------------------------

    fn do_anti(&mut self, input: &str) {
        let rest = if input.starts_with("bypass-anti") {
            input["bypass-anti".len()..].trim()
        } else {
            input["anti".len()..].trim()
        };

        match rest {
            "list" => {
                if self.anti_bps.is_empty() {
                    self.log_info("No active anti hooks.");
                } else {
                    let lines: Vec<String> = self.anti_bps.iter().map(|id| {
                        if let Some(bp) = self.bp_manager.breakpoints.iter().find(|b| b.id == *id) {
                            format!("  #{} {}.{}", bp.id, short_class(&bp.class), bp.method)
                        } else {
                            format!("  #{}", id)
                        }
                    }).collect();
                    self.log_info(&format!("{} active anti hook(s):", lines.len()));
                    for line in lines {
                        self.log_info(&line);
                    }
                }
                return;
            }
            "clear" => {
                let ids: Vec<i32> = self.anti_bps.iter().cloned().collect();
                if ids.is_empty() {
                    self.log_info("No anti hooks to clear.");
                    return;
                }
                self.log_info(&format!("Clearing {} anti hook(s)...", ids.len()));
                for id in ids {
                    self.send_command(OutboundCommand::BpClear { id });
                }
                return;
            }
            _ => {}
        }

        if rest.starts_with("xref ") {
            let pattern = rest["xref ".len()..].trim();
            self.do_anti_xref(pattern);
            return;
        }

        if rest.starts_with("callers ") {
            let args = rest["callers ".len()..].trim();
            self.do_anti_callers(args);
            return;
        }

        if self.state == AppState::Disconnected {
            self.log_error("Not connected. Use 'connect' first.");
            return;
        }

        // Parse: <class> <method> [retval]
        let parts: Vec<&str> = rest.splitn(3, ' ').collect();
        if parts.len() < 2 || parts[0].is_empty() || parts[1].is_empty() {
            self.log_error("Usage: anti <class> <method> [true|false|void|<N>]");
            return;
        }

        let class = parts[0];
        let method = parts[1];
        let retval = if parts.len() >= 3 {
            match parts[2].trim() {
                "void" | "frv" => condition::FORCE_RETURN_VOID,
                "true" | "1" => 1,
                "false" | "0" => 0,
                s => s.parse::<i32>().unwrap_or(0),
            }
        } else {
            condition::FORCE_RETURN_AUTO
        };

        let class_jni = commands::to_jni_sig(class);
        let label = if retval == condition::FORCE_RETURN_AUTO {
            "auto".to_string()
        } else if retval == condition::FORCE_RETURN_VOID {
            "void".to_string()
        } else {
            retval.to_string()
        };
        self.log_info(&format!("anti: hooking {}.{} -> {}", short_class(&class_jni), method, label));

        self.pending_bp_conditions.push_back(
            condition::BreakpointCondition::for_action(condition::BreakpointAction::ForceReturn(retval))
        );
        self.pending_anti_count += 1;
        self.send_command(OutboundCommand::BpSet {
            class: class_jni,
            method: method.to_string(),
            sig: None,
            location: None,
        });
    }

    fn do_anti_xref(&mut self, pattern: &str) {
        if pattern.is_empty() {
            self.log_error("usage: anti xref <pattern>");
            return;
        }
        if self.dex_data.is_empty() {
            self.log_error("No DEX loaded. Use 'apk <package>' first.");
            return;
        }
        if self.state == AppState::Disconnected {
            self.log_error("Not connected. Use 'connect' first.");
            return;
        }

        let pat = pattern.to_lowercase();
        const MAX_RESULTS: usize = 100;
        let multi_dex = self.dex_data.len() > 1;

        // Collect matching xrefs, deduplicated by (class, method, proto)
        let mut seen = std::collections::HashSet::new();
        let mut hits: Vec<(String, String, String, String)> = Vec::new(); // (display, class, method, proto)

        'outer: for (dex_idx, dex) in self.dex_data.iter().enumerate() {
            for xref in &dex.string_xrefs {
                if let Some(s) = dex.strings.get(xref.string_idx as usize) {
                    if s.to_lowercase().contains(&pat) {
                        let key = (xref.class_name.clone(), xref.method_name.clone(), xref.proto.clone());
                        if seen.insert(key) {
                            let label = self.dex_labels.get(dex_idx).map(|l| l.as_str()).unwrap_or("?");
                            let prefix = if multi_dex { format!("[{}] ", label) } else { String::new() };
                            let display_str = if s.len() > 60 { format!("{}...", &s[..60]) } else { s.clone() };
                            hits.push((
                                format!("  {}{}.{} (\"{}\")", prefix, short_class(&xref.class_name), xref.method_name, display_str),
                                xref.class_name.clone(),
                                xref.method_name.clone(),
                                xref.proto.clone(),
                            ));
                            if hits.len() >= MAX_RESULTS { break 'outer; }
                        }
                    }
                }
            }
        }

        if hits.is_empty() {
            self.log_info(&format!("anti xref \"{}\": no references found", pattern));
            return;
        }

        let hit_count = hits.len();
        let truncated = hit_count >= MAX_RESULTS;
        self.log_info(&format!("anti xref \"{}\": {} unique method(s) - setting anti hooks...", pattern, hit_count));
        for (display, class_name, method_name, proto) in hits {
            self.log_info(&display);
            self.pending_bp_conditions.push_back(
                condition::BreakpointCondition::for_action(condition::BreakpointAction::ForceReturn(condition::FORCE_RETURN_AUTO))
            );
            self.pending_anti_count += 1;
            self.send_command(OutboundCommand::BpSet {
                class: class_name,
                method: method_name,
                sig: Some(proto),
                location: None,
            });
        }

        if truncated {
            self.log_info(&format!("  ... (truncated at {} results)", MAX_RESULTS));
        }
    }

    fn do_anti_callers(&mut self, args: &str) {
        let parts: Vec<&str> = args.splitn(2, ' ').collect();
        if parts.len() < 2 || parts[0].is_empty() || parts[1].is_empty() {
            self.log_error("usage: anti callers <class> <method>");
            return;
        }
        if self.dex_data.is_empty() {
            self.log_error("No DEX loaded. Use 'apk <package>' first.");
            return;
        }
        if self.state == AppState::Disconnected {
            self.log_error("Not connected. Use 'connect' first.");
            return;
        }

        let target_class_jni = commands::to_jni_sig(parts[0]);
        let target_method = parts[1].to_string();
        let timeout = std::time::Duration::from_secs(3);
        const BROAD_API_THRESHOLD: usize = 5;

        let mut all_callers: Vec<(String, String, String)> = Vec::new();
        let mut timed_out = false;
        let mut seen: std::collections::HashSet<(String, String, String)> = std::collections::HashSet::new();

        for dex in &self.dex_data {
            let (callers, did_timeout) = crate::dex_parser::find_method_callers(dex, &target_class_jni, &target_method, timeout);
            for (cls, meth, proto) in callers {
                if seen.insert((cls.clone(), meth.clone(), proto.clone())) {
                    all_callers.push((cls, meth, proto));
                }
            }
            if did_timeout {
                timed_out = true;
                break;
            }
        }

        if timed_out {
            self.log_error("anti callers: scan timed out (3s) - DEX too large. Results so far:");
        }

        if all_callers.is_empty() {
            self.log_info(&format!("anti callers {}.{}: no callers found", short_class(&target_class_jni), target_method));
            return;
        }

        if all_callers.len() > BROAD_API_THRESHOLD {
            self.log_info(&format!(
                "anti callers: WARNING — {} callers found for {}.{}. This is a broad API; anti-hooking all callers may break legitimate app behaviour.",
                all_callers.len(), short_class(&target_class_jni), target_method
            ));
        }

        self.log_info(&format!("anti callers {}.{}: {} caller(s) - setting anti hooks...",
            short_class(&target_class_jni), target_method, all_callers.len()));

        for (class_name, method_name, proto) in all_callers {
            self.log_info(&format!("  {}.{}", short_class(&class_name), method_name));
            self.pending_bp_conditions.push_back(
                condition::BreakpointCondition::for_action(condition::BreakpointAction::ForceReturn(condition::FORCE_RETURN_AUTO))
            );
            self.pending_anti_count += 1;
            self.send_command(OutboundCommand::BpSet {
                class: class_name,
                method: method_name,
                sig: Some(proto),
                location: None,
            });
        }
    }

    // -------------------------------------------------------------------
    // Call recording helpers
    // -------------------------------------------------------------------

    fn do_record_start(&mut self) {
        if self.state == AppState::Disconnected {
            self.log_error("Not connected. Use 'connect' first.");
            return;
        }
        if self.recording_active {
            self.log_error("Already recording");
            return;
        }
        self.send_command(OutboundCommand::RecordStart {});
    }

    fn do_record_stop(&mut self) {
        if !self.recording_active {
            self.log_error("Not recording");
            return;
        }
        self.send_command(OutboundCommand::RecordStop {});
    }

    fn do_jni_monitor_start(&mut self) {
        if self.state == AppState::Disconnected {
            self.log_error("Not connected");
            return;
        }
        if self.jni_monitoring {
            self.log_error("JNI monitor already active");
            return;
        }
        self.send_command(OutboundCommand::JniMonitorStart {});
    }

    fn do_jni_monitor_stop(&mut self) {
        if !self.jni_monitoring {
            self.log_error("JNI monitor not active");
            return;
        }
        self.send_command(OutboundCommand::JniMonitorStop {});
    }

    /// Parse a native address string ("libnative.so+0x2c40" or "0x7f3a2b10") and
    /// look it up in the captured jni_natives list.  Returns cloned (class_sig, method_name, method_sig).
    fn resolve_jni_addr(&self, addr_str: &str) -> Option<(String, String, String)> {
        // lib+offset form: "libnative.so+0x2c40"
        if let Some(plus) = addr_str.find("+0x").or_else(|| addr_str.find("+0X")) {
            let lib    = &addr_str[..plus];
            let hex    = addr_str[plus + 1..].trim_start_matches("0x").trim_start_matches("0X");
            if let Ok(offset) = u64::from_str_radix(hex, 16) {
                return self.jni_natives.iter().find(|e| {
                    e.lib_name == lib && e.lib_offset as u64 == offset
                }).map(|e| (e.class_sig.clone(), e.method_name.clone(), e.method_sig.clone()));
            }
        }
        // Absolute address form: "0x7f3a2b10"
        if let Some(hex) = addr_str.strip_prefix("0x").or_else(|| addr_str.strip_prefix("0X")) {
            if let Ok(addr) = u64::from_str_radix(hex, 16) {
                return self.jni_natives.iter().find(|e| {
                    e.native_addr as u64 == addr
                }).map(|e| (e.class_sig.clone(), e.method_name.clone(), e.method_sig.clone()));
            }
        }
        None
    }

    /// Returns true if the string looks like a native address rather than a class sig.
    fn is_native_addr(s: &str) -> bool {
        s.starts_with("0x") || s.starts_with("0X") || s.contains("+0x") || s.contains("+0X")
    }

    /// Parse and execute: jni redirect <class_sig> <method_name> <method_sig> <action>
    ///                 or: jni redirect <lib+offset|0xADDR> <action>
    fn do_jni_redirect(&mut self, args: &str) {
        let parts: Vec<&str> = args.splitn(4, ' ').collect();

        // Address-based shorthand: "libnative.so+0x2c40 block"
        if parts.len() >= 2 && Self::is_native_addr(parts[0]) {
            match self.resolve_jni_addr(parts[0]) {
                Some((cs, mn, ms)) => {
                    let action_part = parts[1..].join(" ");
                    self.do_jni_redirect_inner(cs, mn, ms, &action_part);
                }
                None => self.log_error(&format!(
                    "jni redirect: no captured binding for address {} — run 'jni monitor' first",
                    parts[0]
                )),
            }
            return;
        }

        // Full form: "Lcom/example/Shield; checkIntegrity ()Z block"
        if parts.len() < 4 {
            self.log_error("Usage: jni redirect <class_sig> <method_name> <method_sig> <block|true|false|spoof N>");
            self.log_error("    or: jni redirect <lib+0xOFFSET|0xADDR> <action>  (address from JNI tab)");
            return;
        }
        self.do_jni_redirect_inner(parts[0].to_string(), parts[1].to_string(),
                                    parts[2].to_string(), parts[3]);
    }

    fn do_jni_redirect_inner(&mut self, class_sig: String, method_name: String,
                              method_sig: String, action_str: &str) {
        let (action, spoof_value) = if action_str.starts_with("spoof") {
            let v = action_str.splitn(2, ' ').nth(1)
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(0);
            ("spoof".to_string(), Some(v))
        } else {
            (action_str.to_string(), None)
        };

        // Store the intended action in our local entry before the agent confirms
        if let Some(e) = self.jni_natives.iter_mut().find(|e| {
            e.class_sig == class_sig && e.method_name == method_name && e.method_sig == method_sig
        }) {
            e.redirect_action = Some(action.clone());
        }

        self.send_command(OutboundCommand::JniRedirectSet {
            class_sig, method_name, method_sig, action, spoof_value,
        });
    }

    /// Parse and execute: jni restore <class_sig> <method_name> <method_sig>
    ///                 or: jni restore <lib+offset|0xADDR>
    fn do_jni_restore(&mut self, args: &str) {
        let parts: Vec<&str> = args.splitn(3, ' ').collect();

        // Address-based shorthand
        if parts.len() == 1 && Self::is_native_addr(parts[0]) {
            match self.resolve_jni_addr(parts[0]) {
                Some((cs, mn, ms)) => {
                    self.send_command(OutboundCommand::JniRedirectClear {
                        class_sig: cs, method_name: mn, method_sig: ms,
                    });
                }
                None => self.log_error(&format!(
                    "jni restore: no captured binding for address {}",
                    parts[0]
                )),
            }
            return;
        }

        if parts.len() < 3 {
            self.log_error("Usage: jni restore <class_sig> <method_name> <method_sig>");
            return;
        }
        self.send_command(OutboundCommand::JniRedirectClear {
            class_sig:   parts[0].to_string(),
            method_name: parts[1].to_string(),
            method_sig:  parts[2].to_string(),
        });
    }

    fn toggle_trace_save(&mut self) {
        use std::io::Write;
        if self.trace_save_active {
            // Turn off  - flush and close
            if let Some(ref mut w) = self.trace_save_file {
                let _ = w.flush();
            }
            self.trace_save_file = None;
            self.trace_save_active = false;
            self.log_info("Trace save OFF  - dex_trace.log closed");
        } else {
            // Turn on  - open file (append mode)
            match std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open("dex_trace.log")
            {
                Ok(f) => {
                    self.trace_save_file = Some(std::io::BufWriter::new(f));
                    self.trace_save_active = true;
                    self.log_info("Trace save ON  - writing to dex_trace.log");
                }
                Err(e) => {
                    self.log_error(&format!("Failed to open dex_trace.log: {}", e));
                }
            }
        }
    }

    fn trace_write_line(&mut self, line: &str) {
        use std::io::Write;
        if let Some(ref mut w) = self.trace_save_file {
            let _ = writeln!(w, "{}", line);
            let _ = w.flush();
        }
    }

    // -------------------------------------------------------------------
    // AI analysis agent
    // -------------------------------------------------------------------

    fn do_ai_start(&mut self, mode: crate::ai::AiMode, prompt: &str) {
        if prompt.is_empty() {
            self.log_error("usage: ai <prompt>, ai ask <prompt>, ai explain <prompt>");
            return;
        }
        if self.ai_state != AiState::Idle {
            self.log_error("AI is already running. Use 'ai cancel' to stop it.");
            return;
        }

        let snapshot = crate::ai::StateSnapshot {
            app_state: format!("{:?}", self.state),
            current_class: self.current_class.clone(),
            current_method: self.current_method.clone(),
            current_line: self.current_line,
            current_thread: self.current_thread.clone(),
            bp_count: self.bp_manager.count(),
            thread_count: self.threads.len(),
            recording_active: self.recording_active,
            call_record_count: self.call_records.len(),
            dex_loaded: !self.dex_data.is_empty(),
            dex_string_count: self.dex_data.iter().map(|d| d.strings.len()).sum(),
        };

        // Create channels
        let (req_tx, req_rx) = mpsc::channel();
        let (evt_tx, evt_rx) = mpsc::channel();
        let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        self.ai_req_tx = Some(req_tx.clone());
        self.ai_evt_rx = Some(evt_rx);
        self.ai_cancel = Some(cancel.clone());
        self.ai_mode = mode;
        self.ai_state = AiState::Running;
        self.ai_output.clear();
        self.ai_scroll = 0;
        self.ai_auto_scroll = true;
        self.left_tab = LeftTab::Ai;

        let mode_str = match mode {
            crate::ai::AiMode::Auto => "auto",
            crate::ai::AiMode::Ask => "ask",
            crate::ai::AiMode::Explain => "explain",
        };
        self.log_info(&format!("[AI] Starting analysis (mode={}): {}", mode_str, prompt));

        // Send Start request
        let _ = req_tx.send(AiRequest::Start {
            mode,
            prompt: prompt.to_string(),
            snapshot,
        });

        // Spawn AI thread
        crate::ai::spawn_ai_thread(
            self.config.ai.clone(),
            mode,
            req_rx,
            evt_tx,
            cancel,
        );
    }

    fn parse_ai_command(&mut self, input: &str) {
        let rest = input.strip_prefix("ai").unwrap_or("").trim();

        // Parse mode
        let (mode, rest) = if rest.starts_with("ask ") {
            (crate::ai::AiMode::Ask, rest.strip_prefix("ask ").unwrap_or("").trim())
        } else if rest.starts_with("explain ") {
            (crate::ai::AiMode::Explain, rest.strip_prefix("explain ").unwrap_or("").trim())
        } else {
            (crate::ai::AiMode::Auto, rest)
        };

        // Parse flags: --ollama, --model <model>
        let mut backend_override: Option<String> = None;
        let mut model_override: Option<String> = None;
        let mut prompt_parts: Vec<&str> = Vec::new();
        let mut args = rest.split_whitespace().peekable();

        while let Some(arg) = args.next() {
            if arg == "--ollama" {
                backend_override = Some("ollama".into());
            } else if arg == "--claude" {
                backend_override = Some("claude".into());
            } else if arg == "--model" {
                if let Some(model) = args.next() {
                    model_override = Some(model.to_string());
                }
            } else {
                prompt_parts.push(arg);
            }
        }

        let prompt = prompt_parts.join(" ");

        // Apply overrides to a temporary config
        if let Some(backend) = backend_override {
            self.config.ai.backend = backend;
        }
        if let Some(model) = model_override {
            if self.config.ai.backend == "ollama" {
                self.config.ai.ollama_model = model;
            } else {
                self.config.ai.claude_model = model;
            }
        }

        self.do_ai_start(mode, &prompt);
    }

    fn handle_ai_approval(&mut self, approved: bool) {
        if self.ai_state != AiState::WaitingApproval {
            return;
        }

        let pending = self.ai_pending_tool_call.take();
        let pending_input = self.ai_pending_tool_input.take();

        if approved {
            self.ai_output.push(AiOutputLine {
                kind: AiLineKind::Text,
                text: "[Approved]".into(),
            });
            self.ai_state = AiState::Running;

            // Execute the pending tool now
            if let (Some((tool_use_id, _desc)), Some((name, input))) = (pending, pending_input) {
                let result = self.execute_ai_tool(&name, &input);
                self.ai_output.push(AiOutputLine {
                    kind: AiLineKind::ToolResult,
                    text: if result.len() > 200 {
                        format!("[result: {} chars]", result.len())
                    } else {
                        format!("[result: {}]", result.trim())
                    },
                });
                if let Some(tx) = &self.ai_req_tx {
                    let _ = tx.send(AiRequest::ToolResult {
                        tool_use_id,
                        result,
                    });
                }
            }
        } else {
            self.ai_output.push(AiOutputLine {
                kind: AiLineKind::Error,
                text: "[Rejected]".into(),
            });
            self.ai_state = AiState::Running;

            if let Some((tool_use_id, _desc)) = pending {
                // Send a tool result indicating rejection
                if let Some(tx) = &self.ai_req_tx {
                    let _ = tx.send(AiRequest::ToolResult {
                        tool_use_id,
                        result: "Tool execution was rejected by user.".into(),
                    });
                }
            }
        }
        self.ai_auto_scroll = true;
    }

    fn do_ai_cancel(&mut self) {
        if self.ai_state == AiState::Idle {
            self.log_info("[AI] No AI analysis running");
            return;
        }
        if let Some(cancel) = &self.ai_cancel {
            cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        if let Some(tx) = &self.ai_req_tx {
            let _ = tx.send(AiRequest::Cancel);
        }
        self.ai_state = AiState::Idle;
        self.ai_output.push(AiOutputLine {
            kind: AiLineKind::Error,
            text: "[Cancelled]".into(),
        });
        self.log_info("[AI] Analysis cancelled");
    }

    fn poll_dex_load(&mut self) {
        let result = if let Some(rx) = &self.dex_load_rx {
            match rx.try_recv() {
                Ok(r) => Some(r),
                Err(mpsc::TryRecvError::Empty) => None,
                Err(mpsc::TryRecvError::Disconnected) => {
                    // Thread finished without sending (shouldn't happen)
                    self.auto_dex_loading = false;
                    self.dex_load_rx = None;
                    None
                }
            }
        } else {
            None
        };

        if let Some(result) = result {
            self.dex_load_rx = None;
            self.auto_dex_loading = false;
            match result {
                Ok((dex_data, local_path)) => {
                    if self.dex_data.is_empty() {
                        // Only apply if user hasn't manually loaded something in the meantime
                        let mut total_m = 0;
                        let mut total_c = 0;
                        for d in &dex_data {
                            total_m += d.methods.len();
                            total_c += d.class_defs.len();
                        }
                        let n = dex_data.len();
                        self.dex_labels = (0..n).map(|_| "apk".to_string()).collect();
                        self.dynamic_dex_count = 0;
                        self.dex_data = dex_data;
                        self.log_info(&format!(
                            "Auto-loaded {} DEX from {}: {} classes, {} methods  - symbols resolved",
                            n, local_path, total_c, total_m
                        ));
                        // Re-disassemble current bytecodes now that DEX symbols are available
                        if !self.current_bytecode_bytes.is_empty() {
                            if let Some(class) = &self.current_class.clone() {
                                let dex = self.find_dex_for_class(class);
                                self.bytecodes = disassembler::disassemble(&self.current_bytecode_bytes, dex);
                            }
                        }
                    }
                }
                Err(e) => {
                    self.log_debug(&format!("Auto-load DEX failed  - use 'apk <path>' to load manually ({})", e));
                }
            }
        }
    }

    fn poll_ai_events(&mut self) {
        let mut events = Vec::new();

        if let Some(rx) = &self.ai_evt_rx {
            loop {
                match rx.try_recv() {
                    Ok(evt) => events.push(evt),
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        if self.ai_state == AiState::Running {
                            self.ai_state = AiState::Idle;
                        }
                        break;
                    }
                }
            }
        }

        for evt in events {
            self.handle_ai_event(evt);
        }
    }

    fn handle_ai_event(&mut self, evt: AiEvent) {
        match evt {
            AiEvent::TextDelta(text) => {
                // Split text into lines, wrap long lines at ~114 chars
                for line in text.lines() {
                    let kind = if line.starts_with("## ") || line.starts_with("# ") {
                        AiLineKind::Header
                    } else {
                        AiLineKind::Text
                    };
                    if line.len() <= 114 {
                        self.ai_output.push(AiOutputLine {
                            kind,
                            text: line.to_string(),
                        });
                    } else {
                        // Word-wrap long lines
                        for wrapped in wrap_line(line, 114) {
                            self.ai_output.push(AiOutputLine {
                                kind,
                                text: wrapped,
                            });
                        }
                    }
                }
                self.ai_auto_scroll = true;
            }
            AiEvent::ToolCall { tool_use_id, name, input } => {
                let args = if let Some(obj) = input.as_object() {
                    obj.iter()
                        .map(|(k, v)| format!("{}={}", k, v))
                        .collect::<Vec<_>>()
                        .join(", ")
                } else {
                    String::new()
                };
                self.ai_output.push(AiOutputLine {
                    kind: AiLineKind::ToolCall,
                    text: format!("[AI] > {} {}", name, args),
                });
                self.ai_auto_scroll = true;

                // Ask mode: execution tools need y/n confirmation
                let needs_confirm = self.ai_mode == AiMode::Ask
                    && crate::ai_tools::is_execution_tool(&name);

                if needs_confirm {
                    let desc = format!("{} {}", name, args);
                    self.ai_state = AiState::WaitingApproval;
                    self.ai_pending_tool_call = Some((tool_use_id, desc.clone()));
                    self.ai_output.push(AiOutputLine {
                        kind: AiLineKind::Header,
                        text: format!("[AI] Approve? {} (y/n)", desc),
                    });
                    // Store tool info for later execution
                    self.ai_pending_tool_input = Some((name, input));
                } else {
                    // Execute immediately (Auto mode or read-only tool)
                    let result = self.execute_ai_tool(&name, &input);
                    self.ai_output.push(AiOutputLine {
                        kind: AiLineKind::ToolResult,
                        text: if result.len() > 200 {
                            format!("[result: {} chars]", result.len())
                        } else {
                            format!("[result: {}]", result.trim())
                        },
                    });

                    if let Some(tx) = &self.ai_req_tx {
                        let _ = tx.send(AiRequest::ToolResult {
                            tool_use_id,
                            result,
                        });
                    }
                }
            }
            AiEvent::AnalysisBlock(text) => {
                self.ai_output.push(AiOutputLine {
                    kind: AiLineKind::Header,
                    text,
                });
                self.ai_auto_scroll = true;
            }
            AiEvent::ConfirmRequest { tool_use_id, description } => {
                self.ai_state = AiState::WaitingApproval;
                self.ai_pending_tool_call = Some((tool_use_id, description.clone()));
                self.ai_output.push(AiOutputLine {
                    kind: AiLineKind::Header,
                    text: format!("[AI] Approve? {} (y/n)", description),
                });
                self.ai_auto_scroll = true;
            }
            AiEvent::Done => {
                self.ai_state = AiState::Idle;
                self.ai_output.push(AiOutputLine {
                    kind: AiLineKind::Header,
                    text: "[Analysis complete]".into(),
                });
                self.ai_auto_scroll = true;
                self.log_info("[AI] Analysis complete");
                // Clean up channels
                self.ai_req_tx = None;
                self.ai_evt_rx = None;
                self.ai_cancel = None;
            }
            AiEvent::Error(err) => {
                self.ai_state = AiState::Idle;
                self.ai_output.push(AiOutputLine {
                    kind: AiLineKind::Error,
                    text: format!("[Error] {}", err),
                });
                self.ai_auto_scroll = true;
                self.log_error(&format!("[AI] Error: {}", err));
                self.ai_req_tx = None;
                self.ai_evt_rx = None;
                self.ai_cancel = None;
            }
        }
    }

    // -------------------------------------------------------------------
    // AI tool execution
    // -------------------------------------------------------------------

    fn execute_ai_tool(&mut self, name: &str, input: &serde_json::Value) -> String {
        match name {
            // ---- Local state tools (read directly from App) ----
            "get_state" => {
                let state = format!("{:?}", self.state);
                let loc = if let (Some(cls), Some(meth)) = (&self.current_class, &self.current_method) {
                    let short = short_class(cls);
                    if let Some(line) = self.current_line {
                        if line >= 0 { format!("{}.{}:{}", short, meth, line) }
                        else { format!("{}.{}", short, meth) }
                    } else { format!("{}.{}", short, meth) }
                } else { "(not suspended)".into() };
                format!(
                    "State: {}\nLocation: {}\nRecording: {}\nBreakpoints: {}\nThreads: {}\nDEX loaded: {}\nDEX strings: {}\nCall records: {}",
                    state, loc, self.recording_active, self.bp_manager.count(),
                    self.threads.len(), !self.dex_data.is_empty(),
                    self.dex_data.iter().map(|d| d.strings.len()).sum::<usize>(),
                    self.call_records.len()
                )
            }
            "get_locals" => {
                if self.locals.is_empty() {
                    "No locals available (not suspended or no debug info)".into()
                } else {
                    self.locals.iter().map(|l| {
                        format!("  {} ({}) = {}", l.name, short_type(&l.var_type), l.value)
                    }).collect::<Vec<_>>().join("\n")
                }
            }
            "get_stack" => {
                if self.stack.is_empty() {
                    "No stack available".into()
                } else {
                    self.stack.iter().enumerate().map(|(i, f)| {
                        let cls = short_class(&f.class);
                        let line_str = if f.line >= 0 { format!(":{}", f.line) } else { String::new() };
                        format!("  #{} {}.{}{}", i, cls, f.method, line_str)
                    }).collect::<Vec<_>>().join("\n")
                }
            }
            "get_bytecodes" => {
                if self.bytecodes.is_empty() {
                    "No bytecodes loaded".into()
                } else {
                    let cls = self.current_class.as_deref().unwrap_or("?");
                    let meth = self.current_method.as_deref().unwrap_or("?");
                    let loc = self.current_loc.unwrap_or(-1);
                    let mut result = format!("{}.{} @{:04x}\n", short_class(cls), meth, loc);
                    for instr in &self.bytecodes {
                        let marker = if self.current_loc == Some(instr.offset as i64) { ">>>" } else { "   " };
                        result.push_str(&format!("{} {:04x}: {}\n", marker, instr.offset, instr.text));
                    }
                    result
                }
            }
            "get_threads" => {
                if self.threads.is_empty() {
                    "No thread data available".into()
                } else {
                    self.threads.iter().map(|t| {
                        let daemon = if t.daemon { " (daemon)" } else { "" };
                        format!("  {} pri={}{}", t.name, t.priority, daemon)
                    }).collect::<Vec<_>>().join("\n")
                }
            }
            "get_breakpoints" => {
                if self.bp_manager.breakpoints.is_empty() {
                    "No breakpoints set".into()
                } else {
                    self.bp_manager.breakpoints.iter().map(|bp| {
                        let cls = short_class(&bp.class);
                        let cond_str = if let Some(cond) = self.bp_manager.get_condition(bp.id) {
                            format!(" [{}] ({}x)", cond, cond.hit_count)
                        } else {
                            String::new()
                        };
                        format!("  #{} {}.{} @{}{}", bp.id, cls, bp.method, bp.location, cond_str)
                    }).collect::<Vec<_>>().join("\n")
                }
            }
            "get_calls" => {
                let limit = input.get("limit").and_then(|v| v.as_i64()).unwrap_or(50) as usize;
                if self.call_records.is_empty() {
                    "No recorded calls. Use record_start to begin recording.".into()
                } else {
                    let start = self.call_records.len().saturating_sub(limit);
                    let mut result = format!("{} total calls (showing last {})\n", self.call_records.len(), limit.min(self.call_records.len()));
                    for r in self.call_records.iter().skip(start) {
                        result.push_str(&format_call_record(r));
                        result.push('\n');
                    }
                    result
                }
            }
            "get_log" => {
                let limit = input.get("limit").and_then(|v| v.as_i64()).unwrap_or(30) as usize;
                if self.log.is_empty() {
                    "No log entries".into()
                } else {
                    let start = self.log.len().saturating_sub(limit);
                    self.log.iter().skip(start).map(|e| {
                        format_log_entry(e)
                    }).collect::<Vec<_>>().join("\n")
                }
            }

            // ---- Agent command tools (via execute_tool_as_command) ----
            "cls" => {
                let pattern = input.get("pattern").and_then(|v| v.as_str()).unwrap_or("");
                self.execute_tool_as_command(&format!("cls {}", pattern))
            }
            "methods" => {
                let class = input.get("class").and_then(|v| v.as_str()).unwrap_or("");
                self.execute_tool_as_command(&format!("methods {}", class))
            }
            "fields" => {
                let class = input.get("class").and_then(|v| v.as_str()).unwrap_or("");
                self.execute_tool_as_command(&format!("fields {}", class))
            }
            "dis" => {
                let class = input.get("class").and_then(|v| v.as_str()).unwrap_or("");
                let method = input.get("method").and_then(|v| v.as_str()).unwrap_or("");
                self.execute_tool_as_command(&format!("dis {} {}", class, method))
            }
            "strings" => {
                let pattern = input.get("pattern").and_then(|v| v.as_str()).unwrap_or("");
                self.execute_tool_as_command(&format!("strings {}", pattern))
            }
            "xref" => {
                let pattern = input.get("pattern").and_then(|v| v.as_str()).unwrap_or("");
                self.execute_tool_as_command(&format!("xref {}", pattern))
            }
            "heapstr" => {
                let pattern = input.get("pattern").and_then(|v| v.as_str()).unwrap_or("");
                self.execute_tool_as_command(&format!("heapstr {}", pattern))
            }
            "bp" => {
                let class = input.get("class").and_then(|v| v.as_str()).unwrap_or("");
                let method = input.get("method").and_then(|v| v.as_str()).unwrap_or("");
                let mut cmd = format!("bp {} {}", class, method);
                if let Some(n) = input.get("hits").and_then(|v| v.as_i64()) {
                    cmd.push_str(&format!(" --hits {}", n));
                }
                if let Some(n) = input.get("every").and_then(|v| v.as_i64()) {
                    cmd.push_str(&format!(" --every {}", n));
                }
                if let Some(w) = input.get("when").and_then(|v| v.as_str()) {
                    cmd.push_str(&format!(" --when {}", w));
                }
                self.execute_tool_as_command(&cmd)
            }
            "bd" => {
                let id = input.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
                self.execute_tool_as_command(&format!("bd {}", id))
            }
            "bp_profile" => {
                let profile = input.get("profile").and_then(|v| v.as_str()).unwrap_or("bp-all");
                self.execute_tool_as_command(profile)
            }
            "continue_app" => {
                self.execute_tool_as_command("c")
            }
            "step_into" => {
                self.execute_tool_as_command("si")
            }
            "step_over" => {
                self.execute_tool_as_command("s")
            }
            "step_out" => {
                self.execute_tool_as_command("sout")
            }
            "force_return" => {
                let value = input.get("value").and_then(|v| v.as_str()).unwrap_or("void");
                self.execute_tool_as_command(&format!("fr {}", value))
            }
            "record_start" => {
                self.execute_tool_as_command("record start")
            }
            "record_stop" => {
                self.execute_tool_as_command("record stop")
            }
            "anti" => {
                let class = input.get("class").and_then(|v| v.as_str()).unwrap_or("");
                let method = input.get("method").and_then(|v| v.as_str()).unwrap_or("");
                let mut cmd = format!("anti {} {}", class, method);
                if let Some(v) = input.get("value").and_then(|v| v.as_str()) {
                    cmd.push_str(&format!(" {}", v));
                }
                self.execute_tool_as_command(&cmd)
            }
            _ => format!("Unknown tool: {}", name),
        }
    }

    /// Execute a command and capture log entries added during execution as the result.
    fn execute_tool_as_command(&mut self, cmd: &str) -> String {
        let log_before = self.log.len();
        self.execute_command(cmd);
        // Capture new log entries as the result
        let new_entries: Vec<String> = self.log[log_before..]
            .iter()
            .map(|e| format_log_entry(e))
            .collect();
        if new_entries.is_empty() {
            format!("Command '{}' sent (async result pending)", cmd)
        } else {
            new_entries.join("\n")
        }
    }

    // -------------------------------------------------------------------
    // Logging helpers
    // -------------------------------------------------------------------

    fn log_entry(&mut self, level: LogLevel, text: &str) {
        for line in text.lines() {
            self.log.push(LogEntry {
                level: level.clone(),
                text: line.to_string(),
            });
        }
        if self.log.len() > MAX_LOG_ENTRIES {
            self.log.drain(0..self.log.len() - MAX_LOG_ENTRIES);
        }
        self.log_auto_scroll = true;
    }

    fn log_info(&mut self, text: &str) { self.log_entry(LogLevel::Info, text); }
    fn log_error(&mut self, text: &str) { self.log_entry(LogLevel::Error, text); }
    fn log_debug(&mut self, text: &str) { self.log_entry(LogLevel::Debug, text); }
    fn log_agent(&mut self, text: &str) { self.log_entry(LogLevel::Agent, text); }
    fn log_exception(&mut self, text: &str) { self.log_entry(LogLevel::Exception, text); }
    fn log_call(&mut self, text: &str) { self.log_entry(LogLevel::Call, text); }
}

fn format_log_entry(entry: &LogEntry) -> String {
    let prefix = match entry.level {
        LogLevel::Info => "[INFO] ",
        LogLevel::Error => "[ERR]  ",
        LogLevel::Crypto => "[CRYPT]",
        LogLevel::Exception => "[EXCP] ",
        LogLevel::Debug => "[DBG]  ",
        LogLevel::Agent => "[AGNT] ",
        LogLevel::Call => "[CALL] ",
    };
    format!("{} {}", prefix, entry.text)
}

fn format_call_record(r: &CallRecord) -> String {
    let short = short_class(&r.class);
    let indent = "  ".repeat(r.depth.min(10));
    if r.is_exit {
        let arrow = if r.exception { "!!" } else { "<-" };
        let suffix = if r.exception {
            " !EXCEPTION".to_string()
        } else if let Some(ret) = &r.ret {
            format!(" -> {}", ret)
        } else {
            String::new()
        };
        format!("     {}{} {}.{}{}", indent, arrow, short, r.method, suffix)
    } else {
        let args_str = if r.args.is_empty() {
            String::new()
        } else {
            format!("({})", r.args.join(", "))
        };
        let suffix = if r.exception {
            " !EXCEPTION".to_string()
        } else {
            String::new()
        };
        format!("{:>4} {}-> {}.{}{}{}", r.seq + 1, indent, short, r.method, args_str, suffix)
    }
}

/// Split a long line into chunks for readable logging.
/// Prefers breaking at ", " or " " boundaries. Falls back to hard break.
fn split_long_line(line: &str, max_width: usize) -> Vec<String> {
    let trimmed = line.trim_start();
    let mut result = Vec::new();
    let mut remaining = trimmed;
    while remaining.len() > max_width {
        // Prefer ", " then " " then "." then "("  - cover long class names
        let split_at = remaining[..max_width]
            .rfind(", ")
            .map(|i| i + 2)
            .or_else(|| remaining[..max_width].rfind(' ').map(|i| i + 1))
            .or_else(|| remaining[..max_width].rfind('.').map(|i| i + 1))
            .or_else(|| remaining[..max_width].rfind('(').map(|i| i + 1))
            .unwrap_or(max_width);
        result.push(remaining[..split_at].to_string());
        remaining = &remaining[split_at..];
    }
    if !remaining.is_empty() {
        result.push(remaining.to_string());
    }
    result
}

/// Extract the word at a given column position in a string.
/// A "word" is a contiguous sequence of non-whitespace, non-comma characters.
/// For quoted strings, the entire quoted portion (including quotes) is returned.
/// Returns true if a JNI type signature represents a primitive we can set via setreg.
/// '?' is the fallback type for uncovered slots (treated as int).
fn is_primitive_type(var_type: &str) -> bool {
    matches!(var_type.chars().next(),
        Some('I' | 'J' | 'F' | 'D' | 'Z' | 'B' | 'S' | 'C' | '?'))
}

fn word_at_col<'a>(line: &'a str, col: usize) -> Option<&'a str> {
    if col >= line.len() {
        return None;
    }
    let bytes = line.as_bytes();

    // If clicking inside a quoted string, return the whole quoted string
    let mut in_quote = false;
    let mut quote_start = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'"' {
            if in_quote {
                // Closing quote
                if col >= quote_start && col <= i {
                    return Some(&line[quote_start..=i]);
                }
                in_quote = false;
            } else {
                // Opening quote
                in_quote = true;
                quote_start = i;
            }
        }
    }

    // Otherwise, find word boundaries (split on whitespace and commas)
    let is_delim = |b: u8| b == b' ' || b == b',' || b == b'{' || b == b'}';
    if is_delim(bytes[col]) {
        return None;
    }

    let mut start = col;
    while start > 0 && !is_delim(bytes[start - 1]) {
        start -= 1;
    }
    let mut end = col;
    while end < bytes.len() && !is_delim(bytes[end]) {
        end += 1;
    }

    let word = &line[start..end];
    if word.is_empty() { None } else { Some(word) }
}

/// If `word` looks like a hex string (even number of hex chars, >=4 chars),
/// decode to bytes. If all bytes are printable ASCII (0x20..0x7E), return the string.
fn try_hex_to_ascii(word: &str) -> Option<String> {
    let word = word.trim_matches(|c| c == '.' || c == ')' || c == ',');
    if word.len() < 4 || word.len() % 2 != 0 {
        return None;
    }
    if !word.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let bytes: Vec<u8> = (0..word.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&word[i..i + 2], 16).ok())
        .collect();
    if bytes.len() != word.len() / 2 {
        return None;
    }
    if bytes.iter().all(|&b| b >= 0x20 && b <= 0x7E) {
        Some(String::from_utf8(bytes).unwrap())
    } else {
        None
    }
}

/// Scan a string for the longest contiguous hex sequence that decodes to printable ASCII.
/// Works on full untruncated values (not dependent on click column).
fn find_hex_ascii_in(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut best: Option<String> = None;
    let mut i = 0;
    while i < bytes.len() {
        // Find start of hex run
        if !bytes[i].is_ascii_hexdigit() {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
            i += 1;
        }
        let hex_str = &text[start..i];
        // Need even length, at least 4 chars
        let len = if hex_str.len() % 2 != 0 { hex_str.len() - 1 } else { hex_str.len() };
        if len < 4 {
            continue;
        }
        let hex_str = &hex_str[..len];
        if let Some(ascii) = try_hex_to_ascii(hex_str) {
            if best.as_ref().map_or(true, |b| ascii.len() > b.len()) {
                best = Some(ascii);
            }
        }
    }
    best
}

/// Format a "Copy: word" label for the context menu.
/// Truncates long words and pads for consistent menu width.
fn copy_word_label(word: &str) -> String {
    let display = if word.len() > 18 {
        format!("{}...", &word[..15])
    } else {
        word.to_string()
    };
    format!("  Copy: {}", display)
}

/// Parse a Dalvik z-variant conditional jump instruction.
/// Returns (slot, taken_value, not_taken_value, target_label) or None.
/// Handles: if-eqz, if-nez, if-ltz, if-gez, if-gtz, if-lez
fn parse_cond_jump(text: &str) -> Option<(i32, i64, i64, String)> {
    let mut parts = text.split_whitespace();
    let opcode = parts.next()?;
    let (taken, not_taken): (i64, i64) = match opcode {
        "if-eqz" => (0, 1),
        "if-nez" => (1, 0),
        "if-ltz" => (-1, 0),
        "if-gez" => (0, -1),
        "if-gtz" => (1, 0),
        "if-lez" => (0, 1),
        _ => return None,
    };
    // "v3,"
    let reg_str = parts.next()?;
    let slot: i32 = reg_str.trim_start_matches('v').trim_end_matches(',').parse().ok()?;
    // "001a"
    let target = parts.next()?.to_string();
    Some((slot, taken, not_taken, target))
}

fn classify_call(class_sig: &str) -> CallCategory {
    if class_sig.starts_with("Ljavax/crypto/")
        || class_sig.starts_with("Ljava/security/")
        || class_sig.starts_with("Ljavax/net/ssl/")
    {
        CallCategory::Crypto
    } else if class_sig.starts_with("Ljava/net/")
        || class_sig.starts_with("Lokhttp3/")
        || class_sig.starts_with("Lcom/android/volley/")
    {
        CallCategory::Network
    } else if class_sig.starts_with("Ljava/lang/Runtime;")
        || class_sig.starts_with("Ljava/lang/ProcessBuilder")
    {
        CallCategory::Exec
    } else if class_sig.starts_with("Ljava/lang/reflect/")
        || class_sig.starts_with("Ljava/lang/Class;")
        || class_sig.starts_with("Ljava/lang/ClassLoader;")
    {
        CallCategory::Reflection
    } else if class_sig.starts_with("Ldalvik/system/DexClassLoader")
        || class_sig.starts_with("Ldalvik/system/InMemoryDexClassLoader")
        || class_sig.starts_with("Ldalvik/system/PathClassLoader")
        || class_sig.starts_with("Ldalvik/system/DexFile")
        || class_sig.starts_with("Ldalvik/system/BaseDexClassLoader")
    {
        CallCategory::DexLoad
    } else if class_sig.starts_with("Landroid/telephony/")
        || class_sig.starts_with("Landroid/content/ContentResolver;")
        || class_sig.starts_with("Landroid/location/")
        || class_sig.starts_with("Landroid/content/pm/PackageManager;")
    {
        CallCategory::Exfil
    } else {
        CallCategory::Other
    }
}

/// Format bytes as a hex dump (16 bytes per row with ASCII sidebar).
fn format_hexdump(data: &[u8], mut emit: impl FnMut(&str)) {
    for chunk_start in (0..data.len()).step_by(16) {
        let chunk_end = (chunk_start + 16).min(data.len());
        let chunk = &data[chunk_start..chunk_end];

        // Offset
        let mut line = format!("  {:04x}: ", chunk_start);

        // Hex bytes
        for (i, byte) in chunk.iter().enumerate() {
            line.push_str(&format!("{:02x} ", byte));
            if i == 7 { line.push(' '); } // extra space at midpoint
        }
        // Pad if less than 16 bytes
        for i in chunk.len()..16 {
            line.push_str("   ");
            if i == 7 { line.push(' '); }
        }

        // ASCII
        line.push(' ');
        for byte in chunk {
            if *byte >= 0x20 && *byte <= 0x7e {
                line.push(*byte as char);
            } else {
                line.push('.');
            }
        }

        emit(&line);
    }
}

fn apply_scroll(current: usize, delta: i32, max: usize) -> usize {
    if delta < 0 {
        current.saturating_sub((-delta) as usize)
    } else {
        (current + delta as usize).min(max.saturating_sub(1))
    }
}

fn in_rect(col: u16, row: u16, r: ratatui::layout::Rect) -> bool {
    col >= r.x && col < r.x + r.width && row >= r.y && row < r.y + r.height
}

/// Find which styled tab was clicked. Each tab renders as " Name " (space-padded).
fn find_styled_tab_click(rel: usize, tab_names: &[&str]) -> Option<usize> {
    let mut pos = 1usize; // leading space in title
    for (i, name) in tab_names.iter().enumerate() {
        // Each tab span is " Name " = space + name + space
        let span_len = 1 + name.len() + 1;
        if rel >= pos && rel < pos + span_len {
            return Some(i);
        }
        pos += span_len;
    }
    None
}

/// Find which tab was clicked given the title format and known active index.
fn find_tab_click(rel: usize, tab_names: &[&str], active_idx: usize) -> Option<usize> {
    let mut pos = 1usize; // leading space

    for (i, name) in tab_names.iter().enumerate() {
        let start = pos;
        if i == active_idx {
            // "[Name]" = brackets + name
            let end = pos + 1 + name.len() + 1; // [Name]
            if rel >= start && rel < end {
                return Some(i);
            }
            pos = end + 1; // trailing space
        } else {
            // "Name"
            let end = pos + name.len();
            if rel >= start && rel < end {
                return Some(i);
            }
            pos = end + 1; // trailing space
        }
    }
    None
}
