use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Agent → Server (inbound messages)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum AgentMessage {
    #[serde(rename = "connected")]
    Connected {
        pid: i32,
        version: String,
        #[serde(default)]
        device: Option<String>,
        #[serde(default)]
        api_level: Option<i32>,
        capabilities: Option<Capabilities>,
        #[serde(default)]
        package_name: Option<String>,
    },

    #[serde(rename = "cls_result")]
    ClsResult {
        count: i32,
        classes: Vec<ClassEntry>,
    },

    #[serde(rename = "methods_result")]
    MethodsResult {
        class: String,
        count: i32,
        methods: Vec<MethodEntry>,
    },

    #[serde(rename = "fields_result")]
    FieldsResult {
        class: String,
        count: i32,
        fields: Vec<FieldEntry>,
    },

    #[serde(rename = "threads_result")]
    ThreadsResult {
        count: i32,
        threads: Vec<ThreadEntry>,
    },

    #[serde(rename = "dis_result")]
    DisResult {
        class: String,
        method: String,
        bytecode_len: i32,
        bytecodes_b64: String,
        current_loc: Option<i64>,
    },

    #[serde(rename = "bp_set_ok")]
    BpSetOk {
        id: i32,
        class: String,
        method: String,
        location: i64,
    },

    #[serde(rename = "bp_clear_ok")]
    BpClearOk { id: i32 },

    #[serde(rename = "bp_list_result")]
    BpListResult {
        count: i32,
        breakpoints: Vec<BreakpointEntry>,
    },

    #[serde(rename = "bp_hit")]
    BpHit {
        bp_id: i32,
        class: String,
        method: String,
        sig: String,
        location: i64,
        line: i32,
    },

    #[serde(rename = "step_hit")]
    StepHit {
        class: String,
        method: String,
        sig: String,
        location: i64,
        line: i32,
    },

    #[serde(rename = "stepping")]
    Stepping { mode: String },

    #[serde(rename = "step_thread_end")]
    StepThreadEnd {},

    #[serde(rename = "resumed")]
    Resumed {},

    #[serde(rename = "suspended")]
    Suspended {
        thread: Option<String>,
        class: String,
        method: String,
        sig: String,
        location: i64,
        line: i32,
    },

    #[serde(rename = "locals_result")]
    LocalsResult { vars: Vec<LocalVar> },

    #[serde(rename = "regs_result")]
    RegsResult { regs: Vec<RegValue> },

    #[serde(rename = "stack_result")]
    StackResult {
        count: i32,
        frames: Vec<StackFrame>,
    },

    #[serde(rename = "inspect_result")]
    InspectResult {
        class: String,
        slot: i32,
        fields: Vec<FieldValue>,
    },

    #[serde(rename = "eval_result")]
    EvalResult {
        expr: String,
        return_type: String,
        value: String,
    },

    #[serde(rename = "hexdump_result")]
    HexdumpResult {
        slot: i32,
        array_type: String,
        length: i32,
        data_b64: String,
    },

    #[serde(rename = "heap_result")]
    HeapResult {
        class: String,
        total: i32,
        reported: i32,
        objects: Vec<HeapObject>,
    },

    #[serde(rename = "heap_strings_result")]
    HeapStringsResult {
        pattern: String,
        total_strings: i32,
        matches: i32,
        strings: Vec<HeapStringEntry>,
    },

    #[serde(rename = "memdump_result")]
    MemDumpResult {
        addr: u64,
        size: u64,
        #[serde(default)]
        path: Option<String>,
        #[serde(default)]
        data_b64: Option<String>,
    },

    #[serde(rename = "dex_loaded")]
    DexLoaded {
        source: String,
        #[serde(default)]
        path: Option<String>,
        size: i64,
        dex_b64: String,
    },

    #[serde(rename = "call_entry")]
    CallEntry {
        seq: i32,
        ts: i64,
        thread: String,
        class: String,
        method: String,
        #[serde(default)]
        sig: Option<String>,
        #[serde(default)]
        args: Vec<String>,
    },

    #[serde(rename = "call_exit")]
    CallExit {
        thread: String,
        class: String,
        method: String,
        #[serde(default)]
        ret: Option<String>,
        #[serde(default)]
        exception: bool,
    },

    #[serde(rename = "record_started")]
    RecordStarted {},

    #[serde(rename = "record_stopped")]
    RecordStopped {
        total: i32,
    },

    #[serde(rename = "call_overflow")]
    CallOverflow {
        dropped: i32,
        window_ms: i32,
    },

    #[serde(rename = "bp_deferred")]
    BpDeferred { id: i32, class: String, method: String },

    #[serde(rename = "tm_classes")]
    TmClasses { classes: Vec<String> },

    #[serde(rename = "redefine_ok")]
    RedefineOk { class_sig: String },

    #[serde(rename = "redefine_error")]
    RedefineError { class_sig: String, err: i32 },

    #[serde(rename = "error")]
    Error { msg: String },

    #[serde(rename = "exception")]
    Exception {
        exception_class: String,
        message: String,
        class: String,
        method: String,
        location: i64,
        caught: bool,
        catch_class: Option<String>,
        catch_method: Option<String>,
    },

}

// ---------------------------------------------------------------------------
// Nested types for agent messages
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct Capabilities {
    pub breakpoints: Option<bool>,
    pub single_step: Option<bool>,
    pub local_vars: Option<bool>,
    pub line_numbers: Option<bool>,
    pub bytecodes: Option<bool>,
    pub tag_objects: Option<bool>,
    pub force_early_return: Option<bool>,
    pub pop_frame: Option<bool>,
    #[serde(default)]
    pub redefine_classes: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClassEntry {
    pub sig: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MethodEntry {
    pub name: String,
    pub sig: String,
    pub modifiers: i32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FieldEntry {
    pub name: String,
    pub sig: String,
    pub modifiers: i32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ThreadEntry {
    pub name: String,
    pub priority: i32,
    pub daemon: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BreakpointEntry {
    pub id: i32,
    pub class: String,
    pub method: String,
    pub sig: String,
    pub location: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LocalVar {
    pub slot: i32,
    pub name: String,
    #[serde(rename = "type")]
    pub var_type: String,
    pub value: String,
    #[serde(default)]
    pub stale: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegValue {
    pub slot: i32,
    pub value: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StackFrame {
    pub depth: i32,
    pub class: String,
    pub method: String,
    pub sig: String,
    pub location: i64,
    pub line: i32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FieldValue {
    pub name: String,
    #[serde(rename = "type")]
    pub field_type: String,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HeapObject {
    pub index: i32,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HeapStringEntry {
    pub index: i32,
    pub value: String,
}

// ---------------------------------------------------------------------------
// Server → Agent (outbound commands)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "cmd")]
pub enum OutboundCommand {
    #[serde(rename = "cls")]
    Cls { pattern: String },

    #[serde(rename = "methods")]
    Methods { class: String },

    #[serde(rename = "fields")]
    Fields { class: String },

    #[serde(rename = "threads")]
    Threads {},

    #[serde(rename = "dis")]
    Dis {
        class: String,
        method: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        sig: Option<String>,
    },

    #[serde(rename = "bp_set")]
    BpSet {
        class: String,
        method: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        sig: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        location: Option<i64>,
    },

    /// Like BpSet but also calls RetransformClasses to force ART deoptimization.
    /// Workaround for repacked APKs where SetBreakpoint succeeds but OnBreakpoint
    /// never fires because ART fails to deoptimize the method.
    #[serde(rename = "bp_set_deopt")]
    BpSetDeopt {
        class: String,
        method: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        sig: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        location: Option<i64>,
    },

    #[serde(rename = "bp_clear")]
    BpClear { id: i32 },

    #[serde(rename = "bp_list")]
    BpList {},

    #[serde(rename = "continue")]
    Continue {},

    #[serde(rename = "step_into")]
    StepInto {},

    #[serde(rename = "step_over")]
    StepOver {},

    #[serde(rename = "step_out")]
    StepOut {},

    #[serde(rename = "locals")]
    Locals {},

    #[serde(rename = "regs")]
    Regs {},

    #[serde(rename = "stack")]
    Stack {},

    #[serde(rename = "inspect")]
    Inspect {
        slot: i32,
        #[serde(skip_serializing_if = "Option::is_none")]
        depth: Option<i32>,
    },

    #[serde(rename = "eval")]
    Eval {
        expr: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        depth: Option<i32>,
    },

    #[serde(rename = "hexdump")]
    Hexdump {
        slot: i32,
        #[serde(skip_serializing_if = "Option::is_none")]
        depth: Option<i32>,
    },

    #[serde(rename = "heap")]
    Heap {
        class: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        max: Option<i32>,
    },

    #[serde(rename = "heap_strings")]
    HeapStrings {
        pattern: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        max: Option<i32>,
    },

    #[serde(rename = "memdump")]
    MemDump {
        addr: u64,
        size: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        path: Option<String>,
    },

    #[serde(rename = "suspend")]
    Suspend {
        #[serde(skip_serializing_if = "Option::is_none")]
        thread: Option<String>,
    },

    #[serde(rename = "dex_read")]
    DexRead { path: String },

    #[serde(rename = "dex_dump")]
    DexDump {},

    #[serde(rename = "ssl_get_tm_classes")]
    SslGetTmClasses {},

    #[serde(rename = "force_return")]
    ForceReturn {
        return_value: i32,
    },

    #[serde(rename = "record_start")]
    RecordStart {},

    #[serde(rename = "record_stop")]
    RecordStop {},

    #[serde(rename = "redefine_class")]
    RedefineClass {
        class_sig: String,
        dex_b64: String,
        /// If present, automatically call ForceEarlyReturn with this integer value on the
        /// currently suspended thread immediately after RedefineClasses succeeds.
        /// Absent (None) means do not force — used for nop patches where execution continues.
        #[serde(skip_serializing_if = "Option::is_none")]
        return_value: Option<i32>,
    },
}
