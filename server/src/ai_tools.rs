use serde_json::{json, Value};

use crate::ai::AiMode;

pub struct ToolDef {
    pub name: &'static str,
    pub description: &'static str,
    pub parameters: Value,
    pub is_execution: bool, // true = requires confirmation in Ask mode, rejected in Explain mode
}

pub fn all_tools() -> Vec<ToolDef> {
    vec![
        // ---------------------------------------------------------------
        // Read-only tools (15)
        // ---------------------------------------------------------------
        ToolDef {
            name: "cls",
            description: "List loaded classes matching a pattern. Returns matching class names.",
            parameters: json!({
                "type": "object",
                "properties": {
                    "pattern": { "type": "string", "description": "Class name pattern (e.g. 'Cipher', 'crypto')" }
                },
                "required": ["pattern"]
            }),
            is_execution: false,
        },
        ToolDef {
            name: "methods",
            description: "List all methods of a class.",
            parameters: json!({
                "type": "object",
                "properties": {
                    "class": { "type": "string", "description": "Class name (e.g. 'javax.crypto.Cipher')" }
                },
                "required": ["class"]
            }),
            is_execution: false,
        },
        ToolDef {
            name: "fields",
            description: "List all fields of a class.",
            parameters: json!({
                "type": "object",
                "properties": {
                    "class": { "type": "string", "description": "Class name (e.g. 'com.test.MainActivity')" }
                },
                "required": ["class"]
            }),
            is_execution: false,
        },
        ToolDef {
            name: "dis",
            description: "Disassemble a method to Dalvik bytecode.",
            parameters: json!({
                "type": "object",
                "properties": {
                    "class": { "type": "string", "description": "Class name" },
                    "method": { "type": "string", "description": "Method name" }
                },
                "required": ["class", "method"]
            }),
            is_execution: false,
        },
        ToolDef {
            name: "strings",
            description: "Search DEX constant pool for strings matching a pattern. Searches both static APK and dynamically loaded DEX files.",
            parameters: json!({
                "type": "object",
                "properties": {
                    "pattern": { "type": "string", "description": "Search pattern (substring match, case-insensitive)" }
                },
                "required": ["pattern"]
            }),
            is_execution: false,
        },
        ToolDef {
            name: "xref",
            description: "Find code locations that reference strings matching a pattern. Shows which methods load matching string constants.",
            parameters: json!({
                "type": "object",
                "properties": {
                    "pattern": { "type": "string", "description": "String pattern to search for in xrefs" }
                },
                "required": ["pattern"]
            }),
            is_execution: false,
        },
        ToolDef {
            name: "get_state",
            description: "Get the current debugger state: connection status, current location, recording status, breakpoint count.",
            parameters: json!({ "type": "object", "properties": {} }),
            is_execution: false,
        },
        ToolDef {
            name: "get_calls",
            description: "Get recorded API call history. Returns the most recent recorded calls with method names, arguments, and return values.",
            parameters: json!({
                "type": "object",
                "properties": {
                    "limit": { "type": "integer", "description": "Max calls to return (default: 50)" }
                }
            }),
            is_execution: false,
        },
        ToolDef {
            name: "get_log",
            description: "Get recent log entries from the debugger.",
            parameters: json!({
                "type": "object",
                "properties": {
                    "limit": { "type": "integer", "description": "Max entries (default: 30)" }
                }
            }),
            is_execution: false,
        },
        ToolDef {
            name: "get_locals",
            description: "Get local variables at the current suspension point.",
            parameters: json!({ "type": "object", "properties": {} }),
            is_execution: false,
        },
        ToolDef {
            name: "get_stack",
            description: "Get the current call stack.",
            parameters: json!({ "type": "object", "properties": {} }),
            is_execution: false,
        },
        ToolDef {
            name: "get_bytecodes",
            description: "Get the currently disassembled bytecodes with the current execution position.",
            parameters: json!({ "type": "object", "properties": {} }),
            is_execution: false,
        },
        ToolDef {
            name: "get_threads",
            description: "Get the list of threads.",
            parameters: json!({ "type": "object", "properties": {} }),
            is_execution: false,
        },
        ToolDef {
            name: "get_breakpoints",
            description: "Get the list of currently set breakpoints.",
            parameters: json!({ "type": "object", "properties": {} }),
            is_execution: false,
        },
        ToolDef {
            name: "get_heap_instances",
            description: "Find live instances of a class on the heap and show their values. Useful for reading runtime state that isn't visible from bytecodes (e.g. SharedPreferences contents, cipher keys, URL strings stored in fields). Capped at 50 instances.",
            parameters: json!({
                "type": "object",
                "properties": {
                    "class": { "type": "string", "description": "Class to search (e.g. 'java.lang.String', 'javax.crypto.spec.SecretKeySpec')" },
                    "max": { "type": "integer", "description": "Max instances to return (default 20, max 50)" }
                },
                "required": ["class"]
            }),
            is_execution: false,
        },
        ToolDef {
            name: "heapstr",
            description: "Search live String objects on the heap matching a pattern.",
            parameters: json!({
                "type": "object",
                "properties": {
                    "pattern": { "type": "string", "description": "Pattern to match" }
                },
                "required": ["pattern"]
            }),
            is_execution: false,
        },
        ToolDef {
            name: "get_ai_dec",
            description: "Get the cached AI-decompiled pseudo-Java source for a method. Returns the decompiled text if available, or instructs to run 'aidec' first. Use after aidec to read the decompiled source for deeper analysis without re-decompiling.",
            parameters: json!({
                "type": "object",
                "properties": {
                    "class": { "type": "string", "description": "Class name or JNI signature (e.g. 'com.test.Foo' or 'Lcom/test/Foo;')" },
                    "method": { "type": "string", "description": "Method name" }
                },
                "required": ["class", "method"]
            }),
            is_execution: false,
        },
        ToolDef {
            name: "get_xref_callers",
            description: "Find all methods that call a specific method by scanning DEX bytecodes for invoke instructions. Useful for finding what calls a suspicious API (e.g. who calls Runtime.exec or Cipher.doFinal).",
            parameters: json!({
                "type": "object",
                "properties": {
                    "class": { "type": "string", "description": "Target class (e.g. 'android.os.Debug' or 'Lcom/foo/Bar;')" },
                    "method": { "type": "string", "description": "Target method name (e.g. 'isDebuggerConnected')" }
                },
                "required": ["class", "method"]
            }),
            is_execution: false,
        },
        ToolDef {
            name: "wait_for_event",
            description: "Block until the app hits a breakpoint, step, or suspension event, then return the location and locals. Use after continue_app or step_* to wait for execution to pause. Respects 'ai cancel'.",
            parameters: json!({
                "type": "object",
                "properties": {
                    "timeout_s": { "type": "integer", "description": "Seconds to wait before giving up (default 30, max 120)" }
                }
            }),
            is_execution: false,
        },
        ToolDef {
            name: "set_local",
            description: "Set a local variable or register to a new value while suspended at a breakpoint. Use to patch inputs, skip checks, or inject values at runtime.",
            parameters: json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string", "description": "Variable name from get_locals, or register (e.g. 'v3')" },
                    "value": { "type": "string", "description": "New value: integer, 'true', 'false', or 'null'" }
                },
                "required": ["name", "value"]
            }),
            is_execution: true,
        },
        ToolDef {
            name: "get_object_fields",
            description: "Inspect the fields of an object held in a local variable while suspended. Returns class name and all instance field values. Use to read runtime state of complex objects (e.g. cipher keys, URL builders, config objects).",
            parameters: json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string", "description": "Variable name from get_locals, or register (e.g. 'v3')" }
                },
                "required": ["name"]
            }),
            is_execution: false,
        },
        ToolDef {
            name: "follow_method",
            description: "Navigate to a method and return its disassembly plus cached AI decompilation if available. Accepts a full JNI method reference (from dis output) or separate class/method. Use to drill into a method seen in an invoke instruction without manually parsing the JNI signature.",
            parameters: json!({
                "type": "object",
                "properties": {
                    "method_ref": { "type": "string", "description": "Full JNI method ref from dis output, e.g. 'Lcom/example/Foo;->bar(I)V'" },
                    "class": { "type": "string", "description": "Class name (dot or JNI form), used when method_ref is not provided" },
                    "method": { "type": "string", "description": "Method name, used when method_ref is not provided" }
                }
            }),
            is_execution: false,
        },

        // ---------------------------------------------------------------
        // Execution tools (9)  - gated by mode
        // ---------------------------------------------------------------
        ToolDef {
            name: "bp",
            description: "Set a breakpoint on a method. Supports conditional breakpoints with --hits, --every, --when.",
            parameters: json!({
                "type": "object",
                "properties": {
                    "class": { "type": "string", "description": "Class name" },
                    "method": { "type": "string", "description": "Method name" },
                    "hits": { "type": "integer", "description": "Break on Nth hit only" },
                    "every": { "type": "integer", "description": "Break every Nth hit" },
                    "when": { "type": "string", "description": "Variable condition expression, e.g. 'algo == \"AES\"' or 'v0 > 5'" }
                },
                "required": ["class", "method"]
            }),
            is_execution: true,
        },
        ToolDef {
            name: "bd",
            description: "Clear (delete) a breakpoint by ID.",
            parameters: json!({
                "type": "object",
                "properties": {
                    "id": { "type": "integer", "description": "Breakpoint ID to clear" }
                },
                "required": ["id"]
            }),
            is_execution: true,
        },
        ToolDef {
            name: "bp_profile",
            description: "Set a predefined breakpoint profile. Available profiles: bp-crypto, bp-network, bp-exec, bp-exfil, bp-detect, bp-all.",
            parameters: json!({
                "type": "object",
                "properties": {
                    "profile": { "type": "string", "description": "Profile name (e.g. 'bp-crypto', 'bp-all')" }
                },
                "required": ["profile"]
            }),
            is_execution: true,
        },
        ToolDef {
            name: "continue_app",
            description: "Resume execution (continue from breakpoint/step).",
            parameters: json!({ "type": "object", "properties": {} }),
            is_execution: true,
        },
        ToolDef {
            name: "step_into",
            description: "Step into the next method call.",
            parameters: json!({ "type": "object", "properties": {} }),
            is_execution: true,
        },
        ToolDef {
            name: "step_over",
            description: "Step over the current instruction.",
            parameters: json!({ "type": "object", "properties": {} }),
            is_execution: true,
        },
        ToolDef {
            name: "step_out",
            description: "Step out of the current method.",
            parameters: json!({ "type": "object", "properties": {} }),
            is_execution: true,
        },
        ToolDef {
            name: "force_return",
            description: "Force the current method to return immediately with a specific value.",
            parameters: json!({
                "type": "object",
                "properties": {
                    "value": { "type": "string", "description": "Return value: 'true', 'false', 'null', 'void', or an integer" }
                },
                "required": ["value"]
            }),
            is_execution: true,
        },
        ToolDef {
            name: "record_start",
            description: "Start recording API calls. Enables method entry/exit tracing for security-relevant APIs.",
            parameters: json!({ "type": "object", "properties": {} }),
            is_execution: true,
        },
        ToolDef {
            name: "record_stop",
            description: "Stop recording API calls.",
            parameters: json!({ "type": "object", "properties": {} }),
            is_execution: true,
        },
        ToolDef {
            name: "anti",
            description: "Set a silent ghost breakpoint that auto-ForceEarlyReturns with a neutral value on hit. Use to bypass root detection, debuggable checks, integrity checks, license checks. Prefer over bp+force_return for persistent silent interception. Modes: (1) anti <class> <method> [value] — direct hook; (2) anti xref <pattern> — hook all methods referencing a string constant; (3) anti callers <class> <method> — hook all methods that invoke the given API (use sparingly on broad APIs).",
            parameters: json!({
                "type": "object",
                "properties": {
                    "class": { "type": "string", "description": "Class name (e.g. 'com.test.profiletest.MainActivity'), or 'xref' for string pattern mode, or 'callers' for caller-scan mode" },
                    "method": { "type": "string", "description": "Method name; or xref pattern when class='xref' (e.g. 'su'); or 'TargetClass method' when class='callers' (e.g. 'android.os.Debug isDebuggerConnected')" },
                    "value": { "type": "string", "description": "Optional return value: false/true/void/N (default: auto-detect from signature). Direct mode only." }
                },
                "required": ["class", "method"]
            }),
            is_execution: true,
        },
    ]
}

/// Get tool definitions filtered by mode (Explain mode excludes execution tools).
#[allow(dead_code)]
pub fn tools_for_mode(mode: AiMode) -> Vec<&'static ToolDef> {
    // We need static storage, so use a lazy static pattern via leak
    // Instead, we'll return owned copies. The caller can use them.
    // Actually, let's just filter on the fly since tools() returns Vec.
    // We can't return &'static easily, so return owned.
    let _ = mode; // handled by caller
    Vec::new() // placeholder  - caller uses all_tools() directly
}

/// Convert tool definitions to Claude API format.
pub fn tools_to_claude_json(mode: AiMode) -> Vec<Value> {
    all_tools()
        .iter()
        .filter(|t| mode != AiMode::Explain || !t.is_execution)
        .map(|t| {
            json!({
                "name": t.name,
                "description": t.description,
                "input_schema": t.parameters,
            })
        })
        .collect()
}

/// Convert tool definitions to Ollama API format.
pub fn tools_to_ollama_json(mode: AiMode) -> Vec<Value> {
    all_tools()
        .iter()
        .filter(|t| mode != AiMode::Explain || !t.is_execution)
        .map(|t| {
            json!({
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.parameters,
                }
            })
        })
        .collect()
}

/// Check if a tool is an execution tool.
#[allow(dead_code)]
pub fn is_execution_tool(name: &str) -> bool {
    all_tools().iter().any(|t| t.name == name && t.is_execution)
}
