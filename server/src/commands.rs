use crate::protocol::OutboundCommand;

/// Convert a dot-separated class name to JNI signature.
/// "com.test.Foo" → "Lcom/test/Foo;"
/// If already in JNI format (starts with L or [), return as-is.
pub fn to_jni_sig(name: &str) -> String {
    if name.starts_with('L') || name.starts_with('[') {
        return name.to_string();
    }
    format!("L{};", name.replace('.', "/"))
}

/// Return alias label if defined, else short class name.
pub fn display_class(sig: &str, aliases: &std::collections::HashMap<String, String>) -> String {
    if let Some(label) = aliases.get(sig) {
        label.clone()
    } else {
        short_class(sig).to_string()
    }
}

/// Shorten a JNI class signature for display.
/// "Lcom/test/jitdemo/MainActivity;" → "MainActivity"
pub fn short_class(sig: &str) -> &str {
    let s = sig.strip_prefix('L').unwrap_or(sig);
    let s = s.strip_suffix(';').unwrap_or(s);
    s.rsplit('/').next().unwrap_or(s)
}

/// Shorten a JNI type signature for display.
/// "Ljava/lang/String;" → "String"
/// "I" → "int", "[B" → "byte[]", etc.
pub fn short_type(sig: &str) -> String {
    match sig {
        "I" => "int".into(),
        "J" => "long".into(),
        "F" => "float".into(),
        "D" => "double".into(),
        "Z" => "boolean".into(),
        "B" => "byte".into(),
        "S" => "short".into(),
        "C" => "char".into(),
        "V" => "void".into(),
        "?" => "?".into(),
        s if s.starts_with('[') => format!("{}[]", short_type(&s[1..])),
        s if s.starts_with('L') && s.ends_with(';') => {
            let inner = &s[1..s.len() - 1];
            inner.rsplit('/').next().unwrap_or(inner).into()
        }
        s => s.into(),
    }
}

/// Parse JNI parameter types from a proto descriptor.
/// "ILjava/security/Key;[B" → ["I", "Ljava/security/Key;", "[B"]
pub fn parse_jni_params(s: &str) -> Vec<&str> {
    let mut types = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let start = i;
        match bytes[i] {
            b'[' => {
                while i < bytes.len() && bytes[i] == b'[' { i += 1; }
                if i < bytes.len() {
                    if bytes[i] == b'L' {
                        while i < bytes.len() && bytes[i] != b';' { i += 1; }
                        if i < bytes.len() { i += 1; }
                    } else {
                        i += 1;
                    }
                }
                types.push(&s[start..i]);
            }
            b'L' => {
                while i < bytes.len() && bytes[i] != b';' { i += 1; }
                if i < bytes.len() { i += 1; }
                types.push(&s[start..i]);
            }
            _ => {
                i += 1;
                types.push(&s[start..i]);
            }
        }
    }
    types
}

/// Shorten a JNI proto/method signature for display.
/// "(ILjava/security/Key;)V" → "(int, Key)"
pub fn short_proto(proto: &str) -> String {
    if !proto.starts_with('(') {
        return proto.to_string();
    }
    let close = match proto.find(')') {
        Some(i) => i,
        None => return proto.to_string(),
    };
    let params_str = &proto[1..close];
    if params_str.is_empty() {
        return "()".to_string();
    }
    let params = parse_jni_params(params_str);
    let short_params: Vec<String> = params.iter().map(|p| short_type(p)).collect();
    format!("({})", short_params.join(", "))
}

/// Parse a location value: decimal, hex (0x...), or @-prefixed.
/// Accepts: "15", "0xf", "@15", "@0xf"
fn parse_location(s: &str) -> Option<i64> {
    let s = s.strip_prefix('@').unwrap_or(s);
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16).ok()
    } else {
        // Bytecode offsets are always shown in hex in the listing, so default to hex
        i64::from_str_radix(s, 16).ok()
    }
}

/// Parse user command text into an OutboundCommand (or None + error message).
pub fn parse_command(input: &str) -> Result<OutboundCommand, String> {
    let input = input.trim();
    if input.is_empty() {
        return Err("empty command".into());
    }

    let mut parts = input.splitn(2, ' ');
    let cmd = parts.next().unwrap();
    let args = parts.next().unwrap_or("").trim();

    match cmd {
        "cls" | "classes" => Ok(OutboundCommand::Cls {
            pattern: args.to_string(),
        }),

        "methods" | "m" => {
            if args.is_empty() {
                return Err("usage: methods <class>".into());
            }
            Ok(OutboundCommand::Methods {
                class: to_jni_sig(args),
            })
        }

        "fields" | "f" => {
            if args.is_empty() {
                return Err("usage: fields <class>".into());
            }
            Ok(OutboundCommand::Fields {
                class: to_jni_sig(args),
            })
        }

        "threads" | "thd" => Ok(OutboundCommand::Threads {}),

        "dis" | "disassemble" => {
            // dis <class> <method> [sig]
            let parts: Vec<&str> = args.splitn(3, ' ').collect();
            if parts.len() < 2 {
                return Err("usage: dis <class> <method> [sig]".into());
            }
            Ok(OutboundCommand::Dis {
                class: to_jni_sig(parts[0]),
                method: parts[1].to_string(),
                sig: parts.get(2).map(|s| s.to_string()),
            })
        }

        "bp" | "break" => {
            // bp <class> <method> [sig] [@location]
            // Also accepts dot-notation: bp Class.method [@loc]
            // Detect: first token has a dot, second token is a location/sig (not a method name)
            let normalized;
            let args = {
                let first = args.splitn(2, ' ').next().unwrap_or("");
                let rest = args[first.len()..].trim_start();
                if !first.starts_with('L') && !first.starts_with('[') && first.contains('.')
                    && (rest.is_empty() || rest.starts_with('@') || rest.starts_with('(')
                        || rest.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false))
                {
                    if let Some(dot) = first.rfind('.') {
                        let mut s = format!("{} {}", &first[..dot], &first[dot + 1..]);
                        if !rest.is_empty() { s.push(' '); s.push_str(rest); }
                        normalized = s;
                        normalized.as_str()
                    } else { args }
                } else { args }
            };
            let parts: Vec<&str> = args.splitn(4, ' ').collect();
            if parts.len() < 2 {
                return Err("usage: bp <class> <method> [sig] [@location]".into());
            }
            let class = to_jni_sig(parts[0]);
            let method = parts[1].to_string();
            let mut sig = None;
            let mut location = None;

            if let Some(s) = parts.get(2) {
                if s.starts_with('(') {
                    sig = Some(s.to_string());
                    if let Some(loc) = parts.get(3) {
                        location = parse_location(loc);
                    }
                } else {
                    location = parse_location(s);
                }
            }

            Ok(OutboundCommand::BpSet {
                class,
                method,
                sig,
                location,
            })
        }

        "bd" | "bc" => {
            let id: i32 = args.parse().map_err(|_| "usage: bd <id> or bd *".to_string())?;
            Ok(OutboundCommand::BpClear { id })
        }

        "bl" => Ok(OutboundCommand::BpList {}),

        "c" | "continue" | "g" => Ok(OutboundCommand::Continue {}),

        "si" | "step_into" => Ok(OutboundCommand::StepInto {}),

        "s" | "so" | "step_over" | "n" | "next" => Ok(OutboundCommand::StepOver {}),

        "sout" | "step_out" | "finish" => Ok(OutboundCommand::StepOut {}),

        "sout2" | "step_out2" => Ok(OutboundCommand::StepOut2 {}),

        "fr" | "force_return" => {
            let val = match args.trim() {
                "" | "void" | "null" | "false" | "0" => 0,
                "true" | "1" => 1,
                other => other.parse::<i32>()
                    .map_err(|_| "usage: fr true|false|null|void|<int>".to_string())?,
            };
            Ok(OutboundCommand::ForceReturn { return_value: val })
        }

        "locals" | "l" => Ok(OutboundCommand::Locals {}),

        "stack" | "bt" | "backtrace" => Ok(OutboundCommand::Stack {}),

        "inspect" | "i" => {
            // inspect <slot> [depth]   - accepts "inspect 3" or "inspect v3"
            let parts: Vec<&str> = args.splitn(2, ' ').collect();
            if parts.is_empty() || parts[0].is_empty() {
                return Err("usage: inspect <slot> [depth]".into());
            }
            let slot_str = parts[0].strip_prefix('v').unwrap_or(parts[0]);
            let slot: i32 = slot_str
                .parse()
                .map_err(|_| "slot must be a number (e.g. inspect 3 or inspect v3)".to_string())?;
            let depth = parts.get(1).and_then(|d| d.parse::<i32>().ok());
            Ok(OutboundCommand::Inspect { slot, depth })
        }

        "eval" | "e" => {
            if args.is_empty() {
                return Err("usage: eval <expr>  (e.g., eval v3.getAlgorithm())".into());
            }
            let parts: Vec<&str> = args.splitn(2, ' ').collect();
            let expr = parts[0].to_string();
            if !expr.starts_with('v') || !expr.contains('.') {
                return Err("eval: must be vN.member or vN.member()".into());
            }
            let depth = parts.get(1).and_then(|d| d.parse::<i32>().ok());
            Ok(OutboundCommand::Eval { expr, depth })
        }

        "hexdump" | "hd" => {
            // hexdump <vN> [full]
            let parts: Vec<&str> = args.splitn(2, ' ').collect();
            if parts.is_empty() || parts[0].is_empty() {
                return Err("usage: hexdump <vN> [full]".into());
            }
            let slot_str = match parts[0].strip_prefix('v') {
                Some(s) => s,
                None => return Err("usage: hexdump <vN> (e.g. hexdump v3)".into()),
            };
            let slot: i32 = slot_str
                .parse()
                .map_err(|_| "usage: hexdump <vN> (e.g. hexdump v3)".to_string())?;
            Ok(OutboundCommand::Hexdump { slot, depth: None })
        }

        "heap" => {
            // heap <class> [max]
            let parts: Vec<&str> = args.splitn(2, ' ').collect();
            if parts.is_empty() || parts[0].is_empty() {
                return Err("usage: heap <class> [max]".into());
            }
            let class = to_jni_sig(parts[0]);
            let max = parts.get(1).and_then(|m| m.parse::<i32>().ok());
            Ok(OutboundCommand::Heap { class, max })
        }

        "heapstr" | "heapstrings" => {
            // heapstr <pattern> [max]
            let parts: Vec<&str> = args.splitn(2, ' ').collect();
            if parts.is_empty() || parts[0].is_empty() {
                return Err("usage: heapstr <pattern> [max]".into());
            }
            let pattern = parts[0].to_string();
            let max = parts.get(1).and_then(|m| m.parse::<i32>().ok());
            Ok(OutboundCommand::HeapStrings { pattern, max })
        }

        "memdump" | "md" => {
            // memdump <addr> <L<len>|end_addr> [/device/path]
            let parts: Vec<&str> = args.splitn(3, ' ').collect();
            if parts.len() < 2 || parts[0].is_empty() || parts[1].is_empty() {
                return Err("usage: memdump <addr> L<len>|<end_addr> [path]".into());
            }
            let parse_hex = |s: &str| -> Result<u64, String> {
                let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
                u64::from_str_radix(s, 16).map_err(|_| format!("invalid hex value: {}", s))
            };
            let addr = parse_hex(parts[0])?;
            let size = {
                let s = parts[1];
                if let Some(len_str) = s.strip_prefix('L').or_else(|| s.strip_prefix('l')) {
                    if let Some(hex) = len_str.strip_prefix("0x").or_else(|| len_str.strip_prefix("0X")) {
                        u64::from_str_radix(hex, 16).map_err(|_| format!("invalid length: {}", len_str))?
                    } else {
                        len_str.parse::<u64>().map_err(|_| format!("invalid length: {}", len_str))?
                    }
                } else {
                    let end = parse_hex(s)?;
                    if end <= addr {
                        return Err("end address must be > start address".into());
                    }
                    end - addr
                }
            };
            if size == 0 {
                return Err("size must be > 0".into());
            }
            let path = parts.get(2).filter(|s| !s.is_empty()).map(|s| s.to_string());
            Ok(OutboundCommand::MemDump { addr, size, path })
        }

        "pause" | "suspend" => {
            let thread = if args.is_empty() {
                None
            } else {
                Some(args.to_string())
            };
            Ok(OutboundCommand::Suspend { thread })
        }

        _ => Err(format!("unknown command: {}", cmd)),
    }
}

/// Modifier flags → string (ACC_PUBLIC, ACC_STATIC, etc.)
pub fn modifiers_str(modifiers: i32) -> String {
    let mut parts = Vec::new();
    if modifiers & 0x0001 != 0 { parts.push("public"); }
    if modifiers & 0x0002 != 0 { parts.push("private"); }
    if modifiers & 0x0004 != 0 { parts.push("protected"); }
    if modifiers & 0x0008 != 0 { parts.push("static"); }
    if modifiers & 0x0010 != 0 { parts.push("final"); }
    if modifiers & 0x0020 != 0 { parts.push("synchronized"); }
    if modifiers & 0x0100 != 0 { parts.push("native"); }
    if modifiers & 0x0400 != 0 { parts.push("abstract"); }
    parts.join(" ")
}
