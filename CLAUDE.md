# dexbgd - agent instructions

## Documentation
- When adding a new TUI command, update `doc/all_commands.md` with the command syntax and examples.

## Project layout
- `agent/src/` - C++ JVMTI agent (debugger.cpp is the main file)
- `server/src/` - Rust TUI server (app.rs is the main file)
- `server/src/tui/` - Panel rendering
- Agent is thin (JVMTI callbacks, JSON events). Server has all logic (disassembly, parsing, UI, AI).

## Protocol
- JSON-lines over abstract Unix socket, `\n` delimited
- Server -> Agent: `OutboundCommand` enum in `protocol.rs`, `cmd` tag
- Agent -> Server: `AgentMessage` enum in `protocol.rs`, `type` tag
- No tokio. `std::net::TcpStream` + `std::sync::mpsc`

## Build
```bash
# Agent (needs ANDROID_NDK_HOME):
cd agent && scripts\build.bat    # must use -G Ninja, not VS generator
# Copy .so to testapp jniLibs, gradlew clean assembleDebug, adb install

# Server:
cd server && cargo run
```

## Key technical gotchas

### Dalvik slots (NOT like JVM)
```
Dalvik: [local0 | local1 | ... | this | arg0 | arg1]
slot = GetMaxLocals(method) - GetArgumentsSize(method) + param_idx;
```

### ForceEarlyReturn
- Must auto-detect return type from method signature (char after `)` in JNI sig)
- Wrong variant = JVMTI_ERROR_TYPE_MISMATCH (err=34)
- `Z/B/C/S/I` -> Int, `J` -> Long, `F` -> Float, `D` -> Double, `L/[` -> Object, `V` -> Void
- Does not resume thread - must break out of command loop or call ResumeThread
- Agent enables STEP_INTO after force return to pause at caller

### Single-step threading
- `SetEventNotificationMode(ENABLE, SINGLE_STEP, nullptr)` fires for ALL threads
- `ShouldStopStepping` filters by `IsSameObject(thread, step_thread)`
- Dead step thread detected via `GetThreadInfo` failure, triggers cleanup
- `stepping_quiet` flag in server suppresses verbose logs during step sequences

### Build gotchas
- Must use `-G Ninja` for CMake (VS generator fails with NDK)
- Delete `build/` when switching generators
- `gradlew clean` when changing jniLibs
- `useLegacyPackaging = true` in build.gradle
- No unicode in user-facing strings (terminal rendering issues) — this means ALL log_info/log_error calls and any string rendered in the TUI. Use plain ASCII: `-` not `—`, `->` not `→`
- Agent .so must be bundled in APK, not /data/local/tmp/ (SELinux)
- Use bare library name for attach-agent (avoids base64 path truncation)

### Session persistence
- Per-app state saved in `sessions/<pkg>.json` next to the server binary
- `Session` struct is in `server/src/session.rs` — add new persistent fields there with `#[serde(default)]`
- Load/save happens in `app.rs`: `load_session()` / `do_save_session()` — wire new fields in both

### TUI display helpers
- `short_class(sig)` — strips package, returns bare class name (after last `.` and `$`). Use this whenever displaying a class name in the log or TUI.

### Device
- Pixel "lynx", Android 14, user build, Magisk root
- `adb shell cmd activity attach-agent <pkg> libart_jit_tracer.so`

### JVMTI capabilities (confirmed on device)
- breakpoints, single_step, local_vars, line_numbers, bytecodes: yes
- method_entry, method_exit, exceptions, tag_objects: yes
- force_early_return, pop_frame: yes
- field_access_events, field_modification_events: yes
- compiled_method_load, all_class_hook: no (user build)
