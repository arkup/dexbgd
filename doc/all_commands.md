# dexbgd command reference

All commands are typed into the command bar at the bottom of the TUI.
Aliases shown as `cmd / alias`.  `[...]` = optional.  `<...>` = required.

---

## Quick reference

| Category | Key commands |
|---|---|
| Connect | `connect`, `attach <pkg>`, `disconnect` |
| Execution | `c`, `si`, `s`, `sout`, `pause` |
| Breakpoints | `bp`, `bd`, `bl`, `bp2` |
| Watchpoints | `ba`, `bad`, `bal` |
| Inspect | `locals`, `inspect`, `eval`, `r`, `stack` |
| Mutate | `setreg`, `setfield`, `setstaticfield`, `fr` |
| Browse | `cls`, `methods`, `fields`, `dis` |
| Heap | `heap`, `heapstr`, `strings`, `xref` |
| Bypass | `patch`, `anti`, `bypass-ssl`, `jni redirect` |
| Exceptions | `excp-mute`, `excp-unmute`, `excp-mutes` |
| Record | `record` |
| AI | `ai` |

---

## 1. Connection & session

```
connect                          Connect to agent (localhost:12345)
disconnect / dc                  Disconnect
kill                             Force-stop app + disconnect
attach <pkg>                     adb forward + connect + load APK in one shot
                                 e.g.  attach com.example.app
launch <pkg>                     Start app then attach (monkey start)
gate                             Release early-attach gate (--gate repackage)
procs / ps                       List running app processes
quit / q / exit                  Exit dexbgd
```

---

## 2. APK / DEX loading

```
apk <path|pkg>                   Load APK from device path or package name
dex <path|pkg>                   Same as apk
dex-read <path>                  Read DEX/JAR from device path while suspended
dex-dump                         Extract DEX via DexClassLoader (suspended)
```

Examples:
```
apk com.example.app
dex /data/local/tmp/classes.dex
dex-read /data/data/com.example.app/files/dynamic.dex
```

---

## 3. Execution control

```
c / g / F5                       Continue (resume thread)
si / F7                          Step into
s / so / n / next / F8           Step over
sout / finish / F9               Step out (single-step based)
sout2                            Step out via FramePop (faster, no single-step)
use sout2                        Make F9/sout use the FramePop variant
use sout                         Revert F9/sout to single-step variant
pause [thread]                   Suspend thread (like Ctrl+C)
fr <val>                         ForceEarlyReturn with value
                                 val: true | false | void | null | <int>
```

Examples:
```
c
si
sout2
fr true
fr 0
fr void
```

---

## 4. Breakpoints

```
bp <cls> <method> [sig] [@loc]   Set breakpoint
bp2 <cls> <method> [sig] [@loc]  Set breakpoint + force deopt (repacked APKs)
bp here                          Set breakpoint at current bytecode cursor
bd <id> / bc <id>                Clear breakpoint by ID
bd * / bc *                      Clear all breakpoints
bl                               List all breakpoints
```

Class can be short name, dot-notation, or full JNI sig:
```
bp MainActivity checkLicense
bp com.example.MainActivity checkLicense
bp Lcom/example/MainActivity; checkLicense
bp MainActivity checkLicense @0x0010
bp MainActivity checkLicense (Z)V
```

---

## 5. Watchpoints (break on field access)

```
ba [r|w] <class> <field>         Set watchpoint (r=read, w=write, default=both)
bad <id>                         Delete watchpoint by ID
bal                              List active watchpoints
```

Examples:
```
ba MainActivity isPremium
ba w MainActivity licenseState
ba r Lcom/example/LicenseManager; mState
```

---

## 6. Disassembly & navigation

```
dis <cls> <method> [sig]         Disassemble method (-> bytecodes panel)
u <cls> <method> [sig]           Same (WinDbg-style alias)
dis pc / u pc                    Jump to current PC in bytecodes panel
here                             Print current class.method[@offset]
```

Examples:
```
dis MainActivity checkLicense
dis MainActivity checkLicense (Z)V
dis pc
```

---

## 7. Class / method / field browsing

```
cls [pattern] / classes          List loaded classes (filter by pattern)
methods <cls> / m <cls>          List methods of a class
fields <cls> / f <cls>           List fields of a class
threads / thd                    List all threads
```

Examples:
```
cls License
cls com.example
methods MainActivity
fields LicenseManager
```

---

## 8. Locals, registers & stack

All commands below require a suspended thread (at breakpoint or step).

```
locals / l                       Show local variables (name, type, value)
r / regs                         Dump all Dalvik registers to log
r <name|vN>                      Read one register / local by name or slot
stack / bt / backtrace           Show call stack (frame depth, class, method, line)
```

Examples:
```
locals
r v0
r isPremium
stack
```

---

## 9. Object inspection

```
inspect <vN|name> / i <vN|name>  Inspect object fields at slot or local name
eval <expr> / e <expr>           Evaluate expression on live object
hexdump <vN> / hd <vN>           Hex dump byte[]/char[]/String (16 rows)
hexdump <vN> full                Extended hex dump (32 rows)
memdump <addr> L<len>            Dump native memory at address, length bytes
memdump <addr> <end>             Dump native memory address range
memdump <addr> <len> <path>      Dump native memory to file on device
```

Examples:
```
inspect v3
inspect this
inspect result
i v0
eval v3.getAlgorithm()
eval v5.length
hd v2
memdump 0x7b1234ab00 L256
memdump 0x7b1234ab00 0x7b1234ac00
memdump 0x7b1234ab00 L4096 /data/local/tmp/dump.bin
```

---

## 10. Register & field mutation

All require a suspended thread.

### setreg -- write a Dalvik register (stack frame copy only)

```
setreg <vN> <value> / sr         Set register to integer/long value
```

```
setreg v0 1
sr v3 0x1234
```

### setfield -- write an instance field directly on the heap object

```
setfield <this|vN> <field> <val> / sf
```

- `this` resolves automatically from locals
- Supports: `Z B S C I J` (all integer primitives) and `String`
- `null` clears a String field

```
setfield this isPremium true
setfield this licenseState 2
setfield this userId 999999
setfield this grade 65          (char: use ASCII decimal, 65 = 'A')
setfield this label hello world
setfield this label null
setfield v3 active true
sf this score 9999
```

### setstaticfield -- write a static field

```
setstaticfield <class> <field> <val> / ssf
```

- Class: full JNI sig (`Lcom/pkg/Class;`) or alias

```
setstaticfield Lcom/example/MainActivity; sDebugMode true
setstaticfield Lcom/example/LicenseManager; sState 2
setstaticfield Lcom/example/Config; sEndpoint https://evil.example.com
ssf Lcom/example/App; sInitialized false
```

---

## 11. Code analysis

```
strings <pat> / str <pat>        Search DEX constant pool for matching strings
xref <pat>                       Find methods that load strings matching pattern
xref-bp <pat>                    xref + auto-set breakpoints on all matches
```

Examples:
```
strings license
xref isPremium
xref-bp pinning
```

---

## 12. Heap & memory search

```
heap <cls>                       Find live instances of class on heap
heapstr <pat> / heapstrings      Find live String objects matching pattern
```

Examples:
```
heap LicenseManager
heap Lcom/example/Token;
heapstr secret
heapstr api_key
```

---

## 13. Anti-bypass & patching

### patch -- rewrite bytecode via RedefineClasses

```
patch <cls> <method> <val>       Patch method to return value immediately
                                 val: void | true | false | null | 0 | 1
patch <cls> <method> @<bci>:N nop  NOP N instructions at offset
nop-range <to_bci>               NOP from current PC to target BCI
```

```
patch MainActivity checkRoot false
patch LicenseManager validate true
patch MainActivity loadAd void
patch MainActivity decode @0x0014:3 nop
```

### anti -- silent ghost breakpoint (ForceReturn neutral value, no log spam)

```
anti <cls> <method> [val]        Ghost-BP: force return neutral/specified value
anti xref <pat>                  Anti-hook all methods loading matching string
anti callers <cls> <method>      Anti-hook all callers of a method
anti list                        Show active anti hooks
anti clear                       Remove all anti hooks
```

```
anti MainActivity isRooted
anti MainActivity isRooted false
anti xref root_check
anti callers RootBeer isRooted
```

### bypass-ssl -- auto-bypass SSL pinning

```
bypass-ssl                       Set ghost BPs on all SSL validation methods
```

### bp profiles -- bulk breakpoints on API categories

```
bp-ssl                           SSL/TLS pinning methods
bp-crypto                        Crypto APIs
bp-network                       Network APIs
bp-exec                          exec() / Runtime.exec()
bp-loader                        DexClassLoader / PathClassLoader
bp-detect                        Root / tamper detection APIs
bp-exfil                         Data exfiltration APIs
bp-all                           All of the above
```

---

## 14. Call recording

```
record / rec                     Toggle recording on/off
record start                     Start
record stop                      Stop
record clear                     Clear recorded calls
record onenter                   Toggle entry-only (hide return lines)
record flat / record simple      Flat output (no indentation)
record tree                      Tree output (indented call tree, default)
```

---

## 15. JNI monitoring & redirection

```
jni monitor / jni start          Hook RegisterNatives, capture all JNI bindings
jni stop / jni unhook            Stop monitoring
jni clear                        Clear captured list
jni redirect <class> <method> <sig> <action>
                                 Redirect JNI native method
                                 action: block | true | false | void | spoof:<val>
jni redirect <lib+0xOFFSET> <action>
                                 Redirect by native address
jni restore <class> <method> <sig>
                                 Restore original function pointer
```

Examples:
```
jni monitor
jni redirect Lcom/example/Native; checkCert (Ljava/lang/String;)Z block
jni redirect Lcom/example/Native; checkCert (Ljava/lang/String;)Z true
jni redirect libfoo.so+0x1234 spoof:1
jni restore Lcom/example/Native; checkCert (Ljava/lang/String;)Z
```

---

## 16. AI analysis

```
ai <prompt>                      Full autonomy (read + run commands)
ai ask <prompt>                  Confirm before executing commands
ai explain <prompt>              Read-only analysis
ai cancel                        Cancel running analysis
ai --claude <prompt>             Force Claude backend
ai --ollama <prompt>             Force Ollama backend
ai --model <model> <prompt>      Override model
```

Examples:
```
ai what does checkLicense do and how can I bypass it
ai ask find all root detection methods
ai explain summarize what this class does
```

---

## 17. Aliases

```
alias <class> <label>            Set short alias for a class
alias list / aliases             List all aliases
alias clear <class|*>            Remove alias(es)
```

Examples:
```
alias Lcom/example/LicenseManager; LM
alias Lcom/example/MainActivity; MA
alias list
alias clear LM
alias clear *
```

---

## 18. Watches (auto-eval on suspend)

```
watch <expr>                     Add expression to watch list
unwatch <n|expr|*>               Remove watch by index, expression, or all
watch clear                      Remove all watches
```

Examples:
```
watch v0.isPremium
watch v3.getState()
unwatch 0
watch clear
```

---

## 19. Hooks (client-side intercept rules)

```
hook <cls> <method> <action>     Add hook rule applied on every hit
                                 action: log-continue | force-return-void | force-return-0 | force-return-1
hook list / hooks                List active hooks
hook clear <cls> <method>        Remove specific hook
hook clear *                     Remove all hooks
```

---

## 20. Exception mutes

```
excp-mute <pat>                  Suppress caught exceptions whose class name contains pattern
excp-unmute <pat>                Remove a mute rule
excp-mutes                       List active mute rules with suppression counts
```

Matching is case-insensitive substring on the short class name. Uncaught exceptions always bypass mutes.

Examples:
```
excp-mute ErrnoException
excp-mute ClassNotFoundException
excp-mute NoSuchMethodException
excp-unmute ErrnoException
excp-mutes
```

---

## 21. Settings & log

```
lc / log-clear                   Clear log window
save [file]                      Save log to file (default: dexbgd_<ts>.log)
ss / save settings               Save settings (theme, layout, history)
```

---

## Keyboard shortcuts (TUI)

| Key | Action |
|---|---|
| F1 | Connect |
| F2 | Toggle breakpoint at cursor |
| F5 | Continue |
| F7 | Step into |
| F8 | Step over |
| F9 | Step out |
| Shift-F10 | Toggle recording |
| Ctrl+B | Toggle bookmark at cursor |
| Ctrl+S | Save session |
| Ctrl+L | Load session |
| Ctrl+T | Cycle theme |
| F12 | Toggle mouse mode |
| Tab | Cycle panels |
| Esc | Back / close |
| y / n | Approve / deny AI tool call |
