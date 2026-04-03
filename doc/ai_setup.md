# AI-Assisted Analysis (Experimental)

> **This feature is experimental.** The AI can run debugger commands autonomously and has access to the full debugger toolset. Results vary by model and task complexity. Always review what the AI did before acting on its findings.

The AI gets access to all debugger tools — it can set breakpoints, step through code, inspect locals, search strings, query the heap, and compile a report. You give it a goal; it drives the debugger.

## Commands

```
ai <prompt>         Full autonomy — AI runs without asking for approval
ai ask <prompt>     Confirmation mode — AI asks before running each tool call
ai explain <prompt> Read-only mode — AI can inspect but not change execution state
ai cancel           Cancel a running AI session
```

In `ai ask` mode, each tool call the AI wants to make is shown on screen. Press `y` to approve or `n` to deny.

## Backends

Two backends are supported: **Claude** (Anthropic API) and **Ollama** (local models).

### Claude (default)

1. Get an API key from [console.anthropic.com](https://console.anthropic.com)
2. Set the environment variable before starting the server:

   **Linux / macOS:**
   ```bash
   export ANTHROPIC_API_KEY=sk-ant-...
   cd server && cargo run
   ```

   **Windows (cmd):**
   ```cmd
   set ANTHROPIC_API_KEY=sk-ant-...
   cd server && cargo run
   ```

   **Windows (PowerShell):**
   ```powershell
   $env:ANTHROPIC_API_KEY = "sk-ant-..."
   cd server; cargo run
   ```

The key is read at startup. If it is not set, `ai` commands will fail with an error message.

### Ollama (local)

1. Install [Ollama](https://ollama.com) and pull a model:
   ```bash
   ollama pull qwen2.5:7b
   ```
   `qwen2.5:7b` is the recommended model — it handles tool use well and runs on consumer hardware. Larger models generally work better.

2. Switch the backend in `dexbgd.ini` (next to the server binary):
   ```ini
   [ai]
   backend=ollama
   ollama_model=qwen2.5:7b
   ```

Ollama is expected at `http://localhost:11434`. Start it before running the server.

## Configuration (`dexbgd.ini`)

The `[ai]` section is loaded on startup. Edit the file manually — it is not overwritten by `ss` (save settings).

```ini
[ai]
backend=claude            # "claude" or "ollama"
claude_model=claude-sonnet-4-6
ollama_model=qwen2.5:7b
max_turns=25              # maximum tool-use rounds per session
turn_delay_ms=0           # milliseconds to wait between turns (0 = no delay)
```

`max_turns` limits runaway sessions. The default of 25 is enough for most tasks.

`turn_delay_ms` adds a pause between turns. Useful if you hit Claude's rate limit (`429 Too Many Requests`). Set to `2000`–`5000` if you see rate limit errors.

## Example sessions

```
> ai Find all crypto keys used by this app and trace where the ciphertext goes

> ai ask Bypass root detection and get past the license check

> ai explain What is this method doing? (cursor on a deobfuscated method)
```

## Tips

- Start with `ai explain` or `ai ask` while getting familiar — full autonomy can set many breakpoints quickly
- The AI works best when a target class or method is already visible — navigate there first
- If a session stalls or goes in circles, cancel with `ai cancel` and rephrase the prompt
- Ollama quality varies a lot by model size; if results are poor, try a larger model
