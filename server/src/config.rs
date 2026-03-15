use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct AiConfig {
    pub backend: String,       // "claude" or "ollama"
    pub claude_model: String,
    pub ollama_model: String,
    pub ollama_url: String,    // runtime only, not persisted
    pub max_turns: usize,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            backend: "claude".into(),
            claude_model: "claude-sonnet-4-6".into(),
            ollama_model: "qwen2.5:7b".into(),
            ollama_url: "http://localhost:11434".into(),
            max_turns: 25,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub ai: AiConfig,
    /// Commands run automatically on TUI startup (manual-edit only, not saved by `ss`).
    pub startup_cmds: Vec<String>,
    pub auto_connect: bool,
    pub auto_connect_retry: bool,
    pub retry_interval_s: u64,
    pub theme_index: usize,
    pub split_h: f32,
    pub split_v: f32,
    pub split_right_v: f32,
    /// Last up to 15 saved commands (seeded into command_history on startup).
    pub history: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ai: AiConfig::default(),
            startup_cmds: Vec::new(),
            auto_connect: false,
            auto_connect_retry: false,
            retry_interval_s: 3,
            theme_index: 0,
            split_h: 0.6,
            split_v: 0.65,
            split_right_v: 0.5,
            history: Vec::new(),
        }
    }
}

/// Path to dexbgd.ini next to the running executable.
pub fn ini_path() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("dexbgd.ini")))
}

/// Parse a minimal INI file into section -> (key -> value) map.
/// Supports `[section]`, `key=value`, and `#`/`;` line comments.
fn parse_ini(
    content: &str,
) -> std::collections::HashMap<String, std::collections::HashMap<String, String>> {
    let mut map: std::collections::HashMap<
        String,
        std::collections::HashMap<String, String>,
    > = Default::default();
    let mut section = String::new();
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim().to_lowercase();
            map.entry(section.clone()).or_default();
        } else if let Some(eq) = line.find('=') {
            let key = line[..eq].trim().to_lowercase();
            let val = line[eq + 1..].trim().to_string();
            map.entry(section.clone()).or_default().insert(key, val);
        }
    }
    map
}

impl Config {
    /// Load config from `dexbgd.ini` next to the exe.
    /// Returns defaults if the file is absent or unparseable.
    pub fn load() -> Self {
        let path = match ini_path() {
            Some(p) => p,
            None => return Self::default(),
        };
        let content = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(_) => return Self::default(),
        };
        Self::from_ini(&parse_ini(&content))
    }

    fn from_ini(
        ini: &std::collections::HashMap<
            String,
            std::collections::HashMap<String, String>,
        >,
    ) -> Self {
        let mut cfg = Self::default();
        let empty = std::collections::HashMap::new();

        // [startup]
        let startup = ini.get("startup").unwrap_or(&empty);
        if let Some(v) = startup.get("auto_connect") {
            cfg.auto_connect = v == "true" || v == "1";
        }
        if let Some(v) = startup.get("auto_connect_retry") {
            cfg.auto_connect_retry = v == "true" || v == "1";
        }
        if let Some(v) = startup.get("retry_interval_s") {
            if let Ok(n) = v.parse::<u64>() {
                cfg.retry_interval_s = n.max(1);
            }
        }
        // numbered startup cmds: cmd0, cmd1, ...
        let mut i = 0usize;
        loop {
            match startup.get(&format!("cmd{}", i)) {
                Some(v) if !v.is_empty() => {
                    cfg.startup_cmds.push(v.clone());
                    i += 1;
                }
                _ => break,
            }
        }

        // [layout]
        let layout = ini.get("layout").unwrap_or(&empty);
        if let Some(v) = layout.get("theme") {
            if let Ok(n) = v.parse::<usize>() {
                cfg.theme_index = n;
            }
        }
        if let Some(v) = layout.get("split_h") {
            if let Ok(f) = v.parse::<f32>() {
                cfg.split_h = f.clamp(0.15, 0.85);
            }
        }
        if let Some(v) = layout.get("split_v") {
            if let Ok(f) = v.parse::<f32>() {
                cfg.split_v = f.clamp(0.15, 0.85);
            }
        }
        if let Some(v) = layout.get("split_right_v") {
            if let Ok(f) = v.parse::<f32>() {
                cfg.split_right_v = f.clamp(0.15, 0.85);
            }
        }

        // [history]
        let hist = ini.get("history").unwrap_or(&empty);
        let mut i = 0usize;
        loop {
            match hist.get(&format!("cmd{}", i)) {
                Some(v) if !v.is_empty() => {
                    cfg.history.push(v.clone());
                    i += 1;
                    if i >= 6 {
                        break;
                    }
                }
                _ => break,
            }
        }

        // [ai]
        let ai = ini.get("ai").unwrap_or(&empty);
        if let Some(v) = ai.get("backend") {
            cfg.ai.backend = v.clone();
        }
        if let Some(v) = ai.get("claude_model") {
            cfg.ai.claude_model = v.clone();
        }
        if let Some(v) = ai.get("ollama_model") {
            cfg.ai.ollama_model = v.clone();
        }
        if let Some(v) = ai.get("max_turns") {
            if let Ok(n) = v.parse::<usize>() {
                cfg.ai.max_turns = n.max(1);
            }
        }

        cfg
    }

    /// Write settings to `dexbgd.ini` next to the exe.
    ///
    /// Runtime layout state (`theme_index`, `split_*`, `history`) is passed in
    /// from the App. The `[startup]` and `[ai]` sections are round-tripped from
    /// whatever was loaded (manual-edit only — `ss` does not modify them).
    ///
    /// Returns the path written on success.
    pub fn write_ini(
        &self,
        theme_index: usize,
        split_h: f32,
        split_v: f32,
        split_right_v: f32,
        history: &[String],
    ) -> std::io::Result<PathBuf> {
        let path = ini_path().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "cannot determine exe path")
        })?;

        let mut out = String::new();

        out.push_str("[startup]\n");
        out.push_str(&format!("auto_connect={}\n", self.auto_connect));
        out.push_str(&format!("auto_connect_retry={}\n", self.auto_connect_retry));
        out.push_str(&format!("retry_interval_s={}\n", self.retry_interval_s));
        for (i, cmd) in self.startup_cmds.iter().enumerate() {
            out.push_str(&format!("cmd{}={}\n", i, cmd));
        }

        out.push_str("\n[layout]\n");
        out.push_str(&format!("theme={}\n", theme_index));
        out.push_str(&format!("split_h={:.3}\n", split_h));
        out.push_str(&format!("split_v={:.3}\n", split_v));
        out.push_str(&format!("split_right_v={:.3}\n", split_right_v));

        out.push_str("\n[history]\n");
        // Take last 15, most-recent last; skip `ss` / `save settings` itself.
        let saved: Vec<&str> = history
            .iter()
            .rev()
            .filter(|s| !matches!(s.as_str(), "ss" | "save settings"))
            .take(15)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .map(|s| s.as_str())
            .collect();
        for (i, cmd) in saved.iter().enumerate() {
            out.push_str(&format!("cmd{}={}\n", i, cmd));
        }

        out.push_str("\n[ai]\n");
        out.push_str(&format!("backend={}\n", self.ai.backend));
        out.push_str(&format!("claude_model={}\n", self.ai.claude_model));
        out.push_str(&format!("ollama_model={}\n", self.ai.ollama_model));
        out.push_str(&format!("max_turns={}\n", self.ai.max_turns));

        std::fs::write(&path, out)?;
        Ok(path)
    }
}
