use std::collections::HashMap;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookRule {
    pub class: String,
    pub method: String,
    /// "log-continue", "force-return-void", "force-return-0", "force-return-1"
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionBookmark {
    pub class: String,
    pub method: String,
    pub offset: i64,
    pub label: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Session {
    #[serde(default)]
    pub aliases: HashMap<String, String>,
    /// Key: "class method bci"  e.g. "Lcom/a/B; check 18"
    #[serde(default)]
    pub comments: HashMap<String, String>,
    #[serde(default)]
    pub hooks: Vec<HookRule>,
    #[serde(default)]
    pub bookmarks: Vec<SessionBookmark>,
    /// Commands to run automatically on session load (e.g. "anti sg.vantagepoint.a.c a false")
    #[serde(default)]
    pub startup_commands: Vec<String>,
}

pub fn session_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("sessions")))
}

fn safe_filename(package: &str) -> String {
    package
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '.' || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

pub fn session_path(package: &str) -> Option<PathBuf> {
    session_dir().map(|d| d.join(format!("{}.json", safe_filename(package))))
}

impl Session {
    /// Returns Ok(None) if no session file exists, Ok(Some) on success, Err on parse failure.
    pub fn load(package: &str) -> Result<Option<Self>, String> {
        let path = match session_path(package) {
            Some(p) => p,
            None => return Ok(None),
        };
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => return Ok(None), // file doesn't exist
        };
        serde_json::from_str(&content)
            .map(Some)
            .map_err(|e| format!("Session JSON parse error in {}: {}", path.display(), e))
    }

    pub fn save(&self, package: &str) -> std::io::Result<PathBuf> {
        let dir = session_dir().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "cannot determine exe path")
        })?;
        std::fs::create_dir_all(&dir)?;
        let path = session_path(package).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "cannot determine session path")
        })?;
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(&path, content)?;
        Ok(path)
    }
}

pub const VALID_ACTIONS: &[&str] = &[
    "log-continue",
    "force-return-void",
    "force-return-0",
    "force-return-1",
];
