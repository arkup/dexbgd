use ratatui::style::Color;

/// Grouped color theme for the entire TUI.
///
/// ~15 slots covering bytecode syntax + UI chrome.
/// Ctrl+T cycles through built-in themes at runtime.
#[derive(Debug, Clone)]
pub struct Theme {
    pub name: &'static str,

    // ── Bytecode syntax (8 slots) ──────────────────────────────────────
    /// Opcodes: invoke-*, const, move, new-instance, etc.
    pub bc_opcode: Color,
    /// Flow control: goto, if-*, return, throw
    pub bc_flow: Color,
    /// Registers: v0, v1, p0, {v0, v1}
    pub bc_register: Color,
    /// String literals: "hello"
    pub bc_string: Color,
    /// Numeric constants: #42, #0xff, +3, -1
    pub bc_number: Color,
    /// Resolved references: Class.method, Class.field (contains a dot)
    pub bc_reference: Color,
    /// Branch targets: hex offsets like 00a5, 00c1
    pub bc_branch: Color,
    /// Unresolved references: string@0042, method@001a
    pub bc_unresolved: Color,

    // ── UI chrome (8 slots) ────────────────────────────────────────────
    /// Accent color: focused borders, active tabs, prompts, key elements
    pub ui_accent: Color,
    /// Primary text: instruction text, variable names, main content
    pub ui_text: Color,
    /// Secondary/dim text: offsets, placeholders, separators, unfocused borders
    pub ui_dim: Color,
    /// Values: variable values, register values, line numbers
    pub ui_value: Color,
    /// Cursor-selected line background
    pub ui_cursor_bg: Color,
    /// Current execution line background (PC exactly at line's primary offset)
    pub ui_current_bg: Color,
    /// Step-inside background: PC is within a line but past its primary offset
    pub ui_step_bg: Color,
    /// Word-highlight background (click-to-highlight)
    pub ui_highlight_bg: Color,
    /// Breakpoint marker color
    pub ui_breakpoint: Color,
    /// Main background (used to fill the frame; avoids inheriting terminal system color)
    pub ui_bg: Color,
    /// Background for the branch-target line when a taken branch points to it
    pub ui_branch_target_bg: Color,
}

/// All built-in themes. Index into this with `theme_index`.
pub fn builtin_themes() -> Vec<Theme> {
    vec![
        dark(),
        solarized(),
        one_light(),
    ]
}

/// Default dark theme (matches original hardcoded colors).
pub fn dark() -> Theme {
    Theme {
        name: "Dark",
        // Bytecode syntax
        bc_opcode: Color::Cyan,
        bc_flow: Color::Rgb(200, 140, 60),       // orange
        bc_register: Color::White,
        bc_string: Color::Green,
        bc_number: Color::Magenta,
        bc_reference: Color::Yellow,
        bc_branch: Color::Rgb(100, 130, 200),
        bc_unresolved: Color::Rgb(120, 80, 80),
        // UI chrome
        ui_accent: Color::Cyan,
        ui_text: Color::White,
        ui_dim: Color::DarkGray,
        ui_value: Color::Yellow,
        ui_cursor_bg: Color::Rgb(50, 50, 70),
        ui_current_bg: Color::Rgb(40, 40, 60),
        ui_step_bg: Color::Rgb(20, 20, 40),
        ui_highlight_bg: Color::Rgb(80, 70, 20),
        ui_breakpoint: Color::Red,
        ui_bg: Color::Black,
        ui_branch_target_bg: Color::Rgb(20, 50, 20),
    }
}

/// Solarized Dark theme.
pub fn solarized() -> Theme {
    Theme {
        name: "Solarized",
        // Bytecode syntax
        bc_opcode: Color::Rgb(38, 139, 210),    // blue
        bc_flow: Color::Rgb(203, 75, 22),        // orange
        bc_register: Color::Rgb(147, 161, 161), // base1
        bc_string: Color::Rgb(42, 161, 152),    // cyan
        bc_number: Color::Rgb(211, 54, 130),    // magenta
        bc_reference: Color::Rgb(181, 137, 0),  // yellow
        bc_branch: Color::Rgb(108, 113, 196),   // violet
        bc_unresolved: Color::Rgb(88, 110, 117),// base01
        // UI chrome
        ui_accent: Color::Rgb(38, 139, 210),    // blue
        ui_text: Color::Rgb(131, 148, 150),      // base0
        ui_dim: Color::Rgb(88, 110, 117),        // base01
        ui_value: Color::Rgb(181, 137, 0),       // yellow
        ui_cursor_bg: Color::Rgb(7, 54, 66),     // base02
        ui_current_bg: Color::Rgb(0, 80, 102),   // brighter teal, visible against base03
        ui_step_bg: Color::Rgb(0, 60, 78),       // halfway between ui_bg and ui_current_bg
        ui_highlight_bg: Color::Rgb(40, 60, 50),
        ui_breakpoint: Color::Rgb(220, 50, 47),  // red
        ui_bg: Color::Rgb(0, 43, 54),             // base03 #002b36
        ui_branch_target_bg: Color::Rgb(20, 52, 40),
    }
}

/// Atom One Light theme.
pub fn one_light() -> Theme {
    Theme {
        name: "One Light",
        // Bytecode syntax
        bc_opcode:     Color::Rgb(0, 132, 187),   // hue-1  cyan  #0084BB
        bc_flow:       Color::Rgb(193, 132, 1),   // hue-6-2 orange #C18401
        bc_register:   Color::Rgb(56, 58, 66),    // mono-1  #383A42
        bc_string:     Color::Rgb(80, 161, 79),   // hue-4  green  #50A14F
        bc_number:     Color::Rgb(166, 38, 164),  // hue-3  purple #A626A4
        bc_reference:  Color::Rgb(64, 120, 242),  // hue-2  blue   #4078F2
        bc_branch:     Color::Rgb(193, 132, 1),   // orange, same as flow
        bc_unresolved: Color::Rgb(160, 161, 167), // mono-3  #A0A1A7
        // UI chrome
        ui_accent:      Color::Rgb(64, 120, 242), // hue-2  blue
        ui_text:        Color::Rgb(56, 58, 66),   // mono-1 dark gray
        ui_dim:         Color::Rgb(160, 161, 167),// mono-3 medium gray
        ui_value:       Color::Rgb(152, 104, 1),  // hue-6  orange-brown #986801
        ui_cursor_bg:   Color::Rgb(208, 208, 213),// subtle selection
        ui_current_bg:  Color::Rgb(222, 222, 225),// slightly off-white
        ui_step_bg:     Color::Rgb(215, 215, 220),// between ui_bg and ui_current_bg
        ui_highlight_bg:Color::Rgb(245, 233, 158),// soft yellow highlight
        ui_breakpoint:  Color::Rgb(228, 86, 73),  // hue-5  red    #E45649
        ui_bg:          Color::Rgb(238, 238, 236),// warm off-white, easier on eyes
        ui_branch_target_bg: Color::Rgb(210, 238, 210),// pastel green, fits light bg
    }
}
