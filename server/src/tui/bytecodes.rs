use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::ai::{AiLineKind, AiState};
use crate::app::{App, CallCategory, JniNativeEntry, LeftTab};
use crate::commands;
use crate::disassembler;
use crate::theme::Theme;
use super::make_block;

/// Returns true if this Dalvik instruction is "noise" that the Decompiler tab filters out.
pub fn is_decompiler_noise(text: &str) -> bool {
    let first_word = text.split_whitespace().next().unwrap_or("");
    matches!(first_word,
        "nop" | "move" | "move/from16" | "move/16"
        | "move-wide" | "move-wide/from16" | "move-wide/16"
        | "move-object" | "move-object/from16" | "move-object/16"
        | "move-result" | "move-result-wide" | "move-result-object"
        | "move-exception"
    )
}

/// Apply class aliases to an instruction text string.
/// Replaces "ShortName." with "Alias." for every known alias.
/// Only substitutes when followed by '.' to avoid false positives.
fn apply_aliases<'a>(text: &'a str, aliases: &std::collections::HashMap<String, String>) -> std::borrow::Cow<'a, str> {
    if aliases.is_empty() {
        return std::borrow::Cow::Borrowed(text);
    }
    let mut result = std::borrow::Cow::Borrowed(text);
    for (sig, label) in aliases {
        let short = commands::short_class(sig);
        let needle = format!("{}.", short);
        let replace = format!("{}.", label);
        if result.contains(needle.as_str()) {
            result = std::borrow::Cow::Owned(result.replace(needle.as_str(), replace.as_str()));
        }
    }
    result
}

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let focused = app.focus == 0;
    let t = &app.theme;

    let tabs = ["Bytecodes", "Decompiler", "Trace", " AI ", "JNI"];
    let active_idx = match app.left_tab {
        LeftTab::Bytecodes => 0,
        LeftTab::Decompiler => 1,
        LeftTab::Trace => 2,
        LeftTab::Ai => 3,
        LeftTab::JniMonitor => 4,
    };

    let mut spans = vec![Span::raw(" ")];
    for (i, name) in tabs.iter().enumerate() {
        if i == active_idx {
            spans.push(Span::styled(
                format!(" {} ", name),
                Style::default()
                    .fg(t.ui_text)
                    .bg(t.ui_cursor_bg)
                    .add_modifier(Modifier::BOLD),
            ));
        } else {
            spans.push(Span::styled(
                format!(" {} ", name),
                Style::default().fg(t.ui_dim),
            ));
        }
    }
    spans.push(Span::raw(" "));

    let block = make_block(Line::from(spans), focused, t);

    match app.left_tab {
        LeftTab::Bytecodes => {
            draw_bytecodes(f, app, area, block);
        }
        LeftTab::Decompiler => {
            draw_decompiler(f, app, area, block);
        }
        LeftTab::Trace => {
            draw_trace(f, app, area, block);
        }
        LeftTab::Ai => {
            draw_ai(f, app, area, block);
        }
        LeftTab::JniMonitor => {
            draw_jni_monitor(f, app, area, block);
        }
    }
}

/// Split a span string into up to 3 sub-spans: before selection, inside, after.
/// `span_col`  – display column where this span starts.
/// `sel_start` / `sel_end` – absolute selection columns; `sel_end == usize::MAX` means
///              the selection runs to the end of the span.
fn split_at_sel(
    s: &str,
    span_col: usize,
    sel_start: usize,
    sel_end: usize,
    normal: Style,
    selected: Style,
) -> Vec<Span<'static>> {
    let chars: Vec<char> = s.chars().collect();
    let span_len = chars.len();
    if sel_end != usize::MAX && sel_end <= span_col || sel_start >= span_col + span_len {
        if span_len == 0 { return vec![]; }
        return vec![Span::styled(chars.iter().collect::<String>(), normal)];
    }
    let rel_start = sel_start.saturating_sub(span_col).min(span_len);
    let rel_end   = if sel_end == usize::MAX { span_len } else { sel_end.saturating_sub(span_col).min(span_len) };
    let mut spans = Vec::new();
    if rel_start > 0 {
        spans.push(Span::styled(chars[..rel_start].iter().collect::<String>(), normal));
    }
    if rel_start < rel_end {
        spans.push(Span::styled(chars[rel_start..rel_end].iter().collect::<String>(), selected));
    }
    if rel_end < span_len {
        spans.push(Span::styled(chars[rel_end..].iter().collect::<String>(), normal));
    }
    spans
}

/// Apply a selection column range to a list of spans, splitting where needed.
/// Always returns owned ('static) spans so the result can be freely stored/moved.
fn apply_sel_to_spans<'a>(
    spans: Vec<Span<'a>>,
    sel_start: usize,
    sel_end: usize,
    sel_bg: Color,
) -> Vec<Span<'static>> {
    let mut result = Vec::with_capacity(spans.len() * 2);
    let mut col = 0usize;
    for span in spans {
        let content_len = span.content.chars().count();
        let selected_style = span.style.bg(sel_bg);
        result.extend(split_at_sel(&span.content, col, sel_start, sel_end, span.style, selected_style));
        col += content_len;
    }
    result
}

fn draw_bytecodes(f: &mut Frame, app: &App, area: Rect, block: ratatui::widgets::Block<'_>) {
    let inner_height = area.height.saturating_sub(2) as usize;
    let t = &app.theme;

    if app.bytecodes.is_empty() {
        let msg = if app.current_loc == Some(-1) {
            let cls = app.current_class.as_deref().map(crate::commands::short_class).unwrap_or("?");
            let meth = app.current_method.as_deref().unwrap_or("?");
            format!("(native method: {}.{})", cls, meth)
        } else {
            "(no bytecodes)".to_string()
        };
        let text = Paragraph::new(msg)
            .block(block)
            .style(Style::default().fg(t.ui_dim));
        f.render_widget(text, area);
        return;
    }

    // Build header line: "Class.method @offset"
    let header = build_header(app);
    let code_height = inner_height.saturating_sub(1); // 1 line for header

    // Find current instruction index
    let current_idx = app.current_loc.and_then(|loc| {
        app.bytecodes.iter().position(|i| i.offset == loc as u32)
    });

    // Scroll: show 2 instructions before PC when auto_scroll is true (after suspend/new method),
    // otherwise respect manual scroll position (user scrolled with mouse/keyboard).
    let scroll = if app.bytecodes_auto_scroll {
        if let Some(idx) = current_idx {
            idx.saturating_sub(2)
        } else {
            app.bytecodes_scroll
        }
    } else {
        app.bytecodes_scroll
    };

    // Normalize bytecodes selection to (r0,c0,r1,c1): r0<=r1; usize::MAX end = whole row.
    let sel_full: Option<(usize, usize, usize, usize)> = match (app.bytecodes_sel_anchor, app.bytecodes_sel_head) {
        (Some(a), Some(h)) if a != h => {
            if a.0 < h.0 || (a.0 == h.0 && a.1 <= h.1) {
                Some((a.0, a.1, h.0, h.1))
            } else {
                Some((h.0, h.1, a.0, a.1))
            }
        }
        _ => None,
    };
    let sel_bg = t.ui_highlight_bg;

    let mut lines: Vec<Line> = Vec::with_capacity(inner_height);
    lines.push(header);

    // Evaluate branch at current instruction (if any)
    // Use raw register values (from "regs" command) which covers ALL slots,
    // not just named source variables from the debug info table.
    let branch_eval = current_idx.and_then(|idx| {
        let instr = &app.bytecodes[idx];
        instr.branch.as_ref().and_then(|meta| {
            let taken = disassembler::eval_branch(meta, &|reg| {
                app.regs.iter().find(|r| r.slot == reg as i32).map(|r| r.value)
            });
            taken.map(|t| (t, meta.target))
        })
    });

    // Branch target offset (to highlight the target line green when taken)
    let taken_target: Option<u32> = branch_eval.and_then(|(taken, target)| {
        if taken { Some(target) } else { None }
    });

    // Viewport-wide branch pair colors: assign up to 5 distinct colors to unique branch targets
    // visible in the current scroll window. Both the source (branch instruction) and destination
    // lines get a matching colored dot in the gutter plus colored address tokens.
    const BRANCH_PAIR_COLORS: [Color; 5] = [
        Color::Rgb(80, 200, 190),   // teal
        Color::Rgb(230, 150, 50),   // amber
        Color::Rgb(170, 90, 210),   // purple
        Color::Rgb(210, 90, 130),   // pink
        Color::Rgb(130, 195, 70),   // lime
    ];
    // Collect offsets visible in the viewport so we can require both ends to be on-screen.
    let viewport_offsets: std::collections::HashSet<u32> = app.bytecodes.iter()
        .skip(scroll).take(code_height)
        .map(|i| i.offset)
        .collect();
    let mut branch_target_colors: std::collections::HashMap<u32, usize> = std::collections::HashMap::new();
    for instr in app.bytecodes.iter().skip(scroll).take(code_height) {
        if let Some(ref meta) = instr.branch {
            // Only color the pair when the destination is also visible in the current view.
            if viewport_offsets.contains(&meta.target)
                && !branch_target_colors.contains_key(&meta.target)
                && branch_target_colors.len() < 5
            {
                let len = branch_target_colors.len();
                branch_target_colors.insert(meta.target, len);
            }
        }
    }

    for (idx, instr) in app.bytecodes.iter().enumerate().skip(scroll).take(code_height) {
        let is_current = current_idx == Some(idx);
        let is_cursor = app.bytecodes_cursor == Some(idx);
        let is_branch_target = taken_target.map_or(false, |tgt| instr.offset == tgt);

        // Selection column range for this line (None = row not selected)
        let sel_cols: Option<(usize, usize)> = sel_full.and_then(|(r0, c0, r1, c1)| {
            if idx < r0 || idx > r1 { return None; }
            let start = if idx == r0 { c0 } else { 0 };
            let end   = if idx == r1 { c1 } else { usize::MAX };
            Some((start, end))
        });

        // Look up user comment for this instruction
        let comment = app.current_class.as_ref().zip(app.current_method.as_ref())
            .and_then(|(cls, meth)| app.comments.get(&(cls.clone(), meth.clone(), instr.offset)));

        // Check if a breakpoint is set at this instruction
        let has_bp = if let (Some(cls), Some(meth)) = (&app.current_class, &app.current_method) {
            app.bp_manager.breakpoints.iter().any(|bp| {
                bp.class == *cls && bp.method == *meth && bp.location == instr.offset as i64
            })
        } else {
            false
        };

        // Gutter: breakpoint dot, execution marker, or space
        let gutter = if has_bp && is_current {
            "\u{25cf}\u{25ba}"   // ●►
        } else if has_bp {
            "\u{25cf} "          // ●
        } else if is_current {
            " \u{25ba}"          // ►
        } else {
            "  "
        };

        let offset_str = format!("{:04x}: ", instr.offset);

        // Background for current line / cursor / branch target
        let line_bg = if is_current {
            t.ui_current_bg
        } else if is_cursor {
            t.ui_cursor_bg
        } else if is_branch_target {
            t.ui_branch_target_bg
        } else {
            t.ui_bg
        };

        // Branch pair colors for this instruction:
        //   dest_pair_color - this instruction's offset IS a tracked branch target
        //   src_pair_color  - this instruction IS a branch pointing to a tracked target
        let dest_pair_color: Option<Color> = branch_target_colors.get(&instr.offset)
            .map(|&idx| BRANCH_PAIR_COLORS[idx]);
        let src_pair_color: Option<Color> = instr.branch.as_ref()
            .and_then(|m| branch_target_colors.get(&m.target))
            .map(|&idx| BRANCH_PAIR_COLORS[idx]);

        // Gutter style: red for breakpoint dot, otherwise matches marker
        let bp_gutter_style = if has_bp {
            Style::default().fg(t.ui_breakpoint).bg(line_bg).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(t.ui_dim).bg(line_bg)
        };

        // Softer red for "branch not taken" — less harsh than terminal Color::Red
        const NOT_TAKEN_RED: Color = Color::Rgb(190, 70, 70);

        // Determine colors based on branch evaluation
        let (_marker_style, offset_style, text_style) = if is_current {
            if let Some((taken, _)) = branch_eval {
                if instr.branch.is_some() {
                    // Current instruction IS a branch  - color by taken/not-taken (semantic)
                    let fg = if taken { Color::Green } else { NOT_TAKEN_RED };
                    (
                        Style::default().fg(fg).bg(line_bg).add_modifier(Modifier::BOLD),
                        Style::default().fg(fg).bg(line_bg),
                        Style::default().fg(fg).bg(line_bg).add_modifier(Modifier::BOLD),
                    )
                } else {
                    // Current instruction, not a branch
                    (
                        Style::default().fg(t.ui_value).bg(line_bg).add_modifier(Modifier::BOLD),
                        Style::default().fg(t.ui_dim).bg(line_bg),
                        Style::default().fg(t.ui_text).bg(line_bg).add_modifier(Modifier::BOLD),
                    )
                }
            } else {
                // Current instruction, no branch eval
                (
                    Style::default().fg(t.ui_value).bg(line_bg).add_modifier(Modifier::BOLD),
                    Style::default().fg(t.ui_dim).bg(line_bg),
                    Style::default().fg(t.ui_text).bg(line_bg).add_modifier(Modifier::BOLD),
                )
            }
        } else if is_branch_target {
            // Target of a taken branch  - green highlight (semantic)
            (
                Style::default().fg(Color::Green).bg(line_bg),
                Style::default().fg(Color::Green).bg(line_bg),
                Style::default().fg(Color::Green).bg(line_bg).add_modifier(Modifier::BOLD),
            )
        } else if is_cursor {
            // Cursor-selected line (distinct from execution point)
            (
                Style::default().fg(t.ui_accent).bg(line_bg),
                Style::default().fg(t.ui_dim).bg(line_bg),
                Style::default().fg(t.ui_text).bg(line_bg),
            )
        } else {
            // Normal line
            (
                Style::default().fg(t.ui_dim),
                Style::default().fg(t.ui_dim),
                Style::default().fg(Color::Gray),
            )
        };

        // Override offset color for destination lines (this instruction IS a branch target).
        // Applied after the semantic color block so pair color appears on non-special lines.
        let offset_style = if let Some(c) = dest_pair_color {
            Style::default().fg(c).bg(line_bg).add_modifier(Modifier::BOLD)
        } else {
            offset_style
        };

        // For branch instructions on the current line, split text to highlight target offset
        if is_current && instr.branch.is_some() {
            if let Some((taken, target)) = branch_eval {
                let target_str = format!("{:04x}", target);
                if let Some(pos) = instr.text.rfind(&target_str) {
                    // Split: text before target, target itself, text after
                    let before = &instr.text[..pos];
                    let target_part = &instr.text[pos..pos + target_str.len()];
                    let after = &instr.text[pos + target_str.len()..];

                    let target_fg = if taken { Color::Green } else { NOT_TAKEN_RED };
                    let arrow = if target < instr.offset { " \u{2191}" } else { " \u{2193}" }; // up or down
                    let arrow_fg = if taken { Color::Green } else { NOT_TAKEN_RED };

                    let pair_dot = match src_pair_color.or(dest_pair_color) {
                        Some(c) => Span::styled("\u{25cf}", Style::default().fg(c).bg(line_bg)),
                        None    => Span::styled(" ", Style::default().bg(line_bg)),
                    };
                    let mut branch_spans = vec![
                        pair_dot,
                        Span::styled(gutter.to_string(), bp_gutter_style),
                        Span::styled(offset_str, offset_style),
                        Span::styled(before, text_style),
                        Span::styled(target_part, Style::default().fg(target_fg).bg(line_bg).add_modifier(Modifier::BOLD)),
                        Span::styled(after, text_style),
                        Span::styled(arrow, Style::default().fg(arrow_fg).bg(line_bg).add_modifier(Modifier::BOLD)),
                    ];
                    if let Some(ref hw) = app.bytecodes_highlight {
                        apply_highlight(&mut branch_spans, hw, t.ui_highlight_bg);
                    }
                    if let Some(cmt) = comment {
                        branch_spans.push(Span::styled(
                            format!("  ; {}", cmt),
                            Style::default().fg(t.ui_dim).bg(line_bg),
                        ));
                    }
                    if let Some((ss, se)) = sel_cols {
                        lines.push(Line::from(apply_sel_to_spans(branch_spans, ss, se, sel_bg)));
                    } else {
                        lines.push(Line::from(branch_spans));
                    }
                    continue;
                }
            }
        }

        // Use syntax coloring for instruction text
        let use_bold = is_current || is_branch_target;
        let pair_dot = match src_pair_color.or(dest_pair_color) {
            Some(c) => Span::styled("\u{25cf}", Style::default().fg(c).bg(line_bg)),
            None    => Span::styled(" ", Style::default().bg(line_bg)),
        };
        let mut line_spans = vec![
            pair_dot,
            Span::styled(gutter.to_string(), bp_gutter_style),
            Span::styled(offset_str.to_string(), offset_style),
        ];

        // Underline followable invoke-* instructions (app classes only, not framework)
        let followable = instr.method_idx.map_or(false, |mid| {
            // Check if the target class is defined in any loaded DEX
            app.dex_data.iter().any(|dex| {
                dex.methods.get(mid as usize)
                    .map_or(false, |mref| dex.has_class(&mref.class_name))
            })
        });
        let display_text = apply_aliases(&instr.text, &app.aliases);
        let mut colored = colorize_insn(&display_text, line_bg, use_bold, t);
        if followable && !is_current {
            for span in &mut colored {
                span.style = span.style.add_modifier(Modifier::UNDERLINED);
            }
        }
        // For non-current branch instructions: recolor the target token with the pair color
        // so the source and destination visually share the same color tag.
        if let Some(pair_c) = src_pair_color {
            if !is_current {
                if let Some(ref meta) = instr.branch {
                    let target_str = format!("{:04x}", meta.target);
                    for span in &mut colored {
                        if span.content == target_str {
                            span.style = span.style.fg(pair_c).add_modifier(Modifier::BOLD);
                            break;
                        }
                    }
                }
            }
        }
        line_spans.extend(colored);

        // Apply word highlight (click-to-highlight all occurrences)
        if let Some(ref hw) = app.bytecodes_highlight {
            apply_highlight(&mut line_spans, hw, t.ui_highlight_bg);
        }

        // Append comment if present
        if let Some(cmt) = comment {
            line_spans.push(Span::styled(
                format!("  ; {}", cmt),
                Style::default().fg(t.ui_dim).bg(line_bg),
            ));
        }

        // Apply mouse selection highlight (overrides span backgrounds within selection range)
        let mut line_spans = if let Some((ss, se)) = sel_cols {
            apply_sel_to_spans(line_spans, ss, se, sel_bg)
        } else {
            line_spans
        };

        // Pad line to fill width for background
        let text_len: usize = line_spans.iter().map(|s| s.content.len()).sum();
        let inner_width = area.width.saturating_sub(2) as usize;
        if text_len < inner_width {
            line_spans.push(Span::styled(
                " ".repeat(inner_width - text_len),
                Style::default().bg(line_bg),
            ));
        }

        lines.push(Line::from(line_spans));
    }

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

fn build_header<'a>(app: &App) -> Line<'a> {
    let cls = app.current_class.as_deref().unwrap_or("?");
    let short = crate::commands::short_class(cls);
    let meth = app.current_method.as_deref().unwrap_or("?");
    let t = &app.theme;

    let mut spans = vec![
        Span::styled(
            format!(" {}.{}", short, meth),
            Style::default().fg(t.ui_accent).add_modifier(Modifier::BOLD),
        ),
    ];

    if let Some(loc) = app.current_loc {
        spans.push(Span::styled(
            format!(" @{:04x}", loc),
            Style::default().fg(t.ui_value),
        ));
    }

    if let Some(line) = app.current_line {
        if line >= 0 {
            spans.push(Span::styled(
                format!(" :{}", line),
                Style::default().fg(t.ui_dim),
            ));
        }
    }

    let total = app.bytecodes.len();
    spans.push(Span::styled(
        format!(" ({} insns)", total),
        Style::default().fg(t.ui_dim),
    ));

    Line::from(spans)
}

fn java_keyword_style(word: &str, t: &crate::theme::Theme) -> Style {
    match word {
        // Control flow
        "if" | "else" | "while" | "for" | "do" | "switch" | "case" | "default"
        | "break" | "continue" | "return" | "throw" | "throws" | "try" | "catch"
        | "finally" | "goto" => Style::default().fg(t.bc_flow),
        // Type / modifier keywords
        "int" | "long" | "short" | "byte" | "char" | "boolean" | "float" | "double"
        | "void" | "new" | "null" | "true" | "false" | "this" | "super"
        | "instanceof" | "public" | "private" | "protected" | "static" | "final"
        | "abstract" | "synchronized" | "volatile" | "transient" | "native"
        | "class" | "interface" | "enum" | "extends" | "implements"
        | "import" | "package" | "var" => Style::default().fg(t.bc_opcode),
        _ => {
            // Capitalized identifiers = type/class names
            if word.chars().next().map(|c| c.is_uppercase()).unwrap_or(false) {
                Style::default().fg(t.bc_reference)
            } else {
                Style::default().fg(t.ui_text)
            }
        }
    }
}

/// Tokenise a single pseudo-Java line into styled spans.
fn highlight_java_line(text: &str, t: &crate::theme::Theme) -> Vec<Span<'static>> {
    // Full-line comment
    if text.trim_start().starts_with("//") {
        return vec![Span::styled(text.to_string(), Style::default().fg(t.ui_dim))];
    }

    let mut spans: Vec<Span<'static>> = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        let c = chars[i];

        // Whitespace — preserve as raw (indentation shows through)
        if c == ' ' || c == '\t' {
            let start = i;
            while i < len && (chars[i] == ' ' || chars[i] == '\t') { i += 1; }
            let s: String = chars[start..i].iter().collect();
            spans.push(Span::raw(s));
            continue;
        }

        // String literal
        if c == '"' {
            let start = i;
            i += 1;
            while i < len {
                if chars[i] == '\\' { i += 2; continue; }
                if chars[i] == '"' { i += 1; break; }
                i += 1;
            }
            let s: String = chars[start..i].iter().collect();
            spans.push(Span::styled(s, Style::default().fg(t.bc_string)));
            continue;
        }

        // Char literal
        if c == '\'' {
            let start = i;
            i += 1;
            while i < len {
                if chars[i] == '\\' { i += 2; continue; }
                if chars[i] == '\'' { i += 1; break; }
                i += 1;
            }
            let s: String = chars[start..i].iter().collect();
            spans.push(Span::styled(s, Style::default().fg(t.bc_string)));
            continue;
        }

        // Inline comment
        if c == '/' && i + 1 < len && chars[i + 1] == '/' {
            let s: String = chars[i..].iter().collect();
            spans.push(Span::styled(s, Style::default().fg(t.ui_dim)));
            break;
        }

        // Identifier / keyword
        if c.is_alphabetic() || c == '_' {
            let start = i;
            while i < len && (chars[i].is_alphanumeric() || chars[i] == '_') { i += 1; }
            let word: String = chars[start..i].iter().collect();
            spans.push(Span::styled(word.clone(), java_keyword_style(&word, t)));
            continue;
        }

        // Number literal (decimal, hex 0x…, float)
        if c.is_ascii_digit() {
            let start = i;
            while i < len && (chars[i].is_alphanumeric() || chars[i] == '.' || chars[i] == '_') {
                i += 1;
            }
            let s: String = chars[start..i].iter().collect();
            spans.push(Span::styled(s, Style::default().fg(t.bc_number)));
            continue;
        }

        // Braces / brackets — accent colour
        if matches!(c, '{' | '}' | '(' | ')' | '[' | ']') {
            spans.push(Span::styled(c.to_string(), Style::default().fg(t.ui_accent)));
            i += 1;
            continue;
        }

        // Operators and everything else — accumulate until next token boundary
        let start = i;
        while i < len {
            let ch = chars[i];
            if ch == ' ' || ch == '\t' || ch == '"' || ch == '\''
                || ch.is_alphabetic() || ch == '_' || ch.is_ascii_digit()
                || matches!(ch, '{' | '}' | '(' | ')' | '[' | ']')
                || (ch == '/' && i + 1 < len && chars[i + 1] == '/')
            {
                break;
            }
            i += 1;
        }
        let s: String = chars[start..i].iter().collect();
        spans.push(Span::styled(s, Style::default().fg(t.ui_text)));
    }

    spans
}

fn draw_ai_decompiler(
    f: &mut Frame,
    app: &App,
    area: Rect,
    block: ratatui::widgets::Block<'_>,
    ai_lines: &[crate::ai_dec_cache::AiDecLine],
) {
    let inner_height = area.height.saturating_sub(2) as usize;
    let t = &app.theme;
    let code_height = inner_height.saturating_sub(1);

    // Map current_loc to the AI line with the greatest offset <= loc.
    // Uses max_by_key over all tagged lines so out-of-order or approximate
    // offset tags from the AI still produce a sensible cursor position.
    let current_ai_idx = app.current_loc.map(|loc| {
        ai_lines.iter().enumerate()
            .filter_map(|(i, line)| line.offset.map(|off| (i, off)))
            .filter(|&(_, off)| off <= loc)
            .max_by_key(|&(_, off)| off)
            .map(|(i, _)| i)
    }).flatten();

    // Scroll: center PC in view on auto-scroll, otherwise use bytecodes_scroll as line index
    let scroll = if app.bytecodes_auto_scroll {
        if let Some(pc) = current_ai_idx {
            pc.saturating_sub(code_height / 2)
        } else {
            0
        }
    } else {
        app.bytecodes_scroll.min(ai_lines.len().saturating_sub(1))
    };

    // Selection normalization
    let sel_full: Option<(usize, usize, usize, usize)> =
        match (app.bytecodes_sel_anchor, app.bytecodes_sel_head) {
            (Some(a), Some(h)) if a != h => {
                if a.0 < h.0 || (a.0 == h.0 && a.1 <= h.1) { Some((a.0, a.1, h.0, h.1)) }
                else { Some((h.0, h.1, a.0, a.1)) }
            }
            _ => None,
        };
    let sel_bg = t.ui_highlight_bg;

    let header = build_header(app);
    let mut lines: Vec<Line> = Vec::with_capacity(inner_height);
    lines.push(header);

    for (idx, ai_line) in ai_lines.iter().enumerate().skip(scroll).take(code_height) {
        let is_current = current_ai_idx == Some(idx);

        let has_bp = if let (Some(cls), Some(meth)) = (&app.current_class, &app.current_method) {
            if let Some(off) = ai_line.offset {
                app.bp_manager.breakpoints.iter().any(|bp| {
                    bp.class == *cls && bp.method == *meth && bp.location == off
                })
            } else { false }
        } else { false };

        // is_inner: PC is on this line but past its primary offset (mid-line step)
        let is_inner = is_current && match (app.current_loc, ai_line.offset) {
            (Some(loc), Some(off)) => loc > off,
            _ => false,
        };

        let marker = if has_bp && is_current { "\u{25cf}\u{25ba}" }
            else if has_bp { "\u{25cf} " }
            else if is_current { " \u{25ba}" }
            else { "  " };

        // When stepping inside a line, show the actual PC offset so it changes every step
        let offset_str = if is_inner {
            format!("{:04x}+", app.current_loc.unwrap() as u32 & 0xffff)
        } else {
            match ai_line.offset {
                Some(off) => format!("{:04x} ", off),
                None => "     ".to_string(),
            }
        };

        const PREFIX_LEN: usize = 2 + 5; // marker(2) + offset(5)

        let line_bg = if is_inner { t.ui_step_bg } else if is_current { t.ui_current_bg } else { t.ui_bg };

        let text_spans = highlight_java_line(&ai_line.text, t);

        // Apply current-line background to text spans before selection overlay
        let text_spans: Vec<Span<'static>> = if is_current {
            text_spans.into_iter()
                .map(|s| Span::styled(s.content.into_owned(), s.style.bg(line_bg)))
                .collect()
        } else {
            text_spans
        };

        // Apply selection across all text spans if this line is in the selection range
        let text_spans = if let Some((r0, c0, r1, c1)) = sel_full {
            if idx >= r0 && idx <= r1 {
                let sel_start = if idx == r0 { c0.saturating_sub(PREFIX_LEN) } else { 0 };
                let sel_end   = if idx == r1 { c1.saturating_sub(PREFIX_LEN) } else { usize::MAX };
                apply_sel_to_spans(text_spans, sel_start, sel_end, sel_bg)
            } else {
                text_spans
            }
        } else {
            text_spans
        };

        let mut spans: Vec<Span<'static>> = vec![
            Span::styled(marker.to_string(), if is_current { Style::default().fg(t.ui_accent).bg(line_bg) } else { Style::default().fg(t.ui_dim) }),
            Span::styled(offset_str, if is_inner { Style::default().fg(t.ui_accent).bg(line_bg) } else { Style::default().fg(t.ui_dim).bg(line_bg) }),
        ];
        spans.extend(text_spans);

        if let Some(ref hw) = app.bytecodes_highlight {
            apply_highlight(&mut spans, hw, t.ui_highlight_bg);
        }

        // Brace-pair highlight: color matched { } in red+bold
        if let Some((b_open, b_close)) = app.ai_dec_brace_pair {
            let brace_target = if idx == b_open { '{' } else if idx == b_close { '}' } else { '\0' };
            if brace_target != '\0' {
                let t_str = brace_target.to_string();
                for span in spans.iter_mut() {
                    if span.content == t_str {
                        span.style = span.style
                            .fg(t.ui_bg)
                            .bg(t.ui_breakpoint)
                            .add_modifier(ratatui::style::Modifier::BOLD);
                    }
                }
            }
        }

        lines.push(Line::from(spans));
    }

    // Pending indicator when aidec is running
    if app.ai_dec_rx.is_some() {
        lines.push(Line::from(Span::styled(
            "  [AI decompiling...]",
            Style::default().fg(t.ui_dim),
        )));
    }

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

fn draw_decompiler(f: &mut Frame, app: &App, area: Rect, block: ratatui::widgets::Block<'_>) {
    let inner_height = area.height.saturating_sub(2) as usize;
    let t = &app.theme;

    if app.bytecodes.is_empty() {
        let text = Paragraph::new("(no bytecodes)")
            .block(block)
            .style(Style::default().fg(t.ui_dim));
        f.render_widget(text, area);
        return;
    }

    // Check AI decompile cache for the current method
    let ai_dec_key = match (&app.current_class, &app.current_method) {
        (Some(c), Some(m)) => Some(crate::ai_dec_cache::AiDecCache::method_key(c, m)),
        _ => None,
    };
    let ai_lines = ai_dec_key.as_deref()
        .and_then(|k| app.ai_dec_cache.methods.get(k));

    if let Some(ai_lines) = ai_lines {
        draw_ai_decompiler(f, app, area, block, ai_lines);
        return;
    }

    // Build header
    let header = build_header(app);
    let code_height = inner_height.saturating_sub(1);

    // Find current instruction index
    let current_idx = app.current_loc.and_then(|loc| {
        app.bytecodes.iter().position(|i| i.offset == loc as u32)
    });

    // Build simplified lines from bytecodes
    // Filter out noise (nop, move, move-result) and show important ops
    let mut decompiled: Vec<(u32, Vec<Span<'static>>, bool)> = Vec::new(); // (offset, spans, is_important)

    for instr in &app.bytecodes {
        let text = &instr.text;
        let first_word = text.split_whitespace().next().unwrap_or("");

        // Skip noise instructions
        if is_decompiler_noise(text) { continue; }

        // Determine importance and format
        let (spans, important) = decompile_instruction(text, first_word, t);
        decompiled.push((instr.offset, spans, important));
    }

    // Map current instruction to decompiled index
    let current_dec_idx = current_idx.and_then(|_| {
        let cur_offset = app.current_loc? as u32;
        decompiled.iter().position(|(off, _, _)| *off == cur_offset)
    });

    // Scroll: if PC is at a filtered-out instruction (e.g. move/nop), use the nearest
    // preceding visible entry so the view stays stable instead of jumping to the top.
    let scroll_dec_idx = current_dec_idx.or_else(|| {
        let cur_offset = app.current_loc.map(|l| l as u32)?;
        decompiled.iter().rposition(|(off, _, _)| *off <= cur_offset)
    });

    // Translate bytecodes_scroll (raw index) to decompiled index via offset matching.
    // bytecodes_scroll may be larger than decompiled.len() because noise instructions
    // are filtered out.
    let base_scroll = {
        let raw_offset = app.bytecodes.get(app.bytecodes_scroll)
            .map(|i| i.offset)
            .unwrap_or(u32::MAX);
        decompiled.iter()
            .position(|(off, _, _)| *off >= raw_offset)
            .unwrap_or_else(|| decompiled.len().saturating_sub(1))
    };

    // On initial load (auto_scroll) center the PC in the view.
    // After that, respect bytecodes_scroll directly — the StepHit handler keeps it
    // in sync with the PC so the ► walks to the bottom edge before jumping.
    let scroll = if app.bytecodes_auto_scroll {
        if let Some(pc_idx) = scroll_dec_idx {
            if code_height > 0 { pc_idx.saturating_sub(code_height / 2) } else { 0 }
        } else {
            base_scroll
        }
    } else {
        base_scroll
    };

    let mut lines: Vec<Line> = Vec::with_capacity(inner_height);
    lines.push(header);

    // near_current: nearest preceding entry when PC is at a filtered instruction
    let near_current_idx = if current_dec_idx.is_none() { scroll_dec_idx } else { None };

    // Normalize selection (anchor/head stored as decompiled indices)
    let sel_full: Option<(usize, usize, usize, usize)> = match (app.bytecodes_sel_anchor, app.bytecodes_sel_head) {
        (Some(a), Some(h)) if a != h => {
            if a.0 < h.0 || (a.0 == h.0 && a.1 <= h.1) {
                Some((a.0, a.1, h.0, h.1))
            } else {
                Some((h.0, h.1, a.0, a.1))
            }
        }
        _ => None,
    };
    let sel_bg = t.ui_highlight_bg;

    for (idx, (offset, spans, important)) in decompiled.iter().enumerate().skip(scroll).take(code_height) {
        let is_current = current_dec_idx == Some(idx);
        let is_near  = near_current_idx == Some(idx);

        let has_bp = if let (Some(cls), Some(meth)) = (&app.current_class, &app.current_method) {
            app.bp_manager.breakpoints.iter().any(|bp| {
                bp.class == *cls && bp.method == *meth && bp.location == *offset as i64
            })
        } else {
            false
        };

        let marker = if has_bp && is_current {
            "\u{25cf}\u{25ba}"   // ●►
        } else if has_bp {
            "\u{25cf} "          // ●
        } else if is_current {
            " \u{25ba}"          // ►
        } else if is_near {
            " \u{00b7}"          // ·
        } else {
            "  "
        };
        let offset_str = format!("{:04x} ", offset);

        // Selection column range for this line (None = row not selected)
        let sel_cols: Option<(usize, usize)> = sel_full.and_then(|(r0, c0, r1, c1)| {
            if idx < r0 || idx > r1 { return None; }
            let start = if idx == r0 { c0 } else { 0 };
            let end   = if idx == r1 { c1 } else { usize::MAX };
            Some((start, end))
        });

        let bg = if is_current { t.ui_current_bg } else if is_near { t.ui_cursor_bg } else { t.ui_bg };

        let marker_style = if is_current {
            Style::default().fg(t.ui_value).bg(bg).add_modifier(Modifier::BOLD)
        } else if has_bp {
            Style::default().fg(t.ui_breakpoint).bg(bg).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(t.ui_dim).bg(bg)
        };

        let offset_style = Style::default().fg(t.ui_dim).bg(bg);

        let prefix_len = marker.chars().count() + offset_str.chars().count();
        let mut line_spans = vec![
            Span::styled(marker.to_string(), marker_style),
            Span::styled(offset_str, offset_style),
        ];
        let mut col_pos = prefix_len;
        for span in spans {
            let mut s = span.style;
            if is_current {
                s = s.bg(bg);
                if *important { s = s.add_modifier(Modifier::BOLD); }
            } else if is_near {
                s = s.bg(bg);
            }
            if let Some((sc, ec)) = sel_cols {
                let span_len = span.content.chars().count();
                let span_end = col_pos + span_len;
                if span_end > sc && col_pos < ec.min(usize::MAX - 1).saturating_add(1) {
                    s = s.bg(sel_bg);
                }
                col_pos = span_end;
            }
            line_spans.push(Span::styled(span.content.to_string(), s));
        }

        if let Some(ref hw) = app.bytecodes_highlight {
            apply_highlight(&mut line_spans, hw, t.ui_highlight_bg);
        }

        lines.push(Line::from(line_spans));
    }

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

/// Convert a bytecode instruction into a simplified pseudo-smali span.
pub fn decompile_instruction(text: &str, first_word: &str, t: &Theme) -> (Vec<Span<'static>>, bool) {
    match first_word {
        // Method calls  - the most important for malware analysis
        w if w.starts_with("invoke-") => {
            // Extract method reference from after the closing }
            let method_part = text.find('}')
                .map(|p| text[p+1..].trim_start_matches([',', ' ']))
                .unwrap_or("");
            let reg_part = text.find('{')
                .and_then(|s| text.find('}').map(|e| &text[s..=e]))
                .unwrap_or("");

            let fg = if method_part.contains('.') { t.bc_reference } else { t.bc_unresolved };
            let mut spans = vec![
                Span::styled("call ".to_string(), Style::default().fg(t.bc_opcode)),
                Span::styled(method_part.to_string(), Style::default().fg(fg)),
            ];
            // Split register group into individual spans so each register is highlightable
            if reg_part.starts_with('{') && reg_part.ends_with('}') {
                let inner = &reg_part[1..reg_part.len()-1];
                spans.push(Span::styled(" {".to_string(), Style::default().fg(t.ui_dim)));
                let regs: Vec<&str> = inner.split(',').collect();
                for (i, r) in regs.iter().enumerate() {
                    let reg = r.trim().to_string();
                    if i > 0 {
                        spans.push(Span::styled(", ".to_string(), Style::default().fg(t.ui_dim)));
                    }
                    spans.push(Span::styled(reg, Style::default().fg(t.ui_dim)));
                }
                spans.push(Span::styled("}".to_string(), Style::default().fg(t.ui_dim)));
            } else {
                spans.push(Span::styled(format!(" {}", reg_part), Style::default().fg(t.ui_dim)));
            }
            (spans, true)
        }

        // String loads
        "const-string" | "const-string/jumbo" => {
            let parts: Vec<&str> = text.splitn(3, ' ').collect();
            let reg = parts.get(1).unwrap_or(&"?").trim_end_matches(',');
            let string_val = parts.get(2).unwrap_or(&"");
            let fg = if string_val.starts_with('"') { t.bc_string } else { t.bc_unresolved };
            (vec![
                Span::styled(reg.to_string(), Style::default().fg(t.bc_register)),
                Span::styled(" = ".to_string(), Style::default().fg(t.ui_dim)),
                Span::styled(string_val.to_string(), Style::default().fg(fg)),
            ], true)
        }

        // Object creation
        "new-instance" => {
            let parts: Vec<&str> = text.splitn(3, ' ').collect();
            let reg = parts.get(1).unwrap_or(&"?").trim_end_matches(',');
            let type_ref = parts.get(2).unwrap_or(&"?");
            let fg = if type_ref.contains('.') { t.bc_reference } else { t.bc_unresolved };
            (vec![
                Span::styled(reg.to_string(), Style::default().fg(t.bc_register)),
                Span::styled(" = new ".to_string(), Style::default().fg(t.ui_dim)),
                Span::styled(type_ref.to_string(), Style::default().fg(fg)),
            ], true)
        }

        // Field access
        w if w.starts_with("iget") || w.starts_with("sget") => {
            let parts: Vec<&str> = text.splitn(2, ' ').collect();
            let operands = parts.get(1).unwrap_or(&"");
            let field_ref = operands.rsplit(", ").next().unwrap_or("");
            let regs = operands.strip_suffix(&format!(", {}", field_ref)).unwrap_or(operands);
            let fg = if field_ref.contains('.') { t.bc_reference } else { t.bc_unresolved };
            let op = if w.starts_with("sget") { "sget" } else { "get" };
            let dest_reg = regs.split(',').next().unwrap_or("?");
            (vec![
                Span::styled(dest_reg.to_string(), Style::default().fg(t.bc_register)),
                Span::styled(" = ".to_string(), Style::default().fg(t.ui_dim)),
                Span::styled(format!("{} ", op), Style::default().fg(t.bc_opcode)),
                Span::styled(field_ref.to_string(), Style::default().fg(fg)),
            ], false)
        }

        w if w.starts_with("iput") || w.starts_with("sput") => {
            let parts: Vec<&str> = text.splitn(2, ' ').collect();
            let operands = parts.get(1).unwrap_or(&"");
            let field_ref = operands.rsplit(", ").next().unwrap_or("");
            let op = if w.starts_with("sput") { "sput" } else { "put" };
            (vec![
                Span::styled(format!("{} ", op), Style::default().fg(t.bc_opcode)),
                Span::styled(field_ref.to_string(), Style::default().fg(if field_ref.contains('.') { t.bc_reference } else { t.bc_unresolved })),
            ], false)
        }

        // Branches
        w if w.starts_with("if-") => {
            (colorize_insn(text, t.ui_bg, false, t), false)
        }
        w if w.starts_with("goto") => {
            (colorize_insn(text, t.ui_bg, false, t), false)
        }

        // Returns
        "return-void" | "return" | "return-wide" | "return-object" => {
            (vec![Span::styled(text.to_string(), Style::default().fg(t.bc_flow))], false)
        }

        // Check-cast, instance-of
        "check-cast" | "instance-of" => {
            (colorize_insn(text, t.ui_bg, false, t), false)
        }

        // Constants
        w if w.starts_with("const") => {
            let parts: Vec<&str> = text.splitn(3, ' ').collect();
            let reg = parts.get(1).unwrap_or(&"?").trim_end_matches(',');
            let val = parts.get(2).unwrap_or(&"");
            (vec![
                Span::styled(reg.to_string(), Style::default().fg(t.bc_register)),
                Span::styled(" = ".to_string(), Style::default().fg(t.ui_dim)),
                Span::styled(val.to_string(), Style::default().fg(t.bc_number)),
            ], false)
        }

        // Throw
        "throw" => {
            (vec![Span::styled(text.to_string(), Style::default().fg(t.bc_flow))], true)
        }

        // Everything else  - show as-is with basic coloring
        _ => {
            (colorize_insn(text, t.ui_bg, false, t), false)
        }
    }
}

fn category_color(cat: CallCategory) -> Color {
    match cat {
        CallCategory::Crypto => Color::Yellow,
        CallCategory::Network => Color::Cyan,
        CallCategory::Exec => Color::Red,
        CallCategory::Reflection => Color::Magenta,
        CallCategory::DexLoad => Color::LightRed,
        CallCategory::Exfil => Color::Red,
        CallCategory::Other => Color::Gray,
    }
}

fn draw_trace(f: &mut Frame, app: &App, area: Rect, block: ratatui::widgets::Block<'_>) {
    let inner_height = area.height.saturating_sub(2) as usize;
    let t = &app.theme;

    if app.call_records.is_empty() {
        let msg = if app.recording_active {
            "(recording... waiting for API calls)"
        } else {
            "(no recorded calls  - use 'record' to start)"
        };
        let text = Paragraph::new(msg)
            .block(block)
            .style(Style::default().fg(t.ui_dim));
        f.render_widget(text, area);
        return;
    }

    // Build header
    let header = Line::from(vec![
        Span::styled(
            format!(" {} calls", app.call_records.len()),
            Style::default().fg(t.ui_accent).add_modifier(Modifier::BOLD),
        ),
        if app.recording_active {
            Span::styled(" (recording)", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
        } else {
            Span::styled(" (stopped)", Style::default().fg(t.ui_dim))
        },
    ]);

    let code_height = inner_height.saturating_sub(1); // 1 line for header

    // Auto-scroll to bottom when new calls arrive
    let scroll = if app.trace_auto_scroll {
        app.call_records.len().saturating_sub(code_height)
    } else {
        app.trace_scroll
    };

    let mut lines: Vec<Line> = Vec::with_capacity(inner_height);
    lines.push(header);

    for record in app.call_records.iter().skip(scroll).take(code_height) {
        let color = category_color(record.category);
        let short = commands::short_class(&record.class);

        // Tree indentation: 2 chars per depth level, capped at 20
        let indent_level = record.depth.min(10);
        let indent = "  ".repeat(indent_level);

        if record.is_exit {
            // Exit line: "  <- ClassName.method -> retval"
            let arrow = if record.exception { "!!" } else { "<-" };
            let method_str = format!("{}.{}", short, record.method);

            let mut spans = vec![
                Span::styled(
                    format!("     {}{} ", indent, arrow),
                    if record.exception {
                        Style::default().fg(Color::Red)
                    } else {
                        Style::default().fg(t.ui_dim)
                    },
                ),
                Span::styled(
                    method_str,
                    Style::default().fg(t.ui_dim),
                ),
            ];

            if record.exception {
                spans.push(Span::styled(" !EXC", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)));
            } else if let Some(ret) = &record.ret {
                spans.push(Span::styled(
                    format!(" -> {}", ret),
                    Style::default().fg(t.ui_dim),
                ));
            }

            lines.push(Line::from(spans));
        } else {
            // Entry line: "  42 -> ClassName.method(args)"
            let seq_str = format!("{:>4} ", record.seq + 1);
            let method_str = format!("{}.{}", short, record.method);

            let args_str = if record.args.is_empty() {
                String::new()
            } else {
                format!("({})", record.args.join(", "))
            };

            let mut spans = vec![
                Span::styled(seq_str, Style::default().fg(t.ui_dim)),
                Span::styled(
                    format!("{}-> ", indent),
                    Style::default().fg(t.ui_dim),
                ),
                Span::styled(method_str, Style::default().fg(color).add_modifier(Modifier::BOLD)),
                Span::styled(args_str, Style::default().fg(color)),
            ];

            if record.exception {
                spans.push(Span::styled(" !EXC", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)));
            }

            lines.push(Line::from(spans));
        }
    }

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

// ---------------------------------------------------------------------------
// Syntax coloring for disassembled instructions
// ---------------------------------------------------------------------------

/// Colorize a disassembled instruction text into spans.
/// Color scheme uses theme slots:
///   Opcode          → bc_opcode
///   Registers (vN)  → bc_register
///   String literals  → bc_string
///   Resolved refs   → bc_reference (Class.method, Class.field:Type)
///   Unresolved refs → bc_unresolved (string@xxxx, method@xxxx)
///   Constants (#N)  → bc_number
///   Register lists  → bc_register ({v0, v1})
///   Branch targets  → bc_branch
fn colorize_insn(text: &str, bg: Color, bold: bool, t: &Theme) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    let bytes = text.as_bytes();
    let len = bytes.len();

    // Opcode: first word
    let mut pos = 0;
    while pos < len && bytes[pos] != b' ' {
        pos += 1;
    }
    let opcode = &text[..pos];
    let opcode_color = if is_flow_opcode(opcode) { t.bc_flow } else { t.bc_opcode };
    let mut opcode_style = Style::default().fg(opcode_color).bg(bg);
    if bold { opcode_style = opcode_style.add_modifier(Modifier::BOLD); }
    spans.push(Span::styled(opcode.to_string(), opcode_style));

    // Process rest character by character
    while pos < len {
        let ch = bytes[pos];

        // Whitespace / commas  - keep neutral
        if ch == b' ' || ch == b',' {
            spans.push(Span::styled(
                (ch as char).to_string(),
                Style::default().bg(bg),
            ));
            pos += 1;
            continue;
        }

        // String literal: "..."
        if ch == b'"' {
            let start = pos;
            pos += 1;
            while pos < len && bytes[pos] != b'"' { pos += 1; }
            if pos < len { pos += 1; }
            let mut s = Style::default().fg(t.bc_string).bg(bg);
            if bold { s = s.add_modifier(Modifier::BOLD); }
            spans.push(Span::styled(text[start..pos].to_string(), s));
            continue;
        }

        // Register list: {...}
        if ch == b'{' {
            let start = pos;
            while pos < len && bytes[pos] != b'}' { pos += 1; }
            if pos < len { pos += 1; }
            spans.push(Span::styled(
                text[start..pos].to_string(),
                Style::default().fg(t.bc_register).bg(bg),
            ));
            continue;
        }

        // Parenthesized content: (N entries), (N x M bytes)
        if ch == b'(' {
            let start = pos;
            while pos < len && bytes[pos] != b')' { pos += 1; }
            if pos < len { pos += 1; }
            spans.push(Span::styled(
                text[start..pos].to_string(),
                Style::default().fg(t.ui_dim).bg(bg),
            ));
            continue;
        }

        // Collect a token (until delimiter)
        let start = pos;
        while pos < len && bytes[pos] != b' ' && bytes[pos] != b',' && bytes[pos] != b'"' {
            pos += 1;
        }
        let token = &text[start..pos];
        let fg = classify_token(token, t);
        let mut s = Style::default().fg(fg).bg(bg);
        if bold { s = s.add_modifier(Modifier::BOLD); }
        spans.push(Span::styled(token.to_string(), s));
    }

    spans
}

/// Check if an opcode is a flow-control keyword (goto, if-*, return, throw).
fn is_flow_opcode(opcode: &str) -> bool {
    opcode.starts_with("goto") ||
    opcode.starts_with("if-") ||
    opcode.starts_with("return") ||
    opcode == "throw" ||
    opcode.starts_with("packed-switch") ||
    opcode.starts_with("sparse-switch")
}

/// Classify a token to determine its foreground color.
fn classify_token(token: &str, t: &Theme) -> Color {
    // Register: v0, v1, v2...
    if token.starts_with('v') && token.len() > 1 && token[1..].chars().all(|c| c.is_ascii_digit()) {
        return t.bc_register;
    }
    // Unresolved reference: string@xxxx, method@xxxx, type@xxxx, field@xxxx
    if token.contains('@') {
        return t.bc_unresolved;
    }
    // Constant: #42, #-1, #0x1234
    if token.starts_with('#') {
        return t.bc_number;
    }
    // Resolved reference: contains a dot (Class.method(params), Class.field:Type)
    if token.contains('.') {
        return t.bc_reference;
    }
    // Hex branch target: 4+ hex digits
    if token.len() >= 4 && token.chars().all(|c| c.is_ascii_hexdigit()) {
        return t.bc_branch;
    }
    // Offset with +/- prefix (branch/switch offsets)
    if token.starts_with('+') || (token.starts_with('-') && token.len() > 1) {
        return t.bc_number;
    }
    Color::Gray
}

/// Apply word-highlight to spans: any span whose trimmed content matches the
/// highlight word gets the highlight background color.
fn trim_punct(s: &str) -> &str {
    s.trim_matches(|c: char| c == ',' || c == ' ' || c == ':')
}

fn apply_highlight(spans: &mut [Span<'_>], word: &str, highlight_bg: Color) {
    // Trim punctuation from both sides so that clicking a branch target "005a" in an
    // instruction also highlights the destination offset span "005a: ", and vice versa.
    let word_trimmed = trim_punct(word);
    for span in spans.iter_mut() {
        let content = trim_punct(&span.content);
        if !content.is_empty() && content == word_trimmed {
            span.style = span.style.bg(highlight_bg);
        }
    }
}

fn draw_ai(f: &mut Frame, app: &App, area: Rect, block: ratatui::widgets::Block<'_>) {
    let inner_height = area.height.saturating_sub(2) as usize;
    let t = &app.theme;

    if app.ai_output.is_empty() {
        let msg = match app.ai_state {
            AiState::Idle => "(no AI output  - use 'ai <prompt>' to start analysis)",
            AiState::Running => "(AI is thinking...)",
            AiState::WaitingApproval => "(AI is waiting for approval  - press y/n)",
        };
        let text = Paragraph::new(msg)
            .block(block)
            .style(Style::default().fg(t.ui_dim));
        f.render_widget(text, area);
        return;
    }

    let scroll = if app.ai_auto_scroll {
        app.ai_output.len().saturating_sub(inner_height)
    } else {
        app.ai_scroll
    };

    // Normalize selection to (r0, c0, r1, c1)
    let sel: Option<(usize, usize, usize, usize)> =
        match (app.ai_sel_anchor, app.ai_sel_head) {
            (Some(a), Some(h)) if a != h => {
                if a.0 < h.0 || (a.0 == h.0 && a.1 <= h.1) {
                    Some((a.0, a.1, h.0, h.1))
                } else {
                    Some((h.0, h.1, a.0, a.1))
                }
            }
            _ => None,
        };

    let sel_bg = Color::Rgb(60, 80, 120);
    let mut lines: Vec<Line> = Vec::with_capacity(inner_height);

    for (i, entry) in app.ai_output.iter().enumerate().skip(scroll).take(inner_height) {
        let style = match entry.kind {
            AiLineKind::Text => Style::default().fg(t.ui_text),
            AiLineKind::Header => Style::default().fg(t.ui_accent).add_modifier(Modifier::BOLD),
            AiLineKind::ToolCall => Style::default().fg(t.ui_dim),
            AiLineKind::ToolResult => Style::default().fg(Color::Rgb(60, 60, 60)),
            AiLineKind::Error => Style::default().fg(Color::Red),
        };
        let spans = if let Some((r0, c0, r1, c1)) = sel {
            if i >= r0 && i <= r1 {
                let sel_start = if i == r0 { c0 } else { 0 };
                let sel_end   = if i == r1 { c1 } else { usize::MAX };
                apply_sel_to_spans(vec![Span::styled(entry.text.clone(), style)], sel_start, sel_end, sel_bg)
            } else {
                vec![Span::styled(entry.text.clone(), style)]
            }
        } else {
            vec![Span::styled(entry.text.clone(), style)]
        };
        lines.push(Line::from(spans));
    }

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

// ---------------------------------------------------------------------------
// JNI monitor panel
// ---------------------------------------------------------------------------

/// Decode a single JNI type descriptor token.
/// Returns (human_type, remaining_str).
fn demangle_one(s: &str) -> (String, &str) {
    let b = s.as_bytes();
    if b.is_empty() { return ("?".into(), s); }
    match b[0] {
        b'Z' => ("boolean".into(), &s[1..]),
        b'B' => ("byte".into(),    &s[1..]),
        b'C' => ("char".into(),    &s[1..]),
        b'S' => ("short".into(),   &s[1..]),
        b'I' => ("int".into(),     &s[1..]),
        b'J' => ("long".into(),    &s[1..]),
        b'F' => ("float".into(),   &s[1..]),
        b'D' => ("double".into(),  &s[1..]),
        b'V' => ("void".into(),    &s[1..]),
        b'[' => {
            let (inner, rest) = demangle_one(&s[1..]);
            (format!("{}[]", inner), rest)
        }
        b'L' => {
            if let Some(end) = s.find(';') {
                let path = &s[1..end];
                let simple = path.split('/').last().unwrap_or(path);
                (simple.into(), &s[end + 1..])
            } else {
                ("Object".into(), "")
            }
        }
        _ => ("?".into(), &s[1..]),
    }
}

/// Convert a JNI method signature + name to a readable string.
/// e.g. "checkIntegrity", "()Z"  ->  "boolean checkIntegrity()"
/// e.g. "getKey", "([B)[B"       ->  "byte[] getKey(byte[])"
pub fn demangle_jni_sig(method_name: &str, jni_sig: &str) -> String {
    let paren = jni_sig.find(')').unwrap_or(jni_sig.len());
    let params_str = &jni_sig[1..paren.min(jni_sig.len())];
    let ret_str    = if paren + 1 < jni_sig.len() { &jni_sig[paren + 1..] } else { "V" };

    let (ret_type, _) = demangle_one(ret_str);

    let mut params: Vec<String> = Vec::new();
    let mut rem = params_str;
    while !rem.is_empty() {
        let (t, rest) = demangle_one(rem);
        params.push(t);
        rem = rest;
    }

    format!("{} {}({})", ret_type, method_name, params.join(", "))
}

fn draw_jni_monitor(f: &mut Frame, app: &App, area: Rect, block: ratatui::widgets::Block<'_>) {
    let inner_height = area.height.saturating_sub(2) as usize;
    let t = &app.theme;

    if app.jni_natives.is_empty() {
        let msg = if app.jni_monitoring {
            "(monitoring — waiting for RegisterNatives calls)"
        } else {
            "(no bindings captured — use 'jni monitor' to start)"
        };
        let text = Paragraph::new(msg).block(block).style(Style::default().fg(t.ui_dim));
        f.render_widget(text, area);
        return;
    }

    let status_suffix = if app.jni_monitoring {
        Span::styled(" (monitoring)", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
    } else {
        Span::styled(" (stopped)", Style::default().fg(t.ui_dim))
    };

    let header = Line::from(vec![
        Span::styled(
            format!(" {} native bindings", app.jni_natives.len()),
            Style::default().fg(t.ui_accent).add_modifier(Modifier::BOLD),
        ),
        status_suffix,
        Span::styled(
            "   jni redirect <cls> <method> <sig> <block|true|false>",
            Style::default().fg(t.ui_dim),
        ),
    ]);

    let list_height = inner_height.saturating_sub(1);
    let scroll = app.jni_monitor_scroll.min(app.jni_natives.len().saturating_sub(1));

    let mut lines: Vec<Line> = Vec::with_capacity(inner_height);
    lines.push(header);

    for entry in app.jni_natives.iter().skip(scroll).take(list_height) {
        lines.push(format_jni_entry(entry, t));
    }

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

fn format_jni_entry(e: &JniNativeEntry, t: &Theme) -> Line<'static> {
    // lib+offset column: "libnative.so+0x1b10"
    let addr_str = if e.lib_name.is_empty() || e.lib_name == "[anon]" {
        format!("0x{:x}", e.native_addr as u64)
    } else {
        format!("{}+0x{:x}", e.lib_name, e.lib_offset as u64)
    };

    // Short class name: "Lcom/example/Shield;" -> "Shield"
    let short_class = {
        let inner = e.class_sig.trim_start_matches('L').trim_end_matches(';');
        inner.split('/').last().unwrap_or(inner).to_string()
    };

    let readable = demangle_jni_sig(&e.method_name, &e.method_sig);

    let redirect_tag = if e.redirected {
        let action = e.redirect_action.as_deref().unwrap_or("?");
        format!(" [->{}]", action)
    } else {
        String::new()
    };

    Line::from(vec![
        Span::styled(
            format!("  {:36}", addr_str),
            Style::default().fg(Color::Cyan),
        ),
        Span::styled(
            format!("{}.", short_class),
            Style::default().fg(t.ui_dim),
        ),
        Span::styled(
            readable,
            Style::default().fg(t.ui_text),
        ),
        Span::styled(
            redirect_tag,
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ),
    ])
}
