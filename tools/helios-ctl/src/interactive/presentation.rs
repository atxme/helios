//! Terminal presentation using the line editor's own redraw lifecycle.

use std::time::Duration;

use super::palette::Suggestions;

const BRAND: &str = "\x1b[1;38;5;208m";
const ACCENT: &str = "\x1b[1;38;5;141m";
const MUTED: &str = "\x1b[2m";
const SELECTED: &str = "\x1b[1;7m";
const SUCCESS: &str = "\x1b[32m";
const FAILURE: &str = "\x1b[31m";
const RESET: &str = "\x1b[0m";

/// Last gateway status seen by the shell, shown under the input.
pub(super) enum Gateway {
    Unknown,
    /// No usable answer: unreachable, timed out or an incompatible response.
    Unavailable,
    Reachable {
        state: String,
        version: String,
        dry_run: bool,
    },
}

#[derive(Clone, Copy)]
pub(super) struct Appearance {
    pub color: bool,
}

impl Appearance {
    pub fn paint(self, text: &str, style: &str) -> String {
        if self.color {
            format!("{style}{text}{RESET}")
        } else {
            text.to_owned()
        }
    }

    pub fn prompt(self, prompt: &str) -> String {
        self.paint(prompt, ACCENT)
    }

    pub fn welcome(self, base: &str, width: usize) -> String {
        let width = width.saturating_sub(1).min(88);
        if width >= 40 {
            let title = format!(" Helios v{} ", env!("CARGO_PKG_VERSION"));
            let top = format!("╭─{title}{}╮", "─".repeat(width - title.len() - 3));
            let row = |text: &str, style| {
                let text = fit(text, width - 6);
                let padding = " ".repeat(width - 6 - text.chars().count());
                format!(
                    "{}  {}{padding}  {}",
                    self.paint("│", MUTED),
                    self.paint(&text, style),
                    self.paint("│", MUTED)
                )
            };
            return [
                String::new(),
                self.paint(&top, BRAND),
                row("", MUTED),
                row("☀  Gateway administration", BRAND),
                row(&format!("API  {base}"), RESET),
                row("", MUTED),
                row("Type / to browse commands · /help for usage", MUTED),
                row("OS updates: local · Firmware: explicit SSH target", MUTED),
                self.paint(&format!("╰{}╯", "─".repeat(width - 2)), MUTED),
                String::new(),
            ]
            .join("\n");
        }
        let mut lines = vec![String::new()];
        let title = format!("  ☀ Helios  v{}", env!("CARGO_PKG_VERSION"));
        lines.push(self.paint(&fit(&title, width), BRAND));
        lines.push(self.paint(&fit("  Gateway administration", width), MUTED));
        lines.push(String::new());
        lines.push(fit(&format!("  API  {base}"), width));
        lines.push(self.paint(
            &fit("  Type / to browse commands, or /help for usage.", width),
            MUTED,
        ));
        lines.push(self.paint(
            &fit(
                "  OS updates run locally. Firmware uses an explicit SSH target.",
                width,
            ),
            MUTED,
        ));
        lines.push(String::new());
        lines.join("\n")
    }

    pub fn divider(self, width: usize) -> String {
        self.paint(&"─".repeat(width.saturating_sub(1).min(120)), MUTED)
    }

    pub fn highlight_hint(self, hint: &str, gateway: &Gateway) -> String {
        hint.split('\n')
            .map(|line| {
                if let (true, Some(rest), Gateway::Reachable { state, .. }) =
                    (self.color, line.strip_prefix("  ● "), gateway)
                {
                    format!("  {} {}", crate::state_dot(state), self.paint(rest, MUTED))
                } else if line.starts_with("  › ") {
                    self.paint(line, SELECTED)
                } else {
                    self.paint(line, MUTED)
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Name the command only: argument values may carry key material.
    pub fn command_header(self, path: &str, width: usize) -> String {
        let path = fit(path, width.saturating_sub(3));
        format!(
            "{} {}",
            self.paint("⏺", ACCENT),
            self.paint(&path, "\x1b[1m")
        )
    }

    pub fn command_success(self, elapsed: Duration) -> String {
        let seconds = elapsed.as_secs();
        let elapsed = if seconds < 60 {
            format!("{:.1} s", elapsed.as_secs_f64())
        } else {
            format!("{} min {:02} s", seconds / 60, seconds % 60)
        };
        format!(
            "  {} {} {}",
            self.paint("⎿", MUTED),
            self.paint("✓", SUCCESS),
            self.paint(&elapsed, MUTED)
        )
    }

    /// Gateway error text is untrusted: controls are dropped, and long lines
    /// wrap rather than truncate so no part of the error is hidden.
    pub fn command_failure(self, error: &str, width: usize) -> String {
        let width = width.saturating_sub(7).max(1);
        error
            .lines()
            .flat_map(|line| wrap(line, width))
            .enumerate()
            .map(|(index, line)| {
                let line = self.paint(&line, FAILURE);
                if index == 0 {
                    format!(
                        "  {} {} {line}",
                        self.paint("⎿", MUTED),
                        self.paint("✗", FAILURE)
                    )
                } else {
                    format!("      {line}")
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Keep menu text separate from completion: a footer can never become input.
pub(super) fn hint_text(
    matches: Option<&Suggestions>,
    selected: usize,
    width: usize,
    height: usize,
    gateway: &Gateway,
    base: &str,
) -> String {
    let width = width.saturating_sub(1).min(120);
    let mut lines = vec![String::new(), "─".repeat(width)];
    if let Some(matches) = matches {
        let count = matches.entries.len();
        if count == 0 {
            lines.push(fit("  No matching command. /help lists usage.", width));
        } else {
            let selected = selected.min(count - 1);
            let visible = height.saturating_sub(9).clamp(1, 8).min(count);
            let start = selected.saturating_sub(visible - 1);
            let label_width = matches
                .entries
                .iter()
                .map(|entry| entry.name.len() + usize::from(matches.start == 0))
                .max()
                .unwrap_or(0)
                .min(width / 2);
            for (index, entry) in matches.entries.iter().enumerate().skip(start).take(visible) {
                let name = format!(
                    "{}{name}",
                    if matches.start == 0 { "/" } else { "" },
                    name = entry.name
                );
                let marker = if index == selected { "›" } else { " " };
                let label = fit(&name, label_width);
                let description = entry.description.lines().next().unwrap_or_default();
                lines.push(fit(
                    &format!("  {marker} {label:<label_width$}  {description}"),
                    width,
                ));
            }
            if count > visible {
                lines.push(fit(
                    &format!(
                        "  {}–{} of {count} commands",
                        start + 1,
                        (start + visible).min(count)
                    ),
                    width,
                ));
            }
        }
        lines.push(fit("  ↑↓ navigate · Tab/Enter complete · Esc close", width));
    } else {
        let status = match gateway {
            Gateway::Unknown => format!("  ○ {base}"),
            Gateway::Unavailable => format!("  ○ status unavailable · {base}"),
            Gateway::Reachable {
                state,
                version,
                dry_run,
            } => format!(
                "  ● {state} · heliosd v{version} ·{} {base}",
                if *dry_run { " dry-run ·" } else { "" }
            ),
        };
        lines.push(fit(&status, width));
        lines.push(fit(
            "  / commands · Tab complete · ↑↓ history · Ctrl-D exit",
            width,
        ));
    }
    lines.join("\n")
}

/// Break on spaces; split a word only when it alone exceeds the width.
fn wrap(line: &str, width: usize) -> Vec<String> {
    let line: String = line.chars().filter(|c| !c.is_control()).collect();
    let mut lines = vec![String::new()];
    for word in line.split(' ').filter(|word| !word.is_empty()) {
        let mut word: Vec<char> = word.chars().collect();
        let current = lines.last_mut().map_or(0, |line| line.chars().count());
        if current > 0 && current + 1 + word.len() <= width {
            lines.last_mut().into_iter().for_each(|line| line.push(' '));
        } else if current > 0 {
            lines.push(String::new());
        }
        while let Some(line) = lines.last_mut() {
            let room = width - line.chars().count();
            if word.len() <= room {
                line.extend(word.drain(..));
                break;
            }
            line.extend(word.drain(..room));
            lines.push(String::new());
        }
    }
    lines
}

/// Metadata and gateway labels are text, never terminal control sequences.
fn fit(text: &str, width: usize) -> String {
    let text: String = text.chars().filter(|c| !c.is_control()).collect();
    if text.chars().count() <= width {
        return text;
    }
    if width == 0 {
        return String::new();
    }
    text.chars()
        .take(width - 1)
        .chain(std::iter::once('…'))
        .collect()
}

pub(super) fn dimensions(fallback: (usize, usize)) -> (usize, usize) {
    #[cfg(target_os = "linux")]
    {
        let mut size = libc::winsize {
            ws_row: 0,
            ws_col: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: ioctl writes only to this initialized winsize. stdout is
        // already verified as a terminal before the interactive editor starts.
        if unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut size) } == 0
            && size.ws_col > 0
            && size.ws_row > 0
        {
            return (usize::from(size.ws_col), usize::from(size.ws_row));
        }
    }
    fallback
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interactive::palette::suggestions;
    use clap::CommandFactory;

    #[test]
    fn menu_scrolls_to_keep_selection_visible_and_fits_narrow_terminals() {
        let mut tree = crate::Cli::command();
        tree.build();
        let matches = suggestions(&tree, "/", 1);
        let selected = matches.entries.len() - 1;
        for width in [12, 40, 80] {
            let text = hint_text(Some(&matches), selected, width, 16, &Gateway::Unknown, "");
            assert!(text.contains("›"));
            assert!(text.contains(&format!("of {}", matches.entries.len())) || width < 20);
            assert!(text.lines().all(|line| line.chars().count() < width));
            assert!(text.lines().count() <= 16);
        }
    }

    #[test]
    fn no_color_and_untrusted_labels_do_not_emit_terminal_controls() {
        let plain = Appearance { color: false };
        let text = plain.welcome("http://gateway/\x1b[2J", 40);
        assert!(!text.contains('\x1b'));
        assert!(text.lines().all(|line| line.chars().count() < 40));
        assert!(!plain
            .highlight_hint("\n  › /status", &Gateway::Unknown)
            .contains('\x1b'));
        assert!(Appearance { color: true }.prompt("❯ ").contains('\x1b'));
    }

    #[test]
    fn command_blocks_report_duration_or_error_without_terminal_controls() {
        let plain = Appearance { color: false };
        assert_eq!(plain.command_header("peer list", 80), "⏺ peer list");
        assert_eq!(
            plain.command_success(Duration::from_millis(420)),
            "  ⎿ ✓ 0.4 s"
        );
        assert_eq!(
            plain.command_success(Duration::from_secs(125)),
            "  ⎿ ✓ 2 min 05 s"
        );
        let failure = plain.command_failure("gateway said \x1b[2Jno\ncaused by: refused", 40);
        assert!(!failure.contains('\x1b'));
        let lines: Vec<_> = failure.lines().collect();
        assert_eq!(lines[0], "  ⎿ ✗ gateway said [2Jno");
        assert_eq!(lines[1], "      caused by: refused");
        assert!(failure.lines().all(|line| line.chars().count() < 40));
        let long = "x".repeat(70) + "END";
        let wrapped = plain.command_failure(&long, 40);
        assert!(wrapped.lines().all(|line| line.chars().count() < 40));
        let kept: String = wrapped
            .lines()
            .map(|line| line.trim_start_matches(['⎿', '✗', ' ']))
            .collect();
        assert_eq!(kept, long, "errors wrap instead of being truncated");
        let words = plain.command_failure("refused: tcp connect error", 20);
        assert_eq!(
            words.lines().collect::<Vec<_>>(),
            ["  ⎿ ✗ refused: tcp", "      connect error"]
        );
        let colored = Appearance { color: true };
        assert!(colored.command_header("status", 80).contains('\x1b'));
        assert!(colored.command_failure("boom", 80).contains("\x1b[31m"));
    }

    #[test]
    fn status_line_shows_gateway_state_and_fits_the_terminal() {
        let up = Gateway::Reachable {
            state: "up".into(),
            version: "0.11.0".into(),
            dry_run: false,
        };
        let text = hint_text(None, 0, 80, 24, &up, "http://gw:8080");
        assert!(text.contains("  ● up · heliosd v0.11.0 · http://gw:8080"));
        assert!(text.contains("/ commands"));
        let dry = Gateway::Reachable {
            state: "down".into(),
            version: "0.11.0".into(),
            dry_run: true,
        };
        assert!(hint_text(None, 0, 80, 24, &dry, "http://gw").contains("· dry-run ·"));
        let text = hint_text(None, 0, 80, 24, &Gateway::Unavailable, "http://gw");
        assert!(text.contains("  ○ status unavailable · http://gw"));
        let hostile = Gateway::Reachable {
            state: "up\x1b[2J".into(),
            version: "\x1b]0;x\x07".into(),
            dry_run: false,
        };
        for width in [12, 40, 80] {
            let text = hint_text(None, 0, width, 24, &hostile, "http://gw");
            assert!(!text.contains('\x1b'));
            assert!(text.lines().all(|line| line.chars().count() < width));
        }
        let colored = Appearance { color: true }.highlight_hint(&text_for(&up), &up);
        assert!(colored.contains("\x1b[32m●"));
        let plain = Appearance { color: false }.highlight_hint(&text_for(&up), &up);
        assert!(!plain.contains('\x1b'));
    }

    fn text_for(gateway: &Gateway) -> String {
        hint_text(None, 0, 80, 24, gateway, "http://gw")
    }
}
