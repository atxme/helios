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

/// Why the status line has no gateway state to show.
pub(super) enum Unavailable {
    /// Refused or timed out. The firewall drops the API port on every
    /// interface but the tunnel, loopback included: from the gateway's own
    /// shell this is the expected answer, not a fault.
    NoAnswer,
    /// Something answered, but not with a status this tool can read.
    Incompatible,
}

/// Last gateway status seen by the shell, shown under the input.
pub(super) enum Gateway {
    Unknown,
    Unavailable(Unavailable),
    Reachable {
        state: String,
        version: String,
        dry_run: bool,
        peers_online: usize,
        peers_total: usize,
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

    /// Input line with its leading slash command emphasized.
    pub fn input(self, line: &str) -> String {
        if !line.starts_with('/') || !self.color {
            return line.to_owned();
        }
        let end = line.find(char::is_whitespace).unwrap_or(line.len());
        format!("{}{}", self.prompt(&line[..end]), &line[end..])
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

    /// Dropping the command does not recall a request already on the wire.
    pub fn command_interrupted(self, width: usize) -> String {
        self.command_failure(
            "interrupted (a request already sent may still complete)",
            width,
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

/// What Ctrl-C at the prompt does, as in Claude Code: it clears typed text;
/// on an empty line it asks for confirmation, and a second one exits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Interrupt {
    Clear,
    Arm,
    Exit,
}

pub(super) fn on_interrupt(line_empty: bool, armed: bool) -> Interrupt {
    match (line_empty, armed) {
        (false, _) => Interrupt::Clear,
        (true, false) => Interrupt::Arm,
        (true, true) => Interrupt::Exit,
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
    exit_armed: bool,
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
            Gateway::Unavailable(Unavailable::NoAnswer) => {
                format!("  ○ no API answer (tunnel only) · {base}")
            }
            Gateway::Unavailable(Unavailable::Incompatible) => {
                format!("  ○ incompatible API response · {base}")
            }
            Gateway::Reachable {
                state,
                version,
                dry_run,
                peers_online,
                peers_total,
            } => format!(
                "  ● {} · {peers_online}/{peers_total} peers online · heliosd v{version} ·{} {base}",
                // heliosd's `connecting` is a ready gateway with no client
                // handshake yet, not a gateway trying to connect somewhere.
                if state == "connecting" { "waiting for clients" } else { state },
                if *dry_run { " dry-run ·" } else { "" }
            ),
        };
        lines.push(fit(&status, width));
        lines.push(fit(
            if exit_armed {
                "  Press Ctrl-C again to exit"
            } else {
                "  / commands · Tab complete · ↑↓ history · Ctrl-C twice to exit"
            },
            width,
        ));
    }
    lines.join("\n")
}

/// Rows left above the cursor once the editor returns: the divider, the `❯ `
/// input and, when the editor kept it on screen, the hint. `None` when the
/// layout cannot be measured; erasing a guess could swallow earlier output.
pub(super) fn submitted_rows(line: &str, width: usize, hint: Option<&str>) -> Option<usize> {
    if width == 0 || !line.is_ascii() {
        return None;
    }
    let input = (2 + line.len()) / width + 1;
    Some(1 + input + hint.map_or(0, |hint| hint.matches('\n').count()))
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
            let text = hint_text(
                Some(&matches),
                selected,
                width,
                16,
                &Gateway::Unknown,
                "",
                false,
            );
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
        let interrupted = plain.command_interrupted(80);
        assert!(interrupted.starts_with("  ⎿ ✗ interrupted"));
        assert!(!interrupted.contains('\x1b'));
        let colored = Appearance { color: true };
        assert!(colored.command_header("status", 80).contains('\x1b'));
        assert!(colored.command_failure("boom", 80).contains("\x1b[31m"));
    }

    #[test]
    fn status_line_shows_gateway_state_and_fits_the_terminal() {
        let up = Gateway::Reachable {
            state: "up".into(),
            version: "1.13.0".into(),
            dry_run: false,
            peers_online: 3,
            peers_total: 17,
        };
        let text = hint_text(None, 0, 90, 24, &up, "local", false);
        assert!(text.contains("  ● up · 3/17 peers online · heliosd v1.13.0 · local"));
        let waiting = Gateway::Reachable {
            state: "connecting".into(),
            version: "1.13.0".into(),
            dry_run: false,
            peers_online: 0,
            peers_total: 17,
        };
        let text = hint_text(None, 0, 90, 24, &waiting, "local", false);
        assert!(
            text.contains("  ● waiting for clients · 0/17 peers online · heliosd v1.13.0 · local"),
            "{text}"
        );
        assert!(text.contains("/ commands"));
        let dry = Gateway::Reachable {
            state: "down".into(),
            version: "0.11.0".into(),
            dry_run: true,
            peers_online: 0,
            peers_total: 0,
        };
        assert!(hint_text(None, 0, 90, 24, &dry, "http://gw", false).contains("· dry-run ·"));
        let silent = Gateway::Unavailable(Unavailable::NoAnswer);
        let text = hint_text(None, 0, 80, 24, &silent, "http://gw", false);
        assert!(text.contains("  ○ no API answer (tunnel only) · http://gw"));
        let odd = Gateway::Unavailable(Unavailable::Incompatible);
        let text = hint_text(None, 0, 80, 24, &odd, "http://gw", false);
        assert!(text.contains("  ○ incompatible API response · http://gw"));
        let hostile = Gateway::Reachable {
            state: "up\x1b[2J".into(),
            version: "\x1b]0;x\x07".into(),
            dry_run: false,
            peers_online: 0,
            peers_total: 1,
        };
        for width in [12, 40, 80] {
            let text = hint_text(None, 0, width, 24, &hostile, "http://gw", false);
            assert!(!text.contains('\x1b'));
            assert!(text.lines().all(|line| line.chars().count() < width));
        }
        let colored = Appearance { color: true }.highlight_hint(&text_for(&up), &up);
        assert!(colored.contains("\x1b[32m●"));
        let plain = Appearance { color: false }.highlight_hint(&text_for(&up), &up);
        assert!(!plain.contains('\x1b'));
    }

    #[test]
    fn submitted_frames_are_measured_before_being_erased() {
        let hint = "\n───\n  status\n  shortcuts";
        assert_eq!(submitted_rows("", 80, None), Some(2));
        assert_eq!(submitted_rows("", 80, Some(hint)), Some(5));
        assert_eq!(submitted_rows(&"x".repeat(77), 80, None), Some(2));
        assert_eq!(submitted_rows(&"x".repeat(78), 80, None), Some(3));
        assert_eq!(submitted_rows("/peer add --name é", 80, None), None);
        assert_eq!(submitted_rows("", 0, None), None);
        let plain = Appearance { color: false };
        assert_eq!(plain.input("/status --x"), "/status --x");
        assert!(Appearance { color: true }
            .input("/status --x")
            .ends_with(" --x"));
    }

    #[test]
    fn a_first_ctrl_c_on_an_empty_line_asks_for_a_second() {
        let armed = hint_text(None, 0, 80, 24, &Gateway::Unknown, "local", true);
        assert!(armed.contains("Press Ctrl-C again to exit"));
        let idle = hint_text(None, 0, 80, 24, &Gateway::Unknown, "local", false);
        assert!(!idle.contains("again"));
        assert_eq!(on_interrupt(false, false), Interrupt::Clear);
        assert_eq!(on_interrupt(false, true), Interrupt::Clear);
        assert_eq!(on_interrupt(true, false), Interrupt::Arm);
        assert_eq!(on_interrupt(true, true), Interrupt::Exit);
    }

    fn text_for(gateway: &Gateway) -> String {
        hint_text(None, 0, 80, 24, gateway, "http://gw", false)
    }
}
