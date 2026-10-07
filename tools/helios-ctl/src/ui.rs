//! One look for every command's output: titles, aligned fields, tables,
//! status marks and human-readable quantities.
//!
//! Color follows the terminal: none when `NO_COLOR` is set or when stdout is
//! not a terminal, so scripts and pipes get plain text. Gateway-supplied text
//! goes through [`clean`] before reaching the terminal.

use std::io::IsTerminal;

/// Width of the label column in field lists.
const LABEL: usize = 13;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Plain,
    Bold,
    Dim,
    Good,
    Warn,
    Bad,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Ok,
    Warn,
    Fail,
}

#[derive(Debug, Clone)]
pub struct Cell {
    pub text: String,
    pub tone: Tone,
}

impl Cell {
    pub fn new(text: impl AsRef<str>, tone: Tone) -> Self {
        Self {
            text: clean(text.as_ref()),
            tone,
        }
    }

    pub fn plain(text: impl AsRef<str>) -> Self {
        Self::new(text, Tone::Plain)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Ui {
    pub color: bool,
    /// Columns available, when stdout is a terminal.
    pub width: Option<usize>,
}

impl Ui {
    pub fn detect() -> Self {
        let terminal = std::io::stdout().is_terminal();
        Self {
            color: terminal && std::env::var_os("NO_COLOR").is_none(),
            width: if terminal {
                terminal_size().map(|(columns, _)| columns)
            } else {
                None
            },
        }
    }

    #[cfg(test)]
    pub fn plain(width: Option<usize>) -> Self {
        Self {
            color: false,
            width,
        }
    }

    pub fn paint(&self, text: &str, tone: Tone) -> String {
        let code = match tone {
            Tone::Plain => return text.to_owned(),
            Tone::Bold => "1",
            Tone::Dim => "2",
            Tone::Good => "32",
            Tone::Warn => "33",
            Tone::Bad => "31",
        };
        if self.color {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_owned()
        }
    }

    /// `\n  Title  subtitle\n\n`.
    pub fn title(&self, title: &str, subtitle: &str) -> String {
        let subtitle = self.fit(&clean(subtitle), 2 + title.chars().count() + 2);
        let subtitle = if subtitle.is_empty() {
            String::new()
        } else {
            format!("  {}", self.paint(&subtitle, Tone::Dim))
        };
        format!("\n  {}{subtitle}\n\n", self.paint(title, Tone::Bold))
    }

    /// A section heading inside a command's output; the caller decides the
    /// blank line before it.
    pub fn section(&self, title: &str, subtitle: &str) -> String {
        let subtitle = self.fit(&clean(subtitle), 2 + title.chars().count() + 2);
        let subtitle = if subtitle.is_empty() {
            String::new()
        } else {
            format!("  {}", self.paint(&subtitle, Tone::Dim))
        };
        format!("  {}{subtitle}\n", self.paint(title, Tone::Bold))
    }

    /// `  Label         value`, the value cleaned and fitted to the terminal.
    pub fn field(&self, label: &str, value: &str) -> String {
        self.field_toned(label, value, Tone::Plain)
    }

    pub fn field_toned(&self, label: &str, value: &str, tone: Tone) -> String {
        let value = self.fit(&clean(value), 2 + LABEL + 1);
        format!(
            "  {} {}\n",
            self.paint(&format!("{label:<LABEL$}"), Tone::Dim),
            self.paint(&value, tone)
        )
    }

    /// A dim explanatory line.
    pub fn note(&self, text: &str) -> String {
        let text = self.fit(&clean(text), 2);
        format!("  {}\n", self.paint(&text, Tone::Dim))
    }

    pub fn mark(&self, level: Level) -> String {
        match level {
            Level::Ok => self.paint("✓", Tone::Good),
            Level::Warn => self.paint("!", Tone::Warn),
            Level::Fail => self.paint("✗", Tone::Bad),
        }
    }

    /// Columns sized to their content; the last one is cut to the terminal
    /// width. Headers are dim, so the data carries the eye.
    pub fn table(&self, indent: usize, headers: &[&str], rows: &[Vec<Cell>]) -> String {
        let columns = headers.len();
        let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
        for row in rows {
            for (index, cell) in row.iter().enumerate().take(columns) {
                widths[index] = widths[index].max(cell.text.chars().count());
            }
        }
        let pad = " ".repeat(indent);
        let render = |cells: Vec<(String, Tone)>| {
            let mut line = pad.clone();
            let mut used = indent;
            for (index, (text, tone)) in cells.into_iter().enumerate() {
                let last = index + 1 == columns;
                let text = if last {
                    self.fit(&text, used)
                } else {
                    format!("{text:<width$}", width = widths[index])
                };
                used += widths[index] + 2;
                line.push_str(&self.paint(&text, tone));
                if !last {
                    line.push_str("  ");
                }
            }
            format!("{}\n", line.trim_end())
        };
        let mut out = render(
            headers
                .iter()
                .map(|header| ((*header).to_owned(), Tone::Dim))
                .collect(),
        );
        for row in rows {
            out.push_str(&render(
                row.iter()
                    .map(|cell| (cell.text.clone(), cell.tone))
                    .collect(),
            ));
        }
        out
    }

    /// Cuts `text` so that, printed after `used` columns, it fits the line.
    pub fn fit(&self, text: &str, used: usize) -> String {
        let Some(width) = self.width else {
            return text.to_owned();
        };
        let room = width.saturating_sub(used + 1);
        if text.chars().count() <= room {
            return text.to_owned();
        }
        if room == 0 {
            return String::new();
        }
        text.chars()
            .take(room - 1)
            .chain(std::iter::once('…'))
            .collect()
    }
}

/// Tone of a heliosd tunnel state.
pub fn state_tone(state: &str) -> Tone {
    match state {
        "up" => Tone::Good,
        "connecting" | "captive_portal" => Tone::Warn,
        "failed" => Tone::Bad,
        _ => Tone::Dim,
    }
}

/// heliosd's `connecting` is a ready gateway with no client handshake yet.
pub fn state_label(state: &str) -> String {
    match state {
        "connecting" => "waiting for clients".to_owned(),
        "captive_portal" => "captive portal".to_owned(),
        other => clean(other),
    }
}

/// Gateway-supplied text is data, never terminal control sequences.
pub fn clean(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).collect()
}

/// The first characters of a key or fingerprint, enough to tell two apart.
pub fn short(value: &str, length: usize) -> String {
    clean(value).chars().take(length).collect()
}

pub fn percent(part: u64, total: u64) -> u64 {
    part.saturating_mul(100).checked_div(total).unwrap_or(0)
}

pub fn bytes(value: u64) -> String {
    const UNITS: [&str; 4] = ["KiB", "MiB", "GiB", "TiB"];
    if value < 1024 {
        return format!("{value} B");
    }
    let mut amount = value as f64 / 1024.0;
    let mut unit = 0;
    while amount >= 1024.0 && unit < UNITS.len() - 1 {
        amount /= 1024.0;
        unit += 1;
    }
    format!("{amount:.1} {}", UNITS[unit])
}

pub fn duration(seconds: u64) -> String {
    let (days, hours, minutes) = (
        seconds / 86_400,
        seconds % 86_400 / 3_600,
        seconds % 3_600 / 60,
    );
    if days > 0 {
        format!("{days} d {hours:02} h")
    } else if hours > 0 {
        format!("{hours} h {minutes:02} min")
    } else if minutes > 0 {
        format!("{minutes} min {:02} s", seconds % 60)
    } else {
        format!("{seconds} s")
    }
}

/// An instant against the gateway's clock (`now`), never the operator's.
pub fn relative(at: u64, now: u64) -> String {
    if at >= now {
        format!("in {}", duration(at - now))
    } else {
        format!("{} ago", duration(now - at))
    }
}

pub fn terminal_size() -> Option<(usize, usize)> {
    #[cfg(target_os = "linux")]
    {
        let mut size = libc::winsize {
            ws_row: 0,
            ws_col: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: ioctl writes only to this initialized winsize.
        // Some pseudo-terminals report columns but no rows.
        if unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut size) } == 0
            && size.ws_col > 0
        {
            let rows = if size.ws_row > 0 { size.ws_row } else { 24 };
            return Some((usize::from(size.ws_col), usize::from(rows)));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantities_read_like_a_person_wrote_them() {
        assert_eq!(bytes(2 * 1024 * 1024 * 1024), "2.0 GiB");
        assert_eq!(bytes(512 * 1024), "512.0 KiB");
        assert_eq!(bytes(12), "12 B");
        assert_eq!(duration(3 * 86_400 + 4 * 3_600 + 120), "3 d 04 h");
        assert_eq!(duration(3_720), "1 h 02 min");
        assert_eq!(duration(42), "42 s");
        assert_eq!(relative(1_000_000 + 5 * 86_400, 1_000_000), "in 5 d 00 h");
        assert_eq!(relative(1_000_000 - 3_600, 1_000_000), "1 h 00 min ago");
        assert_eq!(percent(5, 0), 0);
    }

    #[test]
    fn tables_align_columns_and_fit_the_last_one() {
        let ui = Ui::plain(Some(30));
        let rows = vec![
            vec![
                Cell::plain("alpha"),
                Cell::plain("a much longer description"),
            ],
            vec![Cell::plain("b\x1b[2J"), Cell::plain("short")],
        ];
        let text = ui.table(2, &["NAME", "NOTE"], &rows);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "  NAME   NOTE");
        assert!(lines[1].starts_with("  alpha  a much"));
        assert!(lines[1].ends_with('…'));
        assert_eq!(lines[2], "  b[2J   short");
        assert!(lines.iter().all(|line| line.chars().count() < 30));
    }

    #[test]
    fn plain_output_has_no_escape_and_colored_output_does() {
        let plain = Ui::plain(None);
        let colored = Ui {
            color: true,
            width: None,
        };
        assert!(!plain.field("Label", "value\x1b[2J").contains('\x1b'));
        assert!(!plain.title("Title", "sub").contains('\x1b'));
        assert!(colored.mark(Level::Fail).contains("\x1b[31m"));
        assert_eq!(plain.field("Uplinks", "eth0"), "  Uplinks       eth0\n");
    }
}
