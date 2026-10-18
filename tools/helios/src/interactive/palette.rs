//! Command suggestions and keyboard navigation, derived from Clap.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use clap::Command;
use rustyline::{Cmd, ConditionalEventHandler, Event, EventContext, KeyCode, RepeatCount};

const BUILTINS: &[(&str, &str)] = &[
    ("clear", "Clear the terminal and show the welcome screen."),
    ("exit", "Close this administration session."),
    ("quit", "Close this administration session."),
    ("use", "Change the gateway API: /use http://gateway:8080"),
];

pub(super) struct Suggestion {
    pub name: String,
    pub description: String,
    pub replacement: String,
}

pub(super) struct Suggestions {
    pub start: usize,
    pub prefix: String,
    pub entries: Vec<Suggestion>,
    pub active: bool,
}

/// Follow the existing command tree rather than maintaining a second catalog.
pub(super) fn suggestions(tree: &Command, line: &str, pos: usize) -> Suggestions {
    let Some(before) = line.get(..pos) else {
        return Suggestions {
            start: 0,
            prefix: String::new(),
            entries: Vec::new(),
            active: false,
        };
    };
    let start = before.rfind(char::is_whitespace).map_or(0, |i| i + 1);
    let prefix = &before[start..];
    let slash = start == 0 && prefix.starts_with('/');
    let prefix = if slash { &prefix[1..] } else { prefix };
    let mut result = Suggestions {
        start,
        prefix: prefix.to_owned(),
        entries: Vec::new(),
        active: false,
    };
    let Some(parents) = shlex::split(&before[..start]) else {
        return result;
    };
    let mut command = tree;
    let mut option_values = 0;
    let mut positional = false;
    for (index, word) in parents.iter().enumerate() {
        let word = if index == 0 {
            word.strip_prefix('/').unwrap_or(word)
        } else {
            word
        };
        if option_values > 0 {
            option_values -= 1;
            continue;
        }
        if let Some(flag) = word.strip_prefix("--") {
            let (name, value) = flag
                .split_once('=')
                .map_or((flag, None), |(k, v)| (k, Some(v)));
            let Some(arg) = command
                .get_arguments()
                .find(|arg| arg.get_long() == Some(name))
            else {
                return result;
            };
            option_values = arg.get_num_args().map_or(0, |range| range.min_values());
            if value.is_some() {
                option_values = option_values.saturating_sub(1);
            }
        } else if let Some(child) = command.find_subcommand(word) {
            command = child;
        } else {
            // Keep the leaf command's flags available after positional values.
            if command.has_subcommands() {
                return result;
            }
            positional = true;
        }
    }
    if option_values > 0 {
        return result;
    }
    let root = std::ptr::eq(command, tree);
    result.active = prefix.starts_with('-') || (!positional && command.has_subcommands());
    if !prefix.starts_with('-') {
        result.entries.extend(
            command
                .get_subcommands()
                .filter(|child| !(child.is_hide_set() || root && child.get_name() == "shell"))
                .map(|child| {
                    (
                        child.get_name().to_owned(),
                        child
                            .get_about()
                            .map(|text| text.to_string())
                            .unwrap_or_default(),
                    )
                })
                .chain(
                    BUILTINS
                        .iter()
                        .filter(|_| parents.is_empty())
                        .map(|(name, description)| (name.to_string(), description.to_string())),
                )
                .filter(|(name, _)| name.starts_with(prefix))
                .map(|(name, description)| Suggestion {
                    replacement: format!("{}{name} ", if slash { "/" } else { "" }),
                    name,
                    description,
                }),
        );
    } else {
        result.entries.extend(
            command
                .get_arguments()
                .filter(|arg| !arg.is_hide_set())
                .filter_map(|arg| {
                    arg.get_long().map(|name| {
                        (
                            format!("--{name}"),
                            arg.get_help()
                                .map(|text| text.to_string())
                                .unwrap_or_default(),
                        )
                    })
                })
                .filter(|(name, _)| name.starts_with(prefix))
                .map(|(name, description)| Suggestion {
                    replacement: format!("{name} "),
                    name,
                    description,
                }),
        );
    }
    result.entries.sort_by(|a, b| a.name.cmp(&b.name));
    result
}

#[derive(Default)]
pub(super) struct Selection {
    pub index: AtomicUsize,
    pub dismissed: AtomicBool,
}

impl Selection {
    pub fn reset(&self) {
        self.index.store(0, Ordering::Relaxed);
        self.dismissed.store(false, Ordering::Relaxed);
    }

    pub fn visible(&self, line: &str, pos: usize) -> bool {
        line.starts_with('/') && pos == line.len() && !self.dismissed.load(Ordering::Relaxed)
    }

    pub fn index(&self, count: usize) -> usize {
        self.index
            .load(Ordering::Relaxed)
            .min(count.saturating_sub(1))
    }
}

pub(super) struct MenuKeys {
    pub tree: Arc<Command>,
    pub selection: Arc<Selection>,
}

impl MenuKeys {
    fn action(&self, key: KeyCode, line: &str, pos: usize) -> Option<Cmd> {
        if !self.selection.visible(line, pos) {
            return None;
        }
        let matches = suggestions(&self.tree, line, pos);
        if key == KeyCode::Esc {
            self.selection.dismissed.store(true, Ordering::Relaxed);
            return Some(Cmd::Repaint);
        }
        let count = matches.entries.len();
        if count == 0 {
            return None;
        }
        let selected = self.selection.index(count);
        match key {
            KeyCode::Up | KeyCode::Down | KeyCode::BackTab => {
                let next = if key == KeyCode::Down {
                    (selected + 1) % count
                } else {
                    (selected + count - 1) % count
                };
                self.selection.index.store(next, Ordering::Relaxed);
                Some(Cmd::Repaint)
            }
            KeyCode::Tab | KeyCode::Enter => {
                // An explicitly typed command executes normally. Accepting a
                // suggestion only edits the input; it never executes an action.
                if key == KeyCode::Enter
                    && matches
                        .entries
                        .iter()
                        .any(|entry| entry.name == matches.prefix)
                {
                    return None;
                }
                let suffix = &matches.entries[selected].replacement[pos - matches.start..];
                Some(Cmd::Insert(1, suffix.to_owned()))
            }
            _ => None,
        }
    }
}

impl ConditionalEventHandler for MenuKeys {
    fn handle(
        &self,
        event: &Event,
        _: RepeatCount,
        _: bool,
        ctx: &EventContext<'_>,
    ) -> Option<Cmd> {
        self.action(event.get(0)?.0, ctx.line(), ctx.pos())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn keys() -> MenuKeys {
        let mut tree = crate::Cli::command();
        tree.build();
        MenuKeys {
            tree: Arc::new(tree),
            selection: Arc::new(Selection::default()),
        }
    }

    #[test]
    fn slash_lists_commands_and_descriptions_without_reopening_the_shell() {
        let keys = keys();
        let entries = suggestions(&keys.tree, "/", 1).entries;
        for name in ["status", "peer", "firmware", "help", "use", "clear", "quit"] {
            assert!(
                entries
                    .iter()
                    .any(|entry| entry.name == name && !entry.description.is_empty()),
                "{name}"
            );
        }
        assert!(!entries
            .iter()
            .any(|entry| entry.name == "shell" || entry.name.starts_with('-')));
    }

    #[test]
    fn navigation_accepts_a_suggestion_without_executing_it() {
        let keys = keys();
        let entries = suggestions(&keys.tree, "/", 1).entries;
        assert_eq!(keys.action(KeyCode::Down, "/", 1), Some(Cmd::Repaint));
        assert_eq!(
            keys.action(KeyCode::Enter, "/", 1),
            Some(Cmd::Insert(1, entries[1].replacement[1..].to_owned()))
        );
        assert_eq!(keys.action(KeyCode::Up, "/", 1), Some(Cmd::Repaint));
        assert_eq!(keys.action(KeyCode::Up, "/", 1), Some(Cmd::Repaint));
        assert_eq!(keys.selection.index(entries.len()), entries.len() - 1);
    }

    #[test]
    fn escape_restores_history_keys_until_the_input_changes() {
        let keys = keys();
        assert_eq!(keys.action(KeyCode::Esc, "/", 1), Some(Cmd::Repaint));
        assert_eq!(keys.action(KeyCode::Down, "/", 1), None);
        keys.selection.reset();
        assert_eq!(keys.action(KeyCode::Down, "/", 1), Some(Cmd::Repaint));
        assert_eq!(keys.action(KeyCode::Up, "status", 6), None);
        assert_eq!(keys.action(KeyCode::Up, "/peer", 2), None);
    }

    #[test]
    fn exact_commands_execute_and_partial_commands_only_complete() {
        let keys = keys();
        assert_eq!(keys.action(KeyCode::Enter, "/status", 7), None);
        assert_eq!(
            keys.action(KeyCode::Enter, "/sta", 4),
            Some(Cmd::Insert(1, "tus ".into()))
        );
        assert_eq!(
            keys.action(KeyCode::Tab, "/peer li", 8),
            Some(Cmd::Insert(1, "st ".into()))
        );
        assert_eq!(keys.action(KeyCode::Enter, "/no-such-command", 16), None);
    }

    #[test]
    fn option_values_and_positionals_do_not_offer_commands() {
        let keys = keys();
        for line in [
            "/use ",
            "/status ",
            "/peer add --name ",
            "/network load 'file name' ",
            "/peer missing ",
        ] {
            assert!(
                suggestions(&keys.tree, line, line.len()).entries.is_empty(),
                "{line}"
            );
        }
        let line = "/--url http://gateway:8080 peer ";
        assert!(suggestions(&keys.tree, line, line.len())
            .entries
            .iter()
            .any(|entry| entry.name == "list"));
        assert!(suggestions(&keys.tree, "/é", 2).entries.is_empty());
    }
}
