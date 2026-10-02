//! Line editing and completion over the canonical administration commands.

use std::{
    borrow::Cow,
    cell::RefCell,
    io::{self, BufRead, IsTerminal, Write},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser};
use reqwest::Client;
use rustyline::{
    completion::{Completer, Pair},
    error::ReadlineError,
    highlight::{CmdKind, Highlighter},
    hint::{Hint, Hinter},
    history::DefaultHistory,
    validate::Validator,
    Context as LineContext, Editor, EventHandler, Helper, KeyCode, KeyEvent, Modifiers,
};

use crate::{Cli, Cmd};

mod palette;
mod presentation;

use palette::{suggestions, MenuKeys, Selection};
use presentation::{dimensions, hint_text, Appearance, Gateway};

/// Bounds the status-line refresh so an unreachable gateway cannot stall input.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

struct Commands {
    tree: Arc<clap::Command>,
    selection: Arc<Selection>,
    previous_line: RefCell<String>,
    appearance: Appearance,
    dimensions: (usize, usize),
    gateway: Gateway,
    base: String,
}

impl Helper for Commands {}
impl Validator for Commands {}
impl Highlighter for Commands {
    fn highlight_prompt<'b, 's: 'b, 'p: 'b>(&'s self, prompt: &'p str, _: bool) -> Cow<'b, str> {
        Cow::Owned(self.appearance.prompt(prompt))
    }

    fn highlight_hint<'h>(&self, hint: &'h str) -> Cow<'h, str> {
        Cow::Owned(self.appearance.highlight_hint(hint, &self.gateway))
    }

    fn highlight<'l>(&self, line: &'l str, _: usize) -> Cow<'l, str> {
        if line.starts_with('/') && self.appearance.color {
            let end = line.find(char::is_whitespace).unwrap_or(line.len());
            Cow::Owned(format!(
                "{}{}",
                self.appearance.prompt(&line[..end]),
                &line[end..]
            ))
        } else {
            Cow::Borrowed(line)
        }
    }

    fn highlight_char(&self, _: &str, _: usize, _: CmdKind) -> bool {
        // Redraw after cursor movement too, so the menu never obscures editing.
        true
    }
}

struct MenuHint(String);
impl Hint for MenuHint {
    fn display(&self) -> &str {
        &self.0
    }
    fn completion(&self) -> Option<&str> {
        None
    }
}

impl Hinter for Commands {
    type Hint = MenuHint;

    fn hint(&self, line: &str, pos: usize, _: &LineContext<'_>) -> Option<MenuHint> {
        let mut previous = self.previous_line.borrow_mut();
        if *previous != line {
            self.selection.reset();
            line.clone_into(&mut previous);
        }
        let matches = self
            .selection
            .visible(line, pos)
            .then(|| suggestions(&self.tree, line, pos))
            .filter(|matches| matches.active);
        let selected = matches
            .as_ref()
            .map_or(0, |matches| self.selection.index(matches.entries.len()));
        let (width, height) = dimensions(self.dimensions);
        Some(MenuHint(hint_text(
            matches.as_ref(),
            selected,
            width,
            height,
            &self.gateway,
            &self.base,
        )))
    }
}

impl Completer for Commands {
    type Candidate = Pair;
    fn complete(
        &self,
        line: &str,
        pos: usize,
        _: &LineContext<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        Ok(completions(&self.tree, line, pos))
    }
}

fn completions(tree: &clap::Command, line: &str, pos: usize) -> (usize, Vec<Pair>) {
    let matches = suggestions(tree, line, pos);
    (
        matches.start,
        matches
            .entries
            .into_iter()
            .map(|entry| Pair {
                display: entry.name,
                replacement: entry.replacement,
            })
            .collect(),
    )
}

/// Subcommand chain of a parsed line, for the output block header.
fn command_path(tree: &clap::Command, args: &[String]) -> String {
    let mut command = tree;
    let mut path = Vec::new();
    let mut words = args.iter();
    while let Some(word) = words.next() {
        if let Some(flag) = word.strip_prefix("--") {
            let takes_value = command
                .get_arguments()
                .find(|arg| arg.get_long() == Some(flag))
                .and_then(|arg| arg.get_num_args())
                .is_some_and(|range| range.min_values() > 0);
            if takes_value {
                words.next();
            }
        } else if let Some(child) = command.find_subcommand(word) {
            path.push(child.get_name());
            command = child;
        } else if !word.starts_with('-') {
            break;
        }
    }
    path.join(" ")
}

async fn probe(client: &Client, base: &str) -> Gateway {
    match tokio::time::timeout(PROBE_TIMEOUT, crate::api_status(client, base)).await {
        Ok(Ok(status)) => Gateway::Reachable {
            state: status.state,
            version: status.version,
            dry_run: status.dry_run,
        },
        // Shown as unavailable; the commands themselves still report errors.
        Ok(Err(_)) | Err(_) => Gateway::Unavailable,
    }
}

async fn refresh(editor: &mut Editor<Commands, DefaultHistory>, client: &Client, base: &str) {
    let gateway = probe(client, base).await;
    if let Some(helper) = editor.helper_mut() {
        helper.gateway = gateway;
        base.clone_into(&mut helper.base);
    }
}

fn words(line: &str) -> Result<Vec<String>> {
    let mut words = shlex::split(line).context("unclosed quote or trailing escape")?;
    if let Some(first) = words.first_mut() {
        if let Some(word) = first.strip_prefix('/') {
            *first = word.to_owned();
        }
    }
    Ok(words)
}

pub async fn run(client: &Client, base: &str) -> Result<()> {
    anyhow::ensure!(
        io::stdin().is_terminal() && io::stdout().is_terminal(),
        "the interactive shell requires a terminal; use `helios --help` for scripted commands"
    );
    // Rustyline falls back to an unedited input stream for these terminal
    // types. Completion is part of this interface, so refuse that fallback.
    let term = std::env::var("TERM").unwrap_or_default();
    anyhow::ensure!(
        supports_editing(&term),
        "TERM={term} does not support line editing/completion; open a supported terminal or use explicit helios commands"
    );
    // Distinguish a standalone Escape from an arrow/Alt sequence without
    // waiting indefinitely for another key (Rustyline's Emacs default).
    let config = rustyline::Config::builder()
        .keyseq_timeout(Some(250))
        .build();
    let mut editor = Editor::<Commands, DefaultHistory>::with_config(config)?;
    let mut tree = Cli::command();
    tree.build();
    let tree = Arc::new(tree);
    let selection = Arc::new(Selection::default());
    let appearance = Appearance {
        color: std::env::var_os("NO_COLOR").is_none(),
    };
    let size = editor
        .dimensions()
        .map(|(w, h)| (w as usize, h as usize))
        .unwrap_or((80, 24));
    editor.set_helper(Some(Commands {
        tree: tree.clone(),
        selection: selection.clone(),
        previous_line: RefCell::new(String::new()),
        appearance,
        dimensions: size,
        gateway: Gateway::Unknown,
        base: base.to_owned(),
    }));
    for key in [
        KeyCode::Up,
        KeyCode::Down,
        KeyCode::Tab,
        KeyCode::BackTab,
        KeyCode::Enter,
        KeyCode::Esc,
    ] {
        let modifiers = if key == KeyCode::BackTab {
            Modifiers::SHIFT
        } else {
            Modifiers::NONE
        };
        editor.bind_sequence(
            KeyEvent(key, modifiers),
            EventHandler::Conditional(Box::new(MenuKeys {
                tree: tree.clone(),
                selection: selection.clone(),
            })),
        );
    }
    let mut base = base.to_owned();
    println!("{}", appearance.welcome(&base, dimensions(size).0));
    refresh(&mut editor, client, &base).await;
    loop {
        selection.reset();
        if let Some(helper) = editor.helper_mut() {
            helper.previous_line.get_mut().clear();
        }
        println!("{}", appearance.divider(dimensions(size).0));
        let line = match editor.readline("❯ ") {
            Ok(line) => line,
            Err(ReadlineError::Interrupted) => continue,
            Err(ReadlineError::Eof) => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        let args = match words(&line) {
            Ok(args) if !args.is_empty() => args,
            Ok(_) => continue,
            Err(error) => {
                eprintln!("{error:#}");
                continue;
            }
        };
        if matches!(args[0].as_str(), "quit" | "exit") && args.len() == 1 {
            return Ok(());
        }
        if args[0] == "clear" {
            if args.len() != 1 {
                eprintln!("usage: /clear");
                continue;
            }
            editor.clear_screen()?;
            println!("{}", appearance.welcome(&base, dimensions(size).0));
            continue;
        }
        if args[0] == "use" {
            if args.len() != 2 {
                eprintln!("usage: /use http://gateway:8080");
                continue;
            }
            match reqwest::Url::parse(&args[1]) {
                Ok(url) if matches!(url.scheme(), "http" | "https") && url.host_str().is_some() => {
                    base = args[1].trim_end_matches('/').to_owned();
                    println!("{}", appearance.welcome(&base, dimensions(size).0));
                    refresh(&mut editor, client, &base).await;
                }
                _ => eprintln!("expected an HTTP(S) gateway URL"),
            }
            continue;
        }
        let mut argv = vec!["helios".to_owned()];
        if !args
            .iter()
            .any(|arg| arg == "--url" || arg.starts_with("--url="))
        {
            argv.extend(["--url".to_owned(), base.clone()]);
        }
        let path = command_path(&tree, &args);
        argv.extend(args);
        let cli = match Cli::try_parse_from(argv) {
            Ok(cli) => cli,
            Err(error) => {
                error.print()?;
                continue;
            }
        };
        let Some(command) = cli.command else { continue };
        if matches!(command, Cmd::Shell) {
            eprintln!("the administration shell is already open");
            continue;
        }
        // History stays in memory. Campaign arguments may contain private keys.
        if !matches!(command, Cmd::Campaign { .. }) {
            editor.add_history_entry(&line)?;
        }
        let width = dimensions(size).0;
        println!("{}", appearance.command_header(&path, width));
        let started = Instant::now();
        match crate::execute_command(client, cli.url.trim_end_matches('/'), command).await {
            Ok(()) => println!("{}", appearance.command_success(started.elapsed())),
            Err(error) => eprintln!(
                "{}",
                appearance.command_failure(&format!("{error:#}"), width)
            ),
        }
        refresh(&mut editor, client, &base).await;
    }
}

fn supports_editing(term: &str) -> bool {
    !["dumb", "cons25", "emacs"]
        .iter()
        .any(|unsupported| term.eq_ignore_ascii_case(unsupported))
}

pub(super) fn confirm(label: &str) -> Result<bool> {
    print!("{label} [y/N] ");
    io::stdout()
        .flush()
        .context("writing the terminal prompt")?;
    let mut answer = String::new();
    io::stdin().lock().read_line(&mut answer)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn menu_hints_filter_reset_selection_and_never_complete_footer_text() {
        let mut tree = Cli::command();
        tree.build();
        let selection = Arc::new(Selection::default());
        let helper = Commands {
            tree: Arc::new(tree),
            selection: selection.clone(),
            previous_line: RefCell::new(String::new()),
            appearance: Appearance { color: false },
            dimensions: (80, 24),
            gateway: Gateway::Unknown,
            base: "http://gw".to_owned(),
        };
        let history = DefaultHistory::new();
        let ctx = LineContext::new(&history);
        let hint = helper.hint("/", 1, &ctx).unwrap();
        assert!(hint.display().contains("/app-update"));
        assert_eq!(hint.completion(), None);
        selection
            .index
            .store(5, std::sync::atomic::Ordering::Relaxed);
        let hint = helper.hint("/sta", 4, &ctx).unwrap();
        assert!(hint.display().contains("/status"));
        assert!(!hint.display().contains("/app-update"));
        assert_eq!(selection.index(10), 0);
        for line in ["/status ", "/use ", "/peer add --name "] {
            assert!(!helper
                .hint(line, line.len(), &ctx)
                .unwrap()
                .display()
                .contains("No matching command"));
        }
    }

    #[test]
    fn command_headers_name_the_command_without_echoing_argument_values() {
        let mut tree = Cli::command();
        tree.build();
        let path = |line: &str| command_path(&tree, &words(line).unwrap());
        assert_eq!(path("/status"), "status");
        assert_eq!(path("/peer add --name laptop"), "peer add");
        assert_eq!(path("firmware list --ssh-target admin@gw"), "firmware list");
        assert_eq!(path("/campaign --client-key secret"), "campaign");
        assert_eq!(path("--url http://gw status"), "status");
    }

    #[test]
    fn unsupported_terminals_cannot_silently_disable_completion() {
        for term in ["dumb", "DUMB", "cons25", "emacs"] {
            assert!(!supports_editing(term));
        }
        assert!(supports_editing("xterm-256color"));
    }
    #[test]
    fn quoted_arguments_and_slash_commands_use_the_script_parser() {
        let mut args = vec!["helios".to_owned()];
        args.extend(words("/network load 'a directory/network.toml'").unwrap());
        assert!(matches!(
            Cli::try_parse_from(args).unwrap().command,
            Some(Cmd::Network {
                command: crate::NetworkCmd::Load { .. }
            })
        ));
        assert!(words("peer add --name 'unfinished").is_err());
    }
    #[test]
    fn completion_covers_the_full_command_tree_and_nested_flags() {
        let names = |line: &str| {
            let mut tree = Cli::command();
            tree.build();
            completions(&tree, line, line.len())
                .1
                .into_iter()
                .map(|p| p.replacement)
                .collect::<Vec<_>>()
        };
        assert!(names("/sta").contains(&"/status ".into()));
        assert!(names("/peer ").contains(&"add ".into()));
        assert!(names("/peer add --na").contains(&"--name ".into()));
        assert!(names("/firmware ").contains(&"list ".into()));
        assert!(names("/profile ").contains(&"check ".into()));
        assert!(names("/key-nego ").contains(&"init-client-ca ".into()));
    }
}
