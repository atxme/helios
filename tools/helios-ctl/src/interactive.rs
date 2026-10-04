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

use crate::{transport::Api, Cli, Cmd};

mod palette;
mod presentation;

use palette::{suggestions, MenuKeys, Selection};
use presentation::{dimensions, hint_text, Appearance, Gateway, Unavailable};

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
    last_hint: RefCell<String>,
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
        Cow::Owned(self.appearance.input(line))
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
        let hint = hint_text(
            matches.as_ref(),
            selected,
            width,
            height,
            &self.gateway,
            &self.base,
        );
        hint.clone_into(&mut self.last_hint.borrow_mut());
        Some(MenuHint(hint))
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
        // The commands themselves still report the full error.
        Ok(Err(error))
            if error.chain().any(|cause| {
                cause
                    .downcast_ref::<reqwest::Error>()
                    .is_some_and(reqwest::Error::is_decode)
            }) =>
        {
            Gateway::Unavailable(Unavailable::Incompatible)
        }
        Ok(Err(_)) | Err(_) => Gateway::Unavailable(Unavailable::NoAnswer),
    }
}

fn erase_last_frame(editor: &Editor<Commands, DefaultHistory>, size: (usize, usize)) {
    if let Some(helper) = editor.helper() {
        let line = helper.previous_line.borrow().clone();
        let hint = helper.last_hint.borrow().clone();
        erase_frame(&line, Some(&hint), size);
    }
}

/// Erase the divider, input and optional hint above the cursor. Returns
/// whether the frame was erased; unmeasurable input stays on screen.
fn erase_frame(line: &str, hint: Option<&str>, size: (usize, usize)) -> bool {
    let width = dimensions(size).0;
    let Some(rows) = presentation::submitted_rows(line, width, hint) else {
        return false;
    };
    print!("\x1b[{rows}A\r\x1b[J");
    io::stdout().flush().is_ok()
}

/// The line editor owns SIGINT for its whole lifetime, so a stuck command
/// (an unreachable API, a WebSocket that never connects) would otherwise
/// swallow every Ctrl-C. `None` means the command was abandoned.
async fn interruptible(
    command: impl std::future::Future<Output = Result<()>>,
    interrupt: impl std::future::Future<Output = ()>,
) -> Option<Result<()>> {
    tokio::select! {
        result = command => Some(result),
        () = interrupt => None,
    }
}

async fn ctrl_c() {
    if tokio::signal::ctrl_c().await.is_err() {
        // Without a handler the command simply runs to completion, as before.
        std::future::pending::<()>().await;
    }
}

async fn refresh(editor: &mut Editor<Commands, DefaultHistory>, api: &Api) {
    let gateway = probe(&api.client, &api.base).await;
    if let Some(helper) = editor.helper_mut() {
        helper.gateway = gateway;
        helper.base = api.label();
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

pub async fn run(mut api: Api) -> Result<()> {
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
        base: api.label(),
        last_hint: RefCell::new(String::new()),
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
    println!(
        "{}",
        appearance.welcome(&api.describe(), dimensions(size).0)
    );
    refresh(&mut editor, &api).await;
    loop {
        selection.reset();
        if let Some(helper) = editor.helper_mut() {
            helper.previous_line.get_mut().clear();
        }
        println!("{}", appearance.divider(dimensions(size).0));
        let line = match editor.readline("❯ ") {
            Ok(line) => {
                // Replace the input frame with a transcript line; an empty
                // line leaves nothing behind.
                if erase_frame(&line, None, size) && !line.trim().is_empty() {
                    println!("{}{}", appearance.prompt("❯ "), appearance.input(&line));
                }
                line
            }
            // Ctrl-C leaves the cursor below the hint it kept on screen.
            Err(ReadlineError::Interrupted) => {
                erase_last_frame(&editor, size);
                continue;
            }
            // Ctrl-D only ends an empty line, with the cursor under the prompt.
            Err(ReadlineError::Eof) => {
                erase_frame("", None, size);
                return Ok(());
            }
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
            println!(
                "{}",
                appearance.welcome(&api.describe(), dimensions(size).0)
            );
            continue;
        }
        if args[0] == "use" {
            if args.len() != 2 {
                eprintln!("usage: /use http://gateway:8080");
                continue;
            }
            match reqwest::Url::parse(&args[1]) {
                Ok(url) if matches!(url.scheme(), "http" | "https") && url.host_str().is_some() => {
                    match Api::tcp(&args[1]) {
                        Ok(tcp) => api = tcp,
                        Err(error) => {
                            eprintln!("{error:#}");
                            continue;
                        }
                    }
                    println!(
                        "{}",
                        appearance.welcome(&api.describe(), dimensions(size).0)
                    );
                    refresh(&mut editor, &api).await;
                }
                _ => eprintln!("expected an HTTP(S) gateway URL"),
            }
            continue;
        }
        // `--url` on the line targets that TCP API for this command only.
        let explicit_url = args
            .iter()
            .any(|arg| arg == "--url" || arg.starts_with("--url="));
        let mut argv = vec!["helios".to_owned()];
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
        let one_off = match (explicit_url, cli.url.as_deref()) {
            (true, Some(url)) => match Api::tcp(url) {
                Ok(tcp) => Some(tcp),
                Err(error) => {
                    eprintln!(
                        "{}",
                        appearance.command_failure(&format!("{error:#}"), width)
                    );
                    continue;
                }
            },
            _ => None,
        };
        let command = crate::execute_command(one_off.as_ref().unwrap_or(&api), command);
        match interruptible(command, ctrl_c()).await {
            Some(Ok(())) => println!("{}", appearance.command_success(started.elapsed())),
            Some(Err(error)) => eprintln!(
                "{}",
                appearance.command_failure(&format!("{error:#}"), width)
            ),
            None => eprintln!("\n{}", appearance.command_interrupted(width)),
        }
        refresh(&mut editor, &api).await;
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
            last_hint: RefCell::new(String::new()),
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

    #[tokio::test]
    async fn ctrl_c_abandons_a_stuck_command_and_returns_to_the_prompt() {
        let stuck = std::future::pending::<Result<()>>();
        assert!(interruptible(stuck, async {}).await.is_none());
        let done = async { Ok(()) };
        let never = std::future::pending::<()>();
        assert!(matches!(interruptible(done, never).await, Some(Ok(()))));
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
