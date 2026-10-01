//! Line editing and completion over the canonical administration commands.

use std::io::{self, BufRead, IsTerminal, Write};

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser};
use reqwest::Client;
use rustyline::{
    completion::{Completer, Pair},
    error::ReadlineError,
    highlight::Highlighter,
    hint::Hinter,
    history::DefaultHistory,
    validate::Validator,
    Context as LineContext, Editor, Helper,
};

use crate::{Cli, Cmd};

struct Commands;
impl Helper for Commands {}
impl Highlighter for Commands {}
impl Validator for Commands {}
impl Hinter for Commands {
    type Hint = String;
}
impl Completer for Commands {
    type Candidate = Pair;
    fn complete(
        &self,
        line: &str,
        pos: usize,
        _: &LineContext<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        Ok(completions(line, pos))
    }
}

/// Follow Clap's command tree, including nested commands and flags.
fn completions(line: &str, pos: usize) -> (usize, Vec<Pair>) {
    let before = &line[..pos];
    let start = before
        .rfind(char::is_whitespace)
        .map_or(0, |index| index + 1);
    let prefix = &before[start..];
    let slash = start == 0 && prefix.starts_with('/');
    let prefix = prefix.strip_prefix('/').unwrap_or(prefix);
    let mut command = Cli::command();
    command.build();
    let parents = shlex::split(&before[..start]).unwrap_or_default();
    for word in &parents {
        let word = word.strip_prefix('/').unwrap_or(word);
        if let Some(child) = command.find_subcommand(word) {
            command = child.clone();
        }
    }
    let mut names: Vec<String> = command
        .get_subcommands()
        .filter(|child| !child.is_hide_set())
        .map(|child| child.get_name().to_owned())
        .collect();
    names.extend(
        command
            .get_arguments()
            .filter_map(|arg| arg.get_long().map(|name| format!("--{name}"))),
    );
    if parents.is_empty() {
        names.extend(["help", "quit", "exit", "use"].map(str::to_owned));
    }
    names.sort();
    names.dedup();
    let candidates = names
        .into_iter()
        .filter(|name| name.starts_with(prefix))
        .map(|name| Pair {
            display: name.clone(),
            replacement: format!("{}{name} ", if slash { "/" } else { "" }),
        })
        .collect();
    (start, candidates)
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
    let mut editor = Editor::<Commands, DefaultHistory>::new()?;
    editor.set_helper(Some(Commands));
    let mut base = base.to_owned();
    println!("Helios · gateway administration\nGateway API: {base}");
    println!("Tab completes commands and flags; ↑/↓ recalls this session. /help · /quit");
    println!("OS maintenance is local. Firmware targets an explicit SSH gateway.");
    loop {
        let line = match editor.readline("helios> ") {
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
        if args[0] == "use" {
            if args.len() != 2 {
                eprintln!("usage: /use http://gateway:8080");
                continue;
            }
            match reqwest::Url::parse(&args[1]) {
                Ok(url) if matches!(url.scheme(), "http" | "https") && url.host_str().is_some() => {
                    base = args[1].trim_end_matches('/').to_owned();
                    println!("Gateway API: {base}");
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
        if let Err(error) =
            crate::execute_command(client, cli.url.trim_end_matches('/'), command).await
        {
            eprintln!("{error:#}");
        }
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
            completions(line, line.len())
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
