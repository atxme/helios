//! Arguments of the engine mode and the lifecycle that always ends a session.
//!
//! The engine runs elevated, with the UI that launched it as its only client.
//! Every way the session can end goes through [`on_event`], which tears the
//! tunnel down before the process exits. The Win32 calls that observe the
//! parent process live with the launcher; the decisions here are portable.

use std::str::FromStr;
use std::time::Duration;

use crate::serve::ServeOutcome;
use crate::session::SessionToken;

/// Time the engine waits for its client to connect to the pipe.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Exit code for engine arguments that cannot be read. Nothing is started.
pub const BAD_ARGUMENTS: i32 = 2;

/// Exit code for a protected root the engine refuses: its folder is reachable
/// by an account that is not an administrator. Nothing is written under it.
pub const PROTECTED_ROOT_REFUSED: i32 = 3;

const ENGINE_FLAG: &str = "--engine";
const PIPE_PREFIX: &str = r"\\.\pipe\orion-engine-";

/// What the engine was launched with. Its `Debug` never shows the token.
#[derive(Debug)]
pub struct EngineArgs {
    pub pipe: String,
    pub ui_pid: u32,
    /// FILETIME of the UI's creation, to recognise it among its own children.
    pub ui_created_at: u64,
    pub token: SessionToken,
}

impl EngineArgs {
    /// Reads the engine-mode arguments, without the program name.
    ///
    /// `Ok(None)` when `--engine` is absent: the process runs as the UI. With
    /// `--engine`, it must come first and be followed by each of the four
    /// options exactly once, in any order. Anything else is refused.
    pub fn parse(args: &[String]) -> Result<Option<Self>, String> {
        if !args.iter().any(|arg| arg == ENGINE_FLAG) {
            return Ok(None);
        }
        if args.first().map(String::as_str) != Some(ENGINE_FLAG) {
            return Err("`--engine` doit être le premier argument.".to_owned());
        }

        let mut pipe = None;
        let mut ui_pid = None;
        let mut ui_created_at = None;
        let mut token = None;
        let mut rest = args[1..].iter();
        while let Some(option) = rest.next() {
            let name = known_option(option)?;
            let value = rest
                .next()
                .ok_or_else(|| format!("valeur manquante pour {name}."))?;
            match name {
                "--pipe" => {
                    claim(&pipe, name)?;
                    if !value.starts_with(PIPE_PREFIX) {
                        return Err(format!("nom de tube refusé pour {name}."));
                    }
                    pipe = Some(value.clone());
                }
                "--ui-pid" => {
                    claim(&ui_pid, name)?;
                    ui_pid = Some(decimal::<u32>(name, value)?);
                }
                "--ui-created" => {
                    claim(&ui_created_at, name)?;
                    ui_created_at = Some(decimal::<u64>(name, value)?);
                }
                "--token" => {
                    claim(&token, name)?;
                    token = Some(SessionToken::parse(value)?);
                }
                _ => return Err("argument du mode moteur inattendu.".to_owned()),
            }
        }

        Ok(Some(Self {
            pipe: required(pipe, "--pipe")?,
            ui_pid: required(ui_pid, "--ui-pid")?,
            ui_created_at: required(ui_created_at, "--ui-created")?,
            token: required(token, "--token")?,
        }))
    }

    /// The argument list [`EngineArgs::parse`] reads back. Only the launcher uses it.
    pub fn to_args(&self) -> Vec<String> {
        vec![
            ENGINE_FLAG.to_owned(),
            "--pipe".to_owned(),
            self.pipe.clone(),
            "--ui-pid".to_owned(),
            self.ui_pid.to_string(),
            "--ui-created".to_owned(),
            self.ui_created_at.to_string(),
            "--token".to_owned(),
            self.token.as_str().to_owned(),
        ]
    }
}

/// Maps an option name to its fixed spelling. Unknown text is never echoed:
/// it could be the token itself.
fn known_option(option: &str) -> Result<&'static str, String> {
    match option {
        "--pipe" => Ok("--pipe"),
        "--ui-pid" => Ok("--ui-pid"),
        "--ui-created" => Ok("--ui-created"),
        "--token" => Ok("--token"),
        _ => Err("argument inconnu en mode moteur.".to_owned()),
    }
}

fn claim<T>(slot: &Option<T>, name: &str) -> Result<(), String> {
    if slot.is_some() {
        return Err(format!("option répétée : {name}."));
    }
    Ok(())
}

fn decimal<T: FromStr>(name: &str, value: &str) -> Result<T, String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("valeur illisible pour {name}."));
    }
    value
        .parse()
        .map_err(|_| format!("valeur illisible pour {name}."))
}

fn required<T>(value: Option<T>, name: &str) -> Result<T, String> {
    value.ok_or_else(|| format!("option manquante : {name}."))
}

/// What ends the engine's session. Every one of them tears down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleEvent {
    /// The UI process no longer exists.
    ParentMissing,
    /// The UI process exited while the engine watched it.
    ParentExited,
    /// The first frame did not authenticate the UI.
    HelloRefused,
    /// The connected process is not the launching UI.
    ClientRefused,
    /// The UI closed the channel.
    ClientLeft,
    /// The UI asked the engine to stop.
    ShutdownRequested,
    /// The UI stopped reading and critical events found no room.
    EventsOverflowed,
    /// The channel carried something it must not.
    ChannelBroken,
    /// No client connected within [`CONNECT_TIMEOUT`].
    ConnectTimeout,
}

/// What the engine does once an event has happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Disconnect, release the PSK, remove the adapter, then exit.
    TeardownAndExit,
}

/// The engine never serves on after its UI is gone, whatever ended the session.
pub fn on_event(event: LifecycleEvent) -> Action {
    match event {
        LifecycleEvent::ParentMissing
        | LifecycleEvent::ParentExited
        | LifecycleEvent::HelloRefused
        | LifecycleEvent::ClientRefused
        | LifecycleEvent::ClientLeft
        | LifecycleEvent::ShutdownRequested
        | LifecycleEvent::EventsOverflowed
        | LifecycleEvent::ChannelBroken
        | LifecycleEvent::ConnectTimeout => Action::TeardownAndExit,
    }
}

/// Process exit code for an event: 0 only for a requested shutdown.
pub fn exit_code(event: LifecycleEvent) -> i32 {
    match event {
        LifecycleEvent::ShutdownRequested => 0,
        LifecycleEvent::ParentMissing
        | LifecycleEvent::ParentExited
        | LifecycleEvent::HelloRefused
        | LifecycleEvent::ClientRefused
        | LifecycleEvent::ClientLeft
        | LifecycleEvent::EventsOverflowed
        | LifecycleEvent::ChannelBroken
        | LifecycleEvent::ConnectTimeout => 1,
    }
}

impl From<&ServeOutcome> for LifecycleEvent {
    fn from(outcome: &ServeOutcome) -> Self {
        match outcome {
            ServeOutcome::ClientLeft => Self::ClientLeft,
            ServeOutcome::ShutdownRequested => Self::ShutdownRequested,
            ServeOutcome::Refused(_) => Self::HelloRefused,
            ServeOutcome::EventsOverflowed => Self::EventsOverflowed,
            ServeOutcome::Broken(_) => Self::ChannelBroken,
            ServeOutcome::Stopped => Self::ParentExited,
        }
    }
}

/// Whether the process observed at the expected PID is still the UI that launched
/// the engine. A missing process or a different creation time means it is not.
pub fn parent_matches(expected_created_at: u64, observed: Option<u64>) -> bool {
    observed == Some(expected_created_at)
}

#[cfg(test)]
mod tests;
