//! The line an operator pastes on the gateway to admit a client.
//!
//! The requested name is the client's choice. It reaches a shell on the
//! operator's side, so every word goes through [`shell_word`]: `$(…)` in a name
//! would otherwise run on the machine that holds the hardware credential.

/// One POSIX shell word, quoted only when it needs to be.
pub fn shell_word(value: &str) -> String {
    let plain = !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./=:+,@".contains(c));
    if plain {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

/// The `heliosd peer add` line that admits a client from its two leaves.
pub fn admission_command_line(
    name: &str,
    public_key: &str,
    tls_file: &str,
    pq_file: &str,
) -> String {
    format!(
        "heliosd peer add --name {} --public-key {} --certificate {} --pq-certificate {} \
         --minimum-mode ml-kem",
        shell_word(name),
        shell_word(public_key),
        shell_word(tls_file),
        shell_word(pq_file),
    )
}

#[cfg(test)]
mod tests;
