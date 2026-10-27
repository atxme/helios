use super::*;

#[test]
fn a_shell_word_survives_quotes_and_spaces() {
    assert_eq!(shell_word("laptop-alice"), "laptop-alice");
    assert_eq!(shell_word("poste d'alice"), "'poste d'\\''alice'");
}

#[test]
fn the_command_line_quotes_names() {
    let line = admission_command_line(
        "poste d'alice",
        "Zm9v/+=",
        "/tmp/a b/tls.der",
        "/tmp/pq.json",
    );
    assert_eq!(
        line,
        "heliosd peer add --name 'poste d'\\''alice' --public-key Zm9v/+= \
         --certificate '/tmp/a b/tls.der' --pq-certificate /tmp/pq.json --minimum-mode ml-kem"
    );
}
