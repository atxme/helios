//! Reading the document itself: which parser its name selects, which
//! encodings are decoded, and the size ceiling.

use super::fixtures::{temp_directory, CLIENT_PRIVATE, GATEWAY_PUBLIC};
use crate::profile_import::{
    parse_profile_import, read_profile_document, read_profile_import_path, MAX_PROFILE_IMPORT_BYTES,
};

/// `.orion` is the extension the tooling distributes, and `.orionprofile`
/// the one it distributed until August 2026: recognizing either must not
/// depend on the first character surviving the trip.
#[test]
fn the_orion_suffixes_select_the_orion_parser() {
    let raw = format!(
        r#"{{
            "format": "orion-profile",
            "version": 1,
            "profile": {{
                "name": "portable",
                "endpoint": "vpn.example.net:51820",
                "private_key": "{CLIENT_PRIVATE}",
                "peer_public_key": "{GATEWAY_PUBLIC}",
                "address": "100.64.1.2/32"
            }}
        }}"#
    );

    // Leading blank lines: the head no longer decides, the suffix does.
    let padded = format!("\n\n{raw}");
    for name in [
        "poste-windows.orion",
        // Windows matches an extension without regard to case, and a
        // document named `.Orion` is the same document.
        "POSTE-WINDOWS.ORION",
        // Written before August 2026, still read.
        "poste-windows.orionprofile",
        "POSTE-WINDOWS.ORIONPROFILE",
    ] {
        assert_eq!(
            parse_profile_import(&padded, name).unwrap().profile.name,
            "portable",
            "suffixe refusé : {name}"
        );
    }
}

/// A document is carried by hand from one machine to another, and that
/// trip re-encodes it: PowerShell's `Out-File` writes UTF-16LE, Notepad
/// long prefixed UTF-8 with a BOM. The content is intact; refusing it
/// only strands the user.
#[test]
fn reads_a_document_whatever_byte_order_mark_it_carries() {
    let raw = format!(
        r#"{{"format":"orion-profile","version":1,"profile":{{"name":"portable","endpoint":"vpn.example.net:51820","private_key":"{CLIENT_PRIVATE}","peer_public_key":"{GATEWAY_PUBLIC}","address":"100.64.1.2/32"}}}}"#
    );

    let utf16le: Vec<u8> = [0xFF, 0xFE]
        .into_iter()
        .chain(raw.encode_utf16().flat_map(u16::to_le_bytes))
        .collect();
    let utf16be: Vec<u8> = [0xFE, 0xFF]
        .into_iter()
        .chain(raw.encode_utf16().flat_map(u16::to_be_bytes))
        .collect();
    let utf8_bom: Vec<u8> = [0xEF, 0xBB, 0xBF].into_iter().chain(raw.bytes()).collect();

    for (label, bytes) in [
        ("UTF-8", raw.clone().into_bytes()),
        ("UTF-8 + BOM", utf8_bom),
        ("UTF-16LE", utf16le),
        ("UTF-16BE", utf16be),
    ] {
        let directory = temp_directory("orion-import-encoding");
        let path = directory.join("portable.orion");
        std::fs::write(&path, &bytes).unwrap();
        let imported = read_profile_import_path(&path)
            .unwrap_or_else(|error| panic!("{label} should have been read: {error:#}"));
        assert_eq!(imported.profile.name, "portable", "{label}");
        std::fs::remove_dir_all(directory).unwrap();
    }
}

/// «format inconnu» alone leaves the user re-reading a file that looks
/// right to them: the message must say what was actually seen.
#[test]
fn an_unrecognized_document_says_what_it_starts_with() {
    let empty = parse_profile_import("   ", "profil.txt")
        .unwrap_err()
        .to_string();
    assert!(empty.contains("vide"), "message : {empty}");

    let html = parse_profile_import("<!DOCTYPE html>", "profil.txt")
        .unwrap_err()
        .to_string();
    assert!(html.contains("<!DOCTYPE html>"), "message : {html}");
    assert!(html.contains("profil.txt"), "message : {html}");

    // What a UTF-8 decoder leaves when handed UTF-16: the encoding is
    // named, because "unknown format" would send the user looking for a
    // fault in a document that has none.
    let mangled = parse_profile_import("\u{fffd}\u{fffd}{\0", "profil.txt")
        .unwrap_err()
        .to_string();
    assert!(mangled.contains("UTF-8"), "message : {mangled}");
}

#[test]
fn refuses_an_oversized_document() {
    let raw = " ".repeat(MAX_PROFILE_IMPORT_BYTES + 1);
    assert!(parse_profile_import(&raw, "big.json")
        .unwrap_err()
        .to_string()
        .contains("trop volumineux"));
}

#[test]
fn reading_by_path_reuses_the_parser_and_the_limit() {
    let directory = temp_directory("orion-import-path");
    let profile_path = directory.join("portable.orion");
    let raw = format!(
        r#"{{
            "format": "orion-profile",
            "version": 1,
            "profile": {{
                "name": "portable",
                "endpoint": "vpn.example.net:51820",
                "private_key": "{CLIENT_PRIVATE}",
                "peer_public_key": "{GATEWAY_PUBLIC}",
                "address": "100.64.1.2/32"
            }}
        }}"#
    );
    std::fs::write(&profile_path, raw).unwrap();
    assert_eq!(
        read_profile_import_path(&profile_path)
            .unwrap()
            .profile
            .name,
        "portable"
    );

    let oversized_path = directory.join("too-big.orion");
    std::fs::write(&oversized_path, vec![b' '; MAX_PROFILE_IMPORT_BYTES + 1]).unwrap();
    assert!(read_profile_import_path(&oversized_path)
        .unwrap_err()
        .to_string()
        .contains("trop volumineux"));
    std::fs::remove_dir_all(directory).unwrap();
}

/// The UI reads the file and the engine parses what it was sent: the text
/// read that way must be the text the by-path import would have parsed.
#[test]
fn read_profile_document_decodes_like_the_import() {
    let raw = format!(
        r#"{{"format":"orion-profile","version":1,"profile":{{"name":"portable","endpoint":"vpn.example.net:51820","private_key":"{CLIENT_PRIVATE}","peer_public_key":"{GATEWAY_PUBLIC}","address":"100.64.1.2/32"}}}}"#
    );
    let utf16le: Vec<u8> = [0xFF, 0xFE]
        .into_iter()
        .chain(raw.encode_utf16().flat_map(u16::to_le_bytes))
        .collect();
    let directory = temp_directory("orion-import-document");
    let path = directory.join("portable.orion");
    std::fs::write(&path, &utf16le).unwrap();

    let (contents, file_name) = read_profile_document(&path).expect("the document is read");
    assert_eq!(file_name, "portable.orion");
    assert_eq!(contents, raw);

    let by_path = read_profile_import_path(&path).expect("the by-path import reads it");
    let parsed = parse_profile_import(&contents, &file_name).expect("the text parses");
    assert_eq!(parsed.profile.name, by_path.profile.name);
    assert_eq!(parsed.profile.endpoint, by_path.profile.endpoint);
    assert_eq!(
        parsed.profile.private_key.expose(),
        by_path.profile.private_key.expose()
    );
    std::fs::remove_dir_all(directory).unwrap();
}
