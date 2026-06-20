//! (Dé)sérialisation du corps d'un message VICI.
//!
//! Encodage des éléments (cf. documentation du protocole VICI de strongSwan) :
//!
//! | Octet | Élément        | Suite                                             |
//! |-------|----------------|---------------------------------------------------|
//! | 1     | SECTION_START  | nom (u8 len + octets), puis contenu               |
//! | 2     | SECTION_END    | —                                                 |
//! | 3     | KEY_VALUE      | clé (u8 len + octets) + valeur (u16 len + octets) |
//! | 4     | LIST_START     | nom (u8 len + octets)                              |
//! | 5     | LIST_ITEM      | valeur (u16 len + octets)                          |
//! | 6     | LIST_END       | —                                                 |
//!
//! Les noms sont préfixés d'une longueur sur 1 octet, les valeurs sur 2 octets
//! (big-endian).

use helios_core::{HeliosError, Result};

use crate::message::{Element, Message};

const SECTION_START: u8 = 1;
const SECTION_END: u8 = 2;
const KEY_VALUE: u8 = 3;
const LIST_START: u8 = 4;
const LIST_ITEM: u8 = 5;
const LIST_END: u8 = 6;

/// Encode le corps d'un message dans `out`.
pub fn encode(msg: &Message, out: &mut Vec<u8>) {
    for el in &msg.elements {
        match el {
            Element::KeyValue(key, value) => {
                out.push(KEY_VALUE);
                put_name(out, key);
                put_value(out, value);
            }
            Element::Section(name, inner) => {
                out.push(SECTION_START);
                put_name(out, name);
                encode(inner, out);
                out.push(SECTION_END);
            }
            Element::List(name, items) => {
                out.push(LIST_START);
                put_name(out, name);
                for item in items {
                    out.push(LIST_ITEM);
                    put_value(out, item);
                }
                out.push(LIST_END);
            }
        }
    }
}

/// Décode le corps d'un message complet.
pub fn decode(buf: &[u8]) -> Result<Message> {
    let mut pos = 0;
    let msg = decode_section(buf, &mut pos, true)?;
    if pos != buf.len() {
        return Err(HeliosError::Vici(format!(
            "octets résiduels après décodage ({} / {})",
            pos,
            buf.len()
        )));
    }
    Ok(msg)
}

fn decode_section(buf: &[u8], pos: &mut usize, top: bool) -> Result<Message> {
    let mut msg = Message::new();
    while *pos < buf.len() {
        let tag = buf[*pos];
        *pos += 1;
        match tag {
            SECTION_END => {
                if top {
                    return Err(HeliosError::Vici("SECTION_END inattendu au sommet".into()));
                }
                return Ok(msg);
            }
            KEY_VALUE => {
                let key = read_name(buf, pos)?;
                let value = read_value(buf, pos)?;
                msg.elements.push(Element::KeyValue(key, value));
            }
            SECTION_START => {
                let name = read_name(buf, pos)?;
                let inner = decode_section(buf, pos, false)?;
                msg.elements.push(Element::Section(name, inner));
            }
            LIST_START => {
                let name = read_name(buf, pos)?;
                let mut items = Vec::new();
                loop {
                    if *pos >= buf.len() {
                        return Err(HeliosError::Vici("liste non terminée".into()));
                    }
                    let item_tag = buf[*pos];
                    *pos += 1;
                    match item_tag {
                        LIST_ITEM => items.push(read_value(buf, pos)?),
                        LIST_END => break,
                        other => {
                            return Err(HeliosError::Vici(format!(
                                "tag inattendu dans une liste : {other}"
                            )))
                        }
                    }
                }
                msg.elements.push(Element::List(name, items));
            }
            other => {
                return Err(HeliosError::Vici(format!("tag d'élément inconnu : {other}")));
            }
        }
    }
    if !top {
        return Err(HeliosError::Vici("section non terminée".into()));
    }
    Ok(msg)
}

fn put_name(out: &mut Vec<u8>, name: &str) {
    let bytes = name.as_bytes();
    out.push(bytes.len() as u8);
    out.extend_from_slice(bytes);
}

fn put_value(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
}

fn read_name(buf: &[u8], pos: &mut usize) -> Result<String> {
    let len = *buf
        .get(*pos)
        .ok_or_else(|| HeliosError::Vici("longueur de nom tronquée".into()))? as usize;
    *pos += 1;
    let end = *pos + len;
    let slice = buf
        .get(*pos..end)
        .ok_or_else(|| HeliosError::Vici("nom tronqué".into()))?;
    *pos = end;
    String::from_utf8(slice.to_vec()).map_err(|e| HeliosError::Vici(e.to_string()))
}

fn read_value(buf: &[u8], pos: &mut usize) -> Result<Vec<u8>> {
    let hi = *buf
        .get(*pos)
        .ok_or_else(|| HeliosError::Vici("longueur de valeur tronquée".into()))?;
    let lo = *buf
        .get(*pos + 1)
        .ok_or_else(|| HeliosError::Vici("longueur de valeur tronquée".into()))?;
    *pos += 2;
    let len = u16::from_be_bytes([hi, lo]) as usize;
    let end = *pos + len;
    let slice = buf
        .get(*pos..end)
        .ok_or_else(|| HeliosError::Vici("valeur tronquée".into()))?;
    *pos = end;
    Ok(slice.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_keyvalue() {
        let msg = Message::new().kv("type", "tunnel").kv("version", "2");
        let mut buf = Vec::new();
        encode(&msg, &mut buf);
        assert_eq!(decode(&buf).unwrap(), msg);
    }

    #[test]
    fn round_trip_nested_section_and_list() {
        let child = Message::new()
            .kv("local_ts", "10.0.0.0/24")
            .list("remote_ts", &["192.168.1.0/24", "192.168.2.0/24"]);
        let msg = Message::new()
            .kv("ike", "helios")
            .section("children", Message::new().section("net", child));
        let mut buf = Vec::new();
        encode(&msg, &mut buf);
        let decoded = decode(&buf).unwrap();
        assert_eq!(decoded, msg);

        // Vérifie l'accès structuré.
        let net = decoded
            .section_of("children")
            .and_then(|c| c.section_of("net"))
            .unwrap();
        assert_eq!(net.get_str("local_ts"), Some("10.0.0.0/24"));
    }

    #[test]
    fn rejects_unknown_tag() {
        assert!(decode(&[99]).is_err());
    }

    #[test]
    fn rejects_truncated_value() {
        // KEY_VALUE, clé "a", longueur de valeur annoncée 5 mais absente.
        let buf = [KEY_VALUE, 1, b'a', 0, 5];
        assert!(decode(&buf).is_err());
    }
}
