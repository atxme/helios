//! Modèle d'un message VICI : une séquence ordonnée d'éléments (clé/valeur,
//! sections imbriquées, listes).

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Message {
    pub elements: Vec<Element>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Element {
    /// Paire clé -> valeur (la valeur est une chaîne d'octets arbitraire).
    KeyValue(String, Vec<u8>),
    /// Section nommée contenant un sous-message.
    Section(String, Message),
    /// Liste nommée de valeurs.
    List(String, Vec<Vec<u8>>),
}

impl Message {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ajoute une paire clé/valeur (style builder).
    pub fn kv(mut self, key: &str, value: &str) -> Self {
        self.elements
            .push(Element::KeyValue(key.to_string(), value.as_bytes().to_vec()));
        self
    }

    /// Ajoute une section imbriquée.
    pub fn section(mut self, name: &str, inner: Message) -> Self {
        self.elements
            .push(Element::Section(name.to_string(), inner));
        self
    }

    /// Ajoute une liste de chaînes.
    pub fn list(mut self, name: &str, items: &[&str]) -> Self {
        let items = items.iter().map(|s| s.as_bytes().to_vec()).collect();
        self.elements.push(Element::List(name.to_string(), items));
        self
    }

    /// Récupère la valeur brute associée à une clé de premier niveau.
    pub fn get(&self, key: &str) -> Option<&[u8]> {
        self.elements.iter().find_map(|el| match el {
            Element::KeyValue(k, v) if k == key => Some(v.as_slice()),
            _ => None,
        })
    }

    /// Récupère une valeur de premier niveau interprétée en UTF-8.
    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(|v| std::str::from_utf8(v).ok())
    }

    /// Récupère une section imbriquée.
    pub fn section_of(&self, name: &str) -> Option<&Message> {
        self.elements.iter().find_map(|el| match el {
            Element::Section(n, m) if n == name => Some(m),
            _ => None,
        })
    }
}
