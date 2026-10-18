use rustables_macros::nfnetlink_struct;

use super::Expression;
use crate::{error::BuilderError, sys};

/// Immediate reference to a named counter in the rule's table.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
#[nfnetlink_struct]
pub struct Objref {
    #[field(sys::NFTA_OBJREF_IMM_TYPE)]
    kind: u32,
    #[field(sys::NFTA_OBJREF_IMM_NAME)]
    name: String,
}

impl Expression for Objref {
    fn get_name() -> &'static str {
        "objref"
    }
}

impl Objref {
    pub fn counter(name: &str) -> Result<Self, BuilderError> {
        if name.is_empty() || name.len() >= 256 || name.contains('\0') {
            return Err(BuilderError::InvalidObjectName);
        }
        Ok(Self::default()
            .with_kind(sys::NFT_OBJECT_COUNTER)
            .with_name(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::expr::{ExpressionVariant, RawExpression};
    use crate::nlmsg::{NfNetlinkAttribute, NfNetlinkDeserializable};

    #[test]
    fn named_counter_references_decode_as_objref_expressions() {
        let original = RawExpression::from(Objref::counter("drops").unwrap());
        let mut encoded = vec![0; original.get_size()];
        original.write_payload(&mut encoded);
        let (decoded, remaining) = RawExpression::deserialize(&encoded).unwrap();
        assert!(remaining.is_empty());
        assert_eq!(decoded, original);
        assert!(matches!(
            decoded.get_data(),
            Some(ExpressionVariant::Objref(_))
        ));
    }
}
