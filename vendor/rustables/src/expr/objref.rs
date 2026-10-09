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
