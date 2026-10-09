use rustables_macros::nfnetlink_struct;

use crate::error::BuilderError;
use crate::nlmsg::NfNetlinkObject;
use crate::{sys, Batch, MsgType, ProtocolFamily, Table};

/// Initial state of a named counter object.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
#[nfnetlink_struct(nested = true)]
pub struct CounterData {
    #[field(sys::NFTA_COUNTER_BYTES)]
    bytes: u64,
    #[field(sys::NFTA_COUNTER_PACKETS)]
    packets: u64,
}

/// A named counter shared by rules within one table.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
#[nfnetlink_struct(derive_deserialize = false)]
pub struct CounterObject {
    family: ProtocolFamily,
    #[field(sys::NFTA_OBJ_TABLE)]
    table: String,
    #[field(sys::NFTA_OBJ_NAME)]
    name: String,
    #[field(sys::NFTA_OBJ_TYPE)]
    kind: u32,
    #[field(sys::NFTA_OBJ_DATA)]
    data: CounterData,
}

impl CounterObject {
    pub fn new(table: &Table, name: &str) -> Result<Self, BuilderError> {
        if name.is_empty() || name.len() >= 256 || name.contains('\0') {
            return Err(BuilderError::InvalidObjectName);
        }
        Ok(Self {
            family: table.get_family(),
            ..Self::default()
        }
        .with_table(table.get_name().ok_or(BuilderError::MissingTableName)?)
        .with_name(name)
        .with_kind(sys::NFT_OBJECT_COUNTER)
        .with_data(CounterData::default().with_bytes(0u64).with_packets(0u64)))
    }

    pub fn add_to_batch(self, batch: &mut Batch) -> Self {
        batch.add(&self, MsgType::Add);
        self
    }
}

impl NfNetlinkObject for CounterObject {
    const MSG_TYPE_ADD: u32 = sys::NFT_MSG_NEWOBJ;
    const MSG_TYPE_DEL: u32 = sys::NFT_MSG_DELOBJ;

    fn get_family(&self) -> ProtocolFamily {
        self.family
    }

    fn set_family(&mut self, family: ProtocolFamily) {
        self.family = family;
    }
}
