use rustables_macros::nfnetlink_struct;

use super::{Expression, Register};
use crate::sys;

/// FIB lookup: a source-route existence check scoped to the packet's input
/// interface, or the egress interface name of the destination's route.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
#[nfnetlink_struct]
pub struct Fib {
    #[field(sys::NFTA_FIB_DREG)]
    dreg: Register,
    #[field(sys::NFTA_FIB_RESULT)]
    result: u32,
    #[field(sys::NFTA_FIB_FLAGS)]
    flags: u32,
}

impl Expression for Fib {
    fn get_name() -> &'static str {
        "fib"
    }
}

impl Fib {
    /// Writes a one-byte boolean. `mark` includes the packet mark in policy routing.
    pub fn source_route_present(dreg: Register, mark: bool) -> Self {
        let flags = sys::NFTA_FIB_F_SADDR | sys::NFTA_FIB_F_IIF | sys::NFTA_FIB_F_PRESENT;
        Self::default()
            .with_dreg(dreg)
            .with_result(sys::NFT_FIB_RESULT_OIF)
            .with_flags(flags | if mark { sys::NFTA_FIB_F_MARK } else { 0 })
    }

    /// Writes the name of the interface the destination's route leaves by,
    /// `IFNAMSIZ` bytes, NUL-padded: `fib daddr oifname`.
    pub fn destination_oifname(dreg: Register) -> Self {
        Self::default()
            .with_dreg(dreg)
            .with_result(sys::NFT_FIB_RESULT_OIFNAME)
            .with_flags(sys::NFTA_FIB_F_DADDR)
    }
}
