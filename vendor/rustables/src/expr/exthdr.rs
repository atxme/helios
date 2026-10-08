use rustables_macros::nfnetlink_struct;

use super::{Expression, Register};
use crate::sys::{
    NFTA_EXTHDR_FLAGS, NFTA_EXTHDR_LEN, NFTA_EXTHDR_OFFSET, NFTA_EXTHDR_OP, NFTA_EXTHDR_SREG,
    NFTA_EXTHDR_TYPE,
};

/// nftables extension-header expression, including TCP-option read/write.
#[derive(Clone, PartialEq, Eq, Default, Debug)]
#[nfnetlink_struct]
pub struct Exthdr {
    #[field(NFTA_EXTHDR_TYPE)]
    kind: u8,
    #[field(NFTA_EXTHDR_OFFSET)]
    offset: u32,
    #[field(NFTA_EXTHDR_LEN)]
    len: u32,
    #[field(NFTA_EXTHDR_FLAGS)]
    flags: u32,
    #[field(NFTA_EXTHDR_OP)]
    op: u32,
    #[field(NFTA_EXTHDR_SREG)]
    sreg: Register,
}

impl Expression for Exthdr {
    fn get_name() -> &'static str {
        "exthdr"
    }
}

impl Exthdr {
    /// Write a two-byte value from a register to the TCP MSS option.
    /// The Linux kernel implementation ignores writes that would increase
    /// the peer's advertised MSS and updates the TCP checksum:
    /// <https://github.com/torvalds/linux/blob/master/net/netfilter/nft_exthdr.c>.
    pub fn tcp_mss_store(sreg: Register) -> Self {
        Self::default()
            .with_kind(2)
            .with_offset(2u32)
            .with_len(2u32)
            .with_op(1u32)
            .with_sreg(sreg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nlmsg::NfNetlinkAttribute;

    fn attributes(expr: &Exthdr) -> Vec<(u16, Vec<u8>)> {
        let mut bytes = vec![0; expr.get_size()];
        expr.write_payload(&mut bytes);
        let mut attrs = Vec::new();
        let mut offset = 0;
        while offset < bytes.len() {
            let len = u16::from_ne_bytes([bytes[offset], bytes[offset + 1]]) as usize;
            let kind = u16::from_ne_bytes([bytes[offset + 2], bytes[offset + 3]]);
            assert!(len >= 4 && offset + len <= bytes.len());
            attrs.push((kind, bytes[offset + 4..offset + len].to_vec()));
            offset += (len + 3) & !3;
        }
        attrs
    }

    #[test]
    fn tcp_mss_write_encodes_exact_kernel_abi_attributes() {
        let store = Exthdr::tcp_mss_store(Register::Reg1);
        let store_attrs = attributes(&store);
        let scalar = |attrs: &[(u16, Vec<u8>)], id: u16| {
            let bytes = &attrs
                .iter()
                .find(|(kind, _)| kind & 0x3fff == id)
                .unwrap()
                .1;
            u32::from_be_bytes(bytes.as_slice().try_into().unwrap())
        };

        // SREG=7 writes TCPOPT_MSS (2), offset 2, length 2, using
        // NFT_EXTHDR_OP_TCPOPT (1), with no conflicting DREG attribute.
        assert_eq!(
            store_attrs.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
            [2, 3, 4, 6, 7]
        );
        assert_eq!(
            store_attrs.iter().find(|(k, _)| k & 0x3fff == 2).unwrap().1,
            [2]
        );
        assert_eq!(scalar(&store_attrs, 3), 2);
        assert_eq!(scalar(&store_attrs, 4), 2);
        assert_eq!(scalar(&store_attrs, 6), 1);
        assert_eq!(scalar(&store_attrs, 7), 1);
    }
}
