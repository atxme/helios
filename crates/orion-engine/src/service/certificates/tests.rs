//! The read and deposit rules of the approval, on the slot that holds the
//! verified request. A real `VerifiedApproval` needs a served request signed by
//! a domain, which only `orion-core`'s own fixtures can build; both service
//! paths go through `read_verified` and `take_accepted`, so the rules are
//! exercised there with a stand-in. `accepts` and `material` are tested for
//! real in orion-core.

use super::{read_verified, take_accepted, READ_THE_REQUEST_FIRST};

/// What `VerifiedApproval::accepts` answers, as a plain flag.
struct Request {
    matches: bool,
}

const MISMATCH: &str = "l'approbation ne répond pas à la demande";

fn accepts(request: &Request) -> Result<(), &'static str> {
    if request.matches {
        Ok(())
    } else {
        Err(MISMATCH)
    }
}

fn material(request: &Request) -> bool {
    request.matches
}

#[test]
fn the_material_is_refused_without_a_verified_request() {
    let slot: Option<Request> = None;
    assert_eq!(
        read_verified(&slot, material).err().as_deref(),
        Some(READ_THE_REQUEST_FIRST)
    );
}

#[test]
fn the_material_can_be_handed_again_until_a_deposit() {
    let mut slot = Some(Request { matches: true });
    for _ in 0..3 {
        assert_eq!(read_verified(&slot, material), Ok(true));
    }
    assert!(slot.is_some(), "reading leaves the request in place");

    assert!(take_accepted(&mut slot, accepts).is_ok());
    assert!(slot.is_none(), "the deposit empties the slot");
    assert_eq!(
        read_verified(&slot, material).err().as_deref(),
        Some(READ_THE_REQUEST_FIRST)
    );
}

#[test]
fn an_approval_for_another_request_is_refused_and_the_request_is_kept() {
    let mut slot = Some(Request { matches: false });
    let refusal = take_accepted(&mut slot, accepts).err();
    assert_eq!(refusal.as_deref(), Some(MISMATCH));
    assert!(slot.is_some(), "the verified request is kept");
    assert!(read_verified(&slot, material).is_ok());
}

#[test]
fn a_deposited_approval_consumes_the_request() {
    let mut slot = Some(Request { matches: true });
    assert!(take_accepted(&mut slot, accepts).is_ok());
    assert!(slot.is_none());
    assert_eq!(
        take_accepted(&mut slot, accepts).err().as_deref(),
        Some(READ_THE_REQUEST_FIRST)
    );
}
