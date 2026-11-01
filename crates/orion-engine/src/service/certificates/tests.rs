//! The deposit rules of the approval, on the slot that holds the verified
//! request. A real `VerifiedApproval` needs a served request signed by a
//! domain, which only `orion-core`'s own fixtures can build; the rules live in
//! `take_accepted`, so they are exercised there with a stand-in.

use super::{take_accepted, READ_THE_REQUEST_FIRST};

/// What `VerifiedApproval::accepts` answers, as a plain flag.
struct Request {
    matches: bool,
}

fn accepts(request: &Request) -> Result<(), &'static str> {
    if request.matches {
        Ok(())
    } else {
        Err("l'approbation ne répond pas à la demande")
    }
}

#[test]
fn the_material_is_refused_without_a_verified_request() {
    let mut slot: Option<Request> = None;
    assert_eq!(
        take_accepted(&mut slot, accepts).err().as_deref(),
        Some(READ_THE_REQUEST_FIRST)
    );
}

#[test]
fn the_material_can_be_handed_again_until_a_deposit() {
    // Handing the material out is a read of the slot: it never empties it.
    let slot = Some(Request { matches: true });
    for _ in 0..3 {
        assert!(slot.as_ref().is_some());
    }
}

#[test]
fn an_approval_for_another_request_is_refused_and_nothing_is_submitted() {
    let mut slot = Some(Request { matches: false });
    let refusal = take_accepted(&mut slot, accepts).err();
    assert_eq!(
        refusal.as_deref(),
        Some("l'approbation ne répond pas à la demande")
    );
    assert!(slot.is_some(), "the verified request is kept");
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
