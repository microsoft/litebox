// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! OP-TEE messages in LiteBox VM envelopes ([`Protocol::OPTEE_MSG`]): the
//! payload is an `optee_msg_arg`, as the normal-world driver builds it. An
//! RMEM's `shm_ref` is the index of a [`PartKind::BUFFER`] part and `offs` an
//! offset into it. `OpenSession` starts with [`OPEN_SESSION_META_PARAMS`]
//! meta values: the TA's UUID, then the client's UUID with its login in `c`.
//!
//! [`Protocol::OPTEE_MSG`]: litebox_common_vm_abi::envelope::Protocol::OPTEE_MSG

use crate::{OpteeMsgArgs, OpteeMsgParam, OpteeMsgParamRmem, OpteeMsgParamValue};
use crate::{TeeIdentity, TeeLogin, TeeUuid};
use core::ops::Range;
use litebox_common_vm_abi::envelope::{Envelope, PartKind};

/// `StartupInfo::images` indices.
pub const LDELF_IMAGE: usize = 0;
pub const TA_IMAGE: usize = 1;

pub const OPEN_SESSION_META_PARAMS: usize = 2;

#[must_use]
pub fn open_session_meta(
    ta: TeeUuid,
    client: TeeIdentity,
) -> [OpteeMsgParam; OPEN_SESSION_META_PARAMS] {
    let [a, b] = ta.to_u64_array();
    let ta = OpteeMsgParam::new_meta_value(OpteeMsgParamValue { a, b, c: 0 });
    let [a, b] = client.uuid.to_u64_array();
    let c = u64::from(client.login as u32);
    let client = OpteeMsgParam::new_meta_value(OpteeMsgParamValue { a, b, c });
    [ta, client]
}

/// The TA's UUID and the client's identity; `None` if malformed. Only the
/// REE-derived logins carry a client UUID; a TA login is refused.
#[must_use]
pub fn parse_open_session_meta(args: &OpteeMsgArgs) -> Option<(TeeUuid, TeeIdentity)> {
    let ta = args.get_meta_param_value(0).ok()?;
    let client = args.get_meta_param_value(1).ok()?;
    let login = TeeLogin::try_from(u32::try_from(client.c).ok()?).ok()?;
    let uuid = match login {
        TeeLogin::Public | TeeLogin::ReeKernel => TeeUuid::NIL,
        TeeLogin::User
        | TeeLogin::Group
        | TeeLogin::Application
        | TeeLogin::ApplicationUser
        | TeeLogin::ApplicationGroup => TeeUuid::from_u64_array([client.a, client.b]),
        TeeLogin::TrustedApp => return None,
    };
    Some((
        TeeUuid::from_u64_array([ta.a, ta.b]),
        TeeIdentity { login, uuid },
    ))
}

/// The byte range of `rmem`'s data in `envelope`'s message; `None` unless it
/// lies in a buffer part.
#[must_use]
pub fn rmem_buffer(envelope: &Envelope<'_>, rmem: &OpteeMsgParamRmem) -> Option<Range<usize>> {
    let part = envelope
        .part(usize::try_from(rmem.shm_ref).ok()?)
        .filter(|part| part.kind == PartKind::BUFFER)?
        .range();
    let start = part.start.checked_add(usize::try_from(rmem.offs).ok()?)?;
    let end = start.checked_add(usize::try_from(rmem.size).ok()?)?;
    (end <= part.end).then_some(start..end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OpteeMessageCommand;
    use litebox_common_vm_abi::envelope::{Layout, Protocol};

    #[test]
    fn open_session_meta_round_trips() {
        let ta = TeeUuid::from_u64_array([1, 2]);
        let client = TeeIdentity {
            login: TeeLogin::User,
            uuid: TeeUuid::from_u64_array([3, 4]),
        };
        let meta = open_session_meta(ta, client);
        let args = OpteeMsgArgs::new(OpteeMessageCommand::OpenSession, 0, 0, &meta).unwrap();
        assert_eq!(parse_open_session_meta(&args), Some((ta, client)));

        let public = TeeIdentity {
            login: TeeLogin::Public,
            uuid: TeeUuid::from_u64_array([3, 4]),
        };
        let meta = open_session_meta(ta, public);
        let args = OpteeMsgArgs::new(OpteeMessageCommand::OpenSession, 0, 0, &meta).unwrap();
        let (_, parsed) = parse_open_session_meta(&args).unwrap();
        assert_eq!(parsed.uuid, TeeUuid::NIL);

        let app = TeeIdentity {
            login: TeeLogin::TrustedApp,
            uuid: TeeUuid::NIL,
        };
        let meta = open_session_meta(ta, app);
        let args = OpteeMsgArgs::new(OpteeMessageCommand::OpenSession, 0, 0, &meta).unwrap();
        assert_eq!(parse_open_session_meta(&args), None);
    }

    #[test]
    fn rmem_buffers_stay_in_their_part() {
        let layout = Layout::new(
            Protocol::OPTEE_MSG,
            &[(PartKind::PAYLOAD, 8), (PartKind::BUFFER, 16)],
        )
        .unwrap();
        let mut message = alloc::vec![0u8; usize::try_from(layout.message_len()).unwrap()];
        layout.write_table(&mut message).unwrap();
        let envelope = Envelope::parse(&message).unwrap();
        let buffer = layout.parts()[1].range();
        let rmem = |shm_ref, offs, size| OpteeMsgParamRmem {
            offs,
            size,
            shm_ref,
        };
        assert_eq!(
            rmem_buffer(&envelope, &rmem(1, 4, 12)),
            Some(buffer.start + 4..buffer.end)
        );
        assert_eq!(rmem_buffer(&envelope, &rmem(1, 4, 13)), None);
        assert_eq!(rmem_buffer(&envelope, &rmem(0, 0, 1)), None, "the payload");
        assert_eq!(rmem_buffer(&envelope, &rmem(2, 0, 0)), None, "no such part");
        assert_eq!(rmem_buffer(&envelope, &rmem(1, u64::MAX, 1)), None);
    }
}
