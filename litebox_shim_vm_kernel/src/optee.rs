// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! OP-TEE service on a [`Process`], in the message format of
//! [`litebox_common_optee::envelope`]. The TA's UUID is the process identity.
//!
//! Trusted: a reply must keep the request's part table, and yields outputs
//! only for parameters sent as outputs whose type the runner kept, with memref
//! data from the request's own buffers, never from runner-supplied references.

use crate::{Dead, Process};
use alloc::vec::Vec;
use litebox_common_optee::envelope::{OPEN_SESSION_META_PARAMS, open_session_meta};
use litebox_common_optee::{
    OpteeMessageCommand, OpteeMsgArgs, OpteeMsgArgsHeader, OpteeMsgAttrType, OpteeMsgParam,
    OpteeMsgParamRmem, OpteeMsgParamValue, TeeIdentity, TeeLogin, TeeOrigin, TeeResult, TeeUuid,
    UteeParams, optee_msg_args_total_size,
};
use litebox_common_vm_abi::envelope::{Envelope, Layout, Part, PartKind, Protocol};
use zerocopy::FromBytes;

/// Client parameters, as in GlobalPlatform TEE.
pub const NUM_PARAMS: usize = UteeParams::TEE_NUM_PARAMS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryFunc {
    OpenSession,
    InvokeCommand,
    CloseSession,
}

#[derive(Clone, Debug, Default)]
pub enum InParam {
    #[default]
    None,
    ValueInput {
        a: u64,
        b: u64,
    },
    ValueOutput,
    ValueInout {
        a: u64,
        b: u64,
    },
    MemrefInput(Vec<u8>),
    MemrefOutput {
        capacity: usize,
    },
    /// The TA sees the whole capacity, `data` zero-padded.
    MemrefInout {
        data: Vec<u8>,
        capacity: usize,
    },
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum OutParam {
    #[default]
    None,
    Value {
        a: u64,
        b: u64,
    },
    /// `size` is the TA's, which exceeds the capacity for a short buffer;
    /// `data` is at most the capacity.
    Memref {
        data: Vec<u8>,
        size: u64,
    },
}

#[derive(Clone, Debug)]
pub struct Invocation {
    pub func: EntryFunc,
    pub session: u32,
    pub cmd_id: u32,
    pub login: TeeLogin,
    /// `TEE_UUID` memory layout.
    pub client_uuid: TeeUuid,
    pub params: [InParam; NUM_PARAMS],
}

#[derive(Clone, Debug)]
pub struct Completion {
    /// `TEE_Result`, possibly TA-defined.
    pub result: u32,
    pub origin: u32,
    pub session: u32,
    pub params: [OutParam; NUM_PARAMS],
}

/// Requests that do not fit the message window complete with
/// `TEE_ERROR_BAD_PARAMETERS` without reaching the process. A malformed reply
/// kills the process.
///
/// # Errors
///
/// The process is dead, died serving the request, or was killed for its
/// reply.
///
/// # Panics
///
/// If the process was not started.
pub fn call(process: &mut Process, invocation: Invocation) -> Result<Completion, Dead> {
    let ta = TeeUuid::read_from_bytes(&process.identity()[..size_of::<TeeUuid>()])
        .expect("the identity starts with the TA's UUID");
    let Some(request) = Request::encode(ta, &invocation) else {
        return Ok(Completion {
            result: TeeResult::BadParameters.into(),
            origin: *TeeOrigin::Tee.value(),
            session: invocation.session,
            params: Default::default(),
        });
    };
    let reply = process.call(&request.message)?;
    request
        .decode(&reply)
        .ok_or_else(|| process.kill("malformed OP-TEE reply"))
}

/// What the kernel sent for a client parameter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sent {
    /// Nothing comes back.
    Input,
    Value {
        inout: bool,
    },
    /// `part` is its buffer's part index.
    Memref {
        inout: bool,
        part: usize,
        capacity: u64,
    },
}

struct Request {
    message: Vec<u8>,
    parts: Vec<Part>,
    num_params: usize,
    /// Client parameters start here.
    first_param: usize,
    sent: [Sent; NUM_PARAMS],
}

impl Request {
    /// `None` if it does not fit the message window or inout data exceeds its
    /// capacity. Closes carry no parameters, as in OP-TEE MSG, so they always
    /// encode: every close reaches the process.
    fn encode(ta: TeeUuid, invocation: &Invocation) -> Option<Self> {
        let mut params = Vec::with_capacity(OPEN_SESSION_META_PARAMS + NUM_PARAMS);
        let (cmd, first_param) = match invocation.func {
            EntryFunc::OpenSession => {
                let client = TeeIdentity {
                    login: invocation.login,
                    uuid: invocation.client_uuid,
                };
                params.extend(open_session_meta(ta, client));
                (OpteeMessageCommand::OpenSession, OPEN_SESSION_META_PARAMS)
            }
            EntryFunc::InvokeCommand => (OpteeMessageCommand::InvokeCommand, 0),
            EntryFunc::CloseSession => (OpteeMessageCommand::CloseSession, 0),
        };
        let mut parts = Vec::from([(PartKind::PAYLOAD, 0)]);
        let mut buffers: Vec<(&[u8], usize)> = Vec::new();
        let mut sent = [Sent::Input; NUM_PARAMS];
        let no_params: [InParam; NUM_PARAMS] = Default::default();
        let inputs = if invocation.func == EntryFunc::CloseSession {
            &no_params
        } else {
            &invocation.params
        };
        for (input, sent) in inputs.iter().zip(&mut sent) {
            let value =
                |kind, a, b| OpteeMsgParam::new_value(kind, OpteeMsgParamValue { a, b, c: 0 });
            // Memrefs: type, data, capacity, and whether they are outputs (inout).
            let (kind, data, capacity, output) = match input {
                InParam::None => {
                    params.push(OpteeMsgParam::NONE);
                    continue;
                }
                InParam::ValueInput { a, b } => {
                    params.push(value(OpteeMsgAttrType::ValueInput, *a, *b)?);
                    continue;
                }
                InParam::ValueOutput => {
                    *sent = Sent::Value { inout: false };
                    params.push(value(OpteeMsgAttrType::ValueOutput, 0, 0)?);
                    continue;
                }
                InParam::ValueInout { a, b } => {
                    *sent = Sent::Value { inout: true };
                    params.push(value(OpteeMsgAttrType::ValueInout, *a, *b)?);
                    continue;
                }
                InParam::MemrefInput(data) => (
                    OpteeMsgAttrType::RmemInput,
                    data.as_slice(),
                    data.len(),
                    None,
                ),
                InParam::MemrefOutput { capacity } => (
                    OpteeMsgAttrType::RmemOutput,
                    &[][..],
                    *capacity,
                    Some(false),
                ),
                InParam::MemrefInout { data, capacity } => {
                    if data.len() > *capacity {
                        return None;
                    }
                    (
                        OpteeMsgAttrType::RmemInout,
                        data.as_slice(),
                        *capacity,
                        Some(true),
                    )
                }
            };
            let part = parts.len();
            parts.push((PartKind::BUFFER, capacity as u64));
            buffers.push((data, part));
            // An input's size is its data; an output's is its capacity.
            let size = match output {
                None => data.len(),
                Some(inout) => {
                    *sent = Sent::Memref {
                        inout,
                        part,
                        capacity: capacity as u64,
                    };
                    capacity
                }
            };
            params.push(OpteeMsgParam::new_rmem(
                kind,
                OpteeMsgParamRmem {
                    offs: 0,
                    size: size as u64,
                    shm_ref: part as u64,
                },
            )?);
        }
        let num_params = params.len();
        let payload_len = optee_msg_args_total_size(u32::try_from(num_params).ok()?);
        parts[0].1 = payload_len as u64;
        let layout = Layout::new(Protocol::OPTEE_MSG, &parts).ok()?;
        if layout.message_len() > crate::MAX_MESSAGE_LEN {
            return None;
        }
        let mut message = alloc::vec![0u8; usize::try_from(layout.message_len()).ok()?];
        layout.write_table(&mut message).ok()?;
        let parts = layout.parts().to_vec();
        OpteeMsgArgs::new(cmd, invocation.cmd_id, invocation.session, &params)
            .ok()?
            .serialize(&mut message[parts[0].range()])
            .ok()?;
        for (data, part) in buffers {
            message[parts[part].range()][..data.len()].copy_from_slice(data);
        }
        Some(Self {
            message,
            parts,
            num_params,
            first_param,
            sent,
        })
    }

    /// `None` for a malformed reply.
    fn decode(&self, reply: &[u8]) -> Option<Completion> {
        let envelope = Envelope::parse(reply).ok()?;
        if envelope.protocol() != Protocol::OPTEE_MSG || envelope.parts() != self.parts {
            return None;
        }
        let (header, raw) = OpteeMsgArgsHeader::read_from_prefix(envelope.payload()).ok()?;
        if usize::try_from(header.num_params).ok()? != self.num_params || header.pad != 0 {
            return None;
        }
        let mut params: [OutParam; NUM_PARAMS] = Default::default();
        for (i, (out, sent)) in params.iter_mut().zip(self.sent).enumerate() {
            let offset = (self.first_param + i) * size_of::<OpteeMsgParam>();
            let (param, _) = OpteeMsgParam::read_from_prefix(raw.get(offset..)?).ok()?;
            *out = output(sent, &param, &envelope);
        }
        Some(Completion {
            result: header.ret,
            origin: header.ret_origin,
            session: header.session,
            params,
        })
    }
}

/// Trusts only what the kernel sent: an output only for a parameter sent as
/// an output, only if the runner kept its type, with memref data from the
/// kernel's own buffer part.
fn output(sent: Sent, reply: &OpteeMsgParam, envelope: &Envelope<'_>) -> OutParam {
    let kept = |expected| reply.attr_type() == expected;
    match sent {
        Sent::Input => OutParam::None,
        Sent::Value { inout } => {
            let expected = if inout {
                OpteeMsgAttrType::ValueInout
            } else {
                OpteeMsgAttrType::ValueOutput
            };
            match reply.get_param_value() {
                Some(value) if kept(expected) => OutParam::Value {
                    a: value.a,
                    b: value.b,
                },
                _ => OutParam::None,
            }
        }
        Sent::Memref {
            inout,
            part,
            capacity,
        } => {
            let expected = if inout {
                OpteeMsgAttrType::RmemInout
            } else {
                OpteeMsgAttrType::RmemOutput
            };
            match (reply.get_param_rmem(), envelope.buffer(part)) {
                (Some(rmem), Some(buffer)) if kept(expected) => {
                    let len = usize::try_from(rmem.size.min(capacity)).unwrap_or(0);
                    OutParam::Memref {
                        data: buffer[..len.min(buffer.len())].to_vec(),
                        size: rmem.size,
                    }
                }
                _ => OutParam::None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerocopy::IntoBytes as _;

    fn ta_uuid() -> TeeUuid {
        TeeUuid::from_u64_array([0x0707_0707_0707_0707, 0x0707_0707_0707_0707])
    }

    fn invocation(params: [InParam; NUM_PARAMS]) -> Invocation {
        Invocation {
            func: EntryFunc::OpenSession,
            session: 0,
            cmd_id: 0,
            login: TeeLogin::User,
            client_uuid: TeeUuid::from_u64_array([9, 9]),
            params,
        }
    }

    fn args(message: &[u8]) -> (OpteeMsgArgsHeader, Vec<OpteeMsgParam>) {
        let envelope = Envelope::parse(message).unwrap();
        let (header, raw) = OpteeMsgArgsHeader::read_from_prefix(envelope.payload()).unwrap();
        let params = raw
            .chunks(size_of::<OpteeMsgParam>())
            .map(|p| OpteeMsgParam::read_from_bytes(p).unwrap())
            .collect();
        (header, params)
    }

    #[test]
    fn requests_are_optee_messages() {
        let request = Request::encode(
            ta_uuid(),
            &invocation([
                InParam::MemrefInput(alloc::vec![1, 2, 3]),
                InParam::ValueInout { a: 4, b: 5 },
                InParam::MemrefOutput { capacity: 20 },
                InParam::MemrefInout {
                    data: alloc::vec![6],
                    capacity: 8,
                },
            ]),
        )
        .unwrap();
        let envelope = Envelope::parse(&request.message).unwrap();
        let (header, params) = args(&request.message);
        assert_eq!(header.cmd, OpteeMessageCommand::OpenSession as u32);
        assert_eq!(header.num_params, 6);
        let ta = params[0].get_param_value().unwrap();
        assert_eq!(TeeUuid::from_u64_array([ta.a, ta.b]), ta_uuid());
        assert!(params[0].is_meta() && params[1].is_meta());
        assert_eq!(
            params[1].get_param_value().unwrap().c,
            TeeLogin::User as u64
        );
        let input = params[2].get_param_rmem().unwrap();
        assert_eq!((input.size, input.offs), (3, 0));
        assert_eq!(
            envelope.buffer(usize::try_from(input.shm_ref).unwrap()),
            Some(&[1, 2, 3][..])
        );
        assert_eq!(params[4].get_param_rmem().unwrap().size, 20);
        let in_out = params[5].get_param_rmem().unwrap();
        assert_eq!(in_out.size, 8, "the TA sees the whole capacity");
        assert_eq!(
            envelope.buffer(usize::try_from(in_out.shm_ref).unwrap()),
            Some(&[6, 0, 0, 0, 0, 0, 0, 0][..])
        );
    }

    #[test]
    fn oversized_requests_are_refused() {
        let too_big = usize::try_from(crate::MAX_MESSAGE_LEN).unwrap();
        let request = |param| {
            Request::encode(
                ta_uuid(),
                &invocation([param, InParam::None, InParam::None, InParam::None]),
            )
        };
        assert!(request(InParam::MemrefOutput { capacity: too_big }).is_none());
        assert!(
            request(InParam::MemrefInout {
                data: alloc::vec![0; 9],
                capacity: 8,
            })
            .is_none()
        );
        assert!(request(InParam::MemrefOutput { capacity: 64 }).is_some());

        let mut close = invocation([
            InParam::MemrefOutput { capacity: too_big },
            InParam::None,
            InParam::None,
            InParam::None,
        ]);
        close.func = EntryFunc::CloseSession;
        let request = Request::encode(ta_uuid(), &close).expect("closes always encode");
        let (_, params) = args(&request.message);
        assert!(
            params
                .iter()
                .all(|p| p.as_bytes() == OpteeMsgParam::NONE.as_bytes())
        );
    }

    /// The runner's reply: `params` rewritten in place, `ret` set.
    fn reply(request: &Request, edit: impl FnOnce(&mut [OpteeMsgParam], &mut [u8])) -> Vec<u8> {
        let mut message = request.message.clone();
        let (mut header, mut params) = args(&message);
        let payload = request.parts[0].range();
        header.ret = 0xffff_0010; // TA-defined results pass through
        edit(&mut params, &mut message);
        message[payload.clone()][..size_of::<OpteeMsgArgsHeader>()]
            .copy_from_slice(header.as_bytes());
        for (i, param) in params.iter().enumerate() {
            let start =
                payload.start + size_of::<OpteeMsgArgsHeader>() + i * size_of::<OpteeMsgParam>();
            message[start..start + size_of::<OpteeMsgParam>()].copy_from_slice(param.as_bytes());
        }
        message
    }

    #[test]
    fn outputs_follow_what_was_sent() {
        let mut invocation = invocation([
            InParam::ValueInput { a: 1, b: 2 },
            InParam::ValueOutput,
            InParam::MemrefOutput { capacity: 4 },
            InParam::MemrefInput(alloc::vec![1; 4]),
        ]);
        invocation.func = EntryFunc::InvokeCommand;
        let request = Request::encode(ta_uuid(), &invocation).unwrap();
        let output_part = request.parts[1].range();
        let input_part = request.parts[2].range();
        let completion = request
            .decode(&reply(&request, |params, message| {
                // Claims outputs for inputs too, and a memref larger than the
                // buffer (short buffer).
                let value = OpteeMsgParamValue { a: 7, b: 8, c: 0 };
                params[0] = OpteeMsgParam::new_value(OpteeMsgAttrType::ValueInout, value).unwrap();
                params[1] = OpteeMsgParam::new_value(OpteeMsgAttrType::ValueOutput, value).unwrap();
                let rmem = |size, shm_ref| OpteeMsgParamRmem {
                    offs: 0,
                    size,
                    shm_ref,
                };
                params[2] =
                    OpteeMsgParam::new_rmem(OpteeMsgAttrType::RmemOutput, rmem(9, 2)).unwrap();
                params[3] =
                    OpteeMsgParam::new_rmem(OpteeMsgAttrType::RmemInout, rmem(4, 2)).unwrap();
                message[output_part].copy_from_slice(b"abcd");
                message[input_part].copy_from_slice(b"wxyz");
            }))
            .unwrap();
        assert_eq!(completion.result, 0xffff_0010);
        assert_eq!(
            completion.params,
            [
                OutParam::None,
                OutParam::Value { a: 7, b: 8 },
                // From its own buffer, not the runner's `shm_ref`.
                OutParam::Memref {
                    data: b"abcd".to_vec(),
                    size: 9,
                },
                OutParam::None,
            ]
        );
        // Output types the runner changed are dropped.
        let completion = request
            .decode(&reply(&request, |params, _| {
                params[1] = OpteeMsgParam::NONE;
            }))
            .unwrap();
        assert_eq!(completion.params[1], OutParam::None);
    }

    #[test]
    fn replies_keep_the_request_layout() {
        let request = Request::encode(ta_uuid(), &invocation(Default::default())).unwrap();
        assert!(request.decode(&request.message).is_some());
        let mut moved = request.message.clone();
        moved[16..24].copy_from_slice(&0u64.to_le_bytes()); // the payload's offset
        assert!(request.decode(&moved).is_none());
        assert!(request.decode(&request.message[..8]).is_none());
    }
}
