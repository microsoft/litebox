// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Implementation-linked; independently check the original protocol body.

use crate::directory_decoder_spec::directory_decoder_policy;
use litebox_broker_protocol::fs::{
    DirectoryPayloadError, directory_pair_outcome, directory_take_outcome, directory_u8_outcome,
};
use vstd::prelude::*;

verus! {

pub proof fn directory_byte_extraction_preserves_its_checked_transition()
    ensures directory_decoder_policy(),
{
    litebox_broker_protocol::fs::prove_directory_decoder();
}

pub fn check_directory_extraction<'a>(
    payload: &'a [u8],
    offset: usize,
    length: usize,
) -> (result: (usize, Result<&'a [u8], DirectoryPayloadError>))
    ensures directory_take_outcome(payload@, offset, length, result.0, result.1),
{
    litebox_broker_protocol::fs::check_directory_payload_take(payload, offset, length)
}

pub fn check_empty_extraction_at_end(payload: &[u8])
    -> (result: Result<&[u8], DirectoryPayloadError>)
    ensures match result {
        Ok(bytes) => bytes@.len() == 0,
        Err(_) => false,
    },
{
    let (_, bytes) = check_directory_extraction(payload, payload.len(), 0);

    bytes
}

pub fn check_directory_byte(payload: &[u8], offset: usize)
    -> (result: (usize, Result<u8, DirectoryPayloadError>))
    ensures directory_u8_outcome(payload@, offset, result.0, result.1),
{
    litebox_broker_protocol::fs::check_directory_payload_u8(payload, offset)
}

pub fn check_directory_pair(payload: &[u8])
    -> (result: (usize, Result<(u8, u8), DirectoryPayloadError>))
    ensures directory_pair_outcome(payload@, result.0, result.1),
{
    litebox_broker_protocol::fs::check_directory_payload_pair(payload)
}

}
