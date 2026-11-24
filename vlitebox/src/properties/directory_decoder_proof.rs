// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Implementation-linked; independently check the original protocol body.

use crate::spec::directory_decoder_spec::{
    directory_decoder_policy, directory_file_type_policy, directory_transfer_error_policy,
};
use litebox_broker_protocol::fs::{
    DirectoryPayloadError, DirectoryTransferError, FileType, directory_file_type_decoding,
    directory_file_type_encoding, directory_pair_outcome, directory_take_outcome,
    directory_transfer_error_outcome, directory_u8_outcome,
};
use vstd::prelude::*;

verus! {

pub proof fn directory_file_type_tags_match_original_conversions()
    ensures directory_file_type_policy(),
{
    litebox_broker_protocol::fs::prove_directory_file_type();
}

pub fn check_directory_kind_encoding(file_type: FileType) -> (raw: u8)
    ensures raw == directory_file_type_encoding(file_type),
{
    litebox_broker_protocol::fs::check_directory_file_type_encoding(file_type)
}

pub fn check_directory_kind_decoding(raw: u8) -> (file_type: Option<FileType>)
    ensures file_type == directory_file_type_decoding(raw),
{
    litebox_broker_protocol::fs::check_directory_file_type_decoding(raw)
}

pub fn check_directory_kind_roundtrip(file_type: FileType) -> (result: Option<FileType>)
    ensures result == Some(file_type),
{
    litebox_broker_protocol::fs::check_directory_file_type_roundtrip(file_type)
}

pub fn check_directory_kind_reencoding(raw: u8) -> (result: Option<u8>)
    ensures result == if raw <= 3 { Some(raw) } else { None },
{
    litebox_broker_protocol::fs::check_directory_file_type_reencoding(raw)
}

pub proof fn directory_compatibility_conversion_preserves_payload_errors()
    ensures directory_transfer_error_policy(),
{
    litebox_broker_protocol::fs::prove_directory_transfer_error();
}

pub fn check_directory_error(prev: DirectoryTransferError) -> (cur: DirectoryPayloadError)
    ensures directory_transfer_error_outcome(prev, cur),
{
    litebox_broker_protocol::fs::check_directory_transfer_error(prev)
}

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
