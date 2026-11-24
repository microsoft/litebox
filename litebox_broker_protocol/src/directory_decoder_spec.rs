// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Must-read semantics of the original directory decoder's byte extraction.
// No well-formed offset is assumed: overflow and out-of-bounds both reject
// without changing state. Successful extraction advances only the offset and
// returns the exact borrowed subrange. The original u8 reader composes extraction
// with indexing. A failed second byte read retains successful first-byte progress.
// This is not a full directory codec proof.

use vstd::prelude::*;

verus! {

pub open spec fn directory_take_outcome(
    payload: Seq<u8>,
    offset: usize,
    length: usize,
    cur_offset: usize,
    result: Result<&[u8], DirectoryPayloadError>,
) -> bool {
    let end = offset as int + length as int;
    if end <= usize::MAX && end <= payload.len() {
        match result {
            Ok(bytes) => {
                &&& cur_offset == end
                &&& bytes@ == payload.subrange(offset as int, end)
            },
            Err(_) => false,
        }
    } else {
        &&& result == Err(DirectoryPayloadError::Malformed)
        &&& cur_offset == offset
    }
}

pub open spec fn directory_u8_outcome(
    payload: Seq<u8>,
    offset: usize,
    cur_offset: usize,
    result: Result<u8, DirectoryPayloadError>,
) -> bool {
    let end = offset as int + 1;
    if end <= usize::MAX && end <= payload.len() {
        &&& cur_offset == end
        &&& result == Ok(payload[offset as int])
    } else {
        &&& cur_offset == offset
        &&& result == Err(DirectoryPayloadError::Malformed)
    }
}

spec fn decoder_take(
    prev: DirectoryPayloadDecoder,
    cur: DirectoryPayloadDecoder,
    length: usize,
    result: Result<&[u8], DirectoryPayloadError>,
) -> bool {
    &&& cur.payload == prev.payload
    &&& directory_take_outcome(prev.payload@, prev.offset, length, cur.offset, result)
}

fn apply_directory_take<'a>(
    prev: DirectoryPayloadDecoder<'a>,
    length: usize,
) -> (result: (DirectoryPayloadDecoder<'a>, Result<&'a [u8], DirectoryPayloadError>))
    ensures decoder_take(prev, result.0, length, result.1),
{
    let mut cur = prev;

    let bytes = cur.take(length);

    (cur, bytes)
}

closed spec fn directory_take_transition(
    prev: DirectoryPayloadDecoder,
    cur: DirectoryPayloadDecoder,
    length: usize,
    result: Result<&[u8], DirectoryPayloadError>,
) -> bool {
    apply_directory_take.ensures((prev, length), (cur, result))
}

spec fn decoder_u8(
    prev: DirectoryPayloadDecoder,
    cur: DirectoryPayloadDecoder,
    result: Result<u8, DirectoryPayloadError>,
) -> bool {
    &&& cur.payload == prev.payload
    &&& directory_u8_outcome(prev.payload@, prev.offset, cur.offset, result)
}

fn apply_directory_u8<'a>(
    prev: DirectoryPayloadDecoder<'a>,
) -> (result: (DirectoryPayloadDecoder<'a>, Result<u8, DirectoryPayloadError>))
    ensures decoder_u8(prev, result.0, result.1),
{
    let mut cur = prev;

    let byte = cur.u8();

    (cur, byte)
}

closed spec fn directory_u8_transition(
    prev: DirectoryPayloadDecoder,
    cur: DirectoryPayloadDecoder,
    result: Result<u8, DirectoryPayloadError>,
) -> bool {
    apply_directory_u8.ensures((prev,), (cur, result))
}

pub closed spec fn directory_decoder_policy() -> bool {
    &&& (forall|prev: DirectoryPayloadDecoder, cur: DirectoryPayloadDecoder,
        length: usize, result: Result<&[u8], DirectoryPayloadError>|
        #[trigger] directory_take_transition(prev, cur, length, result)
            ==> decoder_take(prev, cur, length, result))
    &&& (forall|prev: DirectoryPayloadDecoder, cur: DirectoryPayloadDecoder,
        result: Result<u8, DirectoryPayloadError>|
        #[trigger] directory_u8_transition(prev, cur, result)
            ==> decoder_u8(prev, cur, result))
}

pub proof fn prove_directory_decoder()
    ensures directory_decoder_policy(),
{
}

// Actual private decoder call with arbitrary initial offset, including malformed states.
pub fn check_directory_payload_take<'a>(
    payload: &'a [u8],
    offset: usize,
    length: usize,
) -> (result: (usize, Result<&'a [u8], DirectoryPayloadError>))
    ensures directory_take_outcome(payload@, offset, length, result.0, result.1),
{
    let prev = DirectoryPayloadDecoder { payload, offset };
    let (cur, bytes) = apply_directory_take(prev, length);

    (cur.offset, bytes)
}

pub fn check_directory_payload_u8(
    payload: &[u8],
    offset: usize,
) -> (result: (usize, Result<u8, DirectoryPayloadError>))
    ensures directory_u8_outcome(payload@, offset, result.0, result.1),
{
    let prev = DirectoryPayloadDecoder { payload, offset };
    let (cur, byte) = apply_directory_u8(prev);

    (cur.offset, byte)
}

pub open spec fn directory_pair_outcome(
    payload: Seq<u8>,
    cur_offset: usize,
    result: Result<(u8, u8), DirectoryPayloadError>,
) -> bool {
    if payload.len() == 0 {
        &&& cur_offset == 0
        &&& result == Err(DirectoryPayloadError::Malformed)
    } else if payload.len() == 1 {
        &&& cur_offset == 1
        &&& result == Err(DirectoryPayloadError::Malformed)
    } else {
        &&& cur_offset == 2
        &&& result == Ok((payload[0], payload[1]))
    }
}

// Two original calls retain first-read progress if only the second read fails.
pub fn check_directory_payload_pair(payload: &[u8])
    -> (result: (usize, Result<(u8, u8), DirectoryPayloadError>))
    ensures directory_pair_outcome(payload@, result.0, result.1),
{
    let mut decoder = DirectoryPayloadDecoder { payload, offset: 0 };

    let result = match decoder.u8() {
        Ok(first) => match decoder.u8() {
            Ok(second) => Ok((first, second)),
            Err(error) => Err(error),
        },
        Err(error) => Err(error),
    };

    (decoder.offset, result)
}

}
