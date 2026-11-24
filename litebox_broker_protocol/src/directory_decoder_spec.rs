// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Must-read semantics of the original directory decoder's byte extraction.
// No well-formed offset is assumed: overflow and out-of-bounds both reject
// without changing state. Successful extraction advances only the offset and
// returns the exact borrowed subrange. This is not a full directory codec proof.

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

pub closed spec fn directory_decoder_policy() -> bool {
    forall|prev: DirectoryPayloadDecoder, cur: DirectoryPayloadDecoder,
        length: usize, result: Result<&[u8], DirectoryPayloadError>|
        #[trigger] directory_take_transition(prev, cur, length, result)
            ==> decoder_take(prev, cur, length, result)
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

}
