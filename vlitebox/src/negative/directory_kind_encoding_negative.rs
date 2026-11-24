// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately assigns the regular-file wire tag to a directory.

use litebox_broker_protocol::fs::FileType;
use vstd::prelude::*;

verus! {

pub fn reject_directory_kind_encoding() -> (raw: u8)
    ensures raw == 0,
{
    vlitebox::directory_decoder_proof::check_directory_kind_encoding(FileType::Directory)
}

}

fn main() {}
