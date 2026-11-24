// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately accepts an unsupported directory file-type tag.

use litebox_broker_protocol::fs::FileType;
use vstd::prelude::*;

verus! {

pub fn reject_directory_kind_invalid_tag() -> (file_type: Option<FileType>)
    ensures file_type.is_some(),
{
    vlitebox::directory_decoder_proof::check_directory_kind_decoding(255)
}

}

fn main() {}
