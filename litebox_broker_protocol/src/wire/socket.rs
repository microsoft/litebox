// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::socket::{ReceiveFlags, ReceiveFromFlags, SendFlags};

wire_newtype!(SendFlags: u32);
wire_newtype!(ReceiveFlags: u32);
wire_newtype!(ReceiveFromFlags: u32);
