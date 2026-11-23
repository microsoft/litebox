// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The Host Compute Service and Host Compute Network. Both report a failure through an HRESULT, a
//! JSON document about it, or both.

pub(super) mod hcn;
pub(super) mod hcs;

use std::fmt;
use std::io;

use windows_sys::core::HRESULT;

#[derive(Debug)]
pub struct Error {
    code: HRESULT,
    document: String,
}

impl Error {
    fn new(code: HRESULT) -> Self {
        Self {
            code,
            document: String::new(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.code >= 0 {
            return formatter.write_str(&self.document);
        }
        write!(
            formatter,
            "{} ({:#010x})",
            io::Error::from_raw_os_error(self.code),
            self.code
        )?;
        if !self.document.is_empty() {
            write!(formatter, ": {}", self.document)?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {}

impl From<Error> for io::Error {
    fn from(error: Error) -> Self {
        io::Error::other(error)
    }
}
