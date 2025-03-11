use core::str::FromStr;

use alloc::{ffi::CString, string::ToString};
use elf_loader::object::ElfObject;
use litebox::fs::{FileSystem, Mode, OFlags, errors::OpenError};

use crate::{file_descriptors, litebox_fs};

pub(super) struct ElfFile {
    name: CString,
    fd: i32,
}

impl ElfFile {
    pub(super) fn from_path(path: &str) -> Result<Self, OpenError> {
        let file = litebox_fs().open(path, OFlags::RDWR, Mode::empty())?;
        let fd = file_descriptors()
            .write()
            .insert(crate::Descriptor::File(file))
            .try_into()
            .unwrap();

        Ok(Self {
            name: CString::from_str(path).unwrap(),
            fd,
        })
    }
}

impl ElfObject for ElfFile {
    fn file_name(&self) -> &core::ffi::CStr {
        &self.name
    }

    fn read(&mut self, buf: &mut [u8], offset: usize) -> elf_loader::Result<()> {
        if let Some(file) = file_descriptors().read().get_file_fd(self.fd as u32) {
            match litebox_fs().read(file, buf, Some(offset)) {
                Ok(_) => Ok(()),
                Err(_) => Err(elf_loader::Error::IOError {
                    msg: "failed to read from file".to_string(),
                }),
            }
        } else {
            Err(elf_loader::Error::IOError {
                msg: "failed to get file descriptor".to_string(),
            })
        }
    }

    fn as_fd(&self) -> Option<i32> {
        Some(self.fd)
    }
}
