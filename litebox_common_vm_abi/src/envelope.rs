// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The format of [`Message`](crate::Message)s: a table of parts that wrap
//! another ABI, read in place. Borrowed from FlatBuffers and Cap'n Proto:
//! offsets into the message, no parsing to reach a part. From protobuf: tagged
//! parts that readers skip if unknown.
//!
//! ```text
//! 0:  Header { protocol, part_count }
//! 8:  Part[part_count] { kind, flags, offset, len }
//! ..: part data
//! ```
//!
//! [`Envelope::parse`] checks:
//! - At most [`MAX_PARTS`] parts, each past the table, inside the message,
//!   [`ALIGN`]-aligned, and disjoint from the others.
//! - Exactly one [`PartKind::PAYLOAD`].
//! - No unknown flags, and no unknown kind marked [`PartFlags::REQUIRED`]; other
//!   unknown kinds are skipped.
//!
//! Kinds, flags, and protocols are never reused.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Of every part's offset.
pub const ALIGN: u64 = 8;

pub const MAX_PARTS: usize = 16;

/// The wrapped ABI, which defines what the parts mean.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(transparent)]
pub struct Protocol(pub u32);

impl Protocol {
    /// OP-TEE's `optee_msg_arg` as the payload. Memrefs are `RMEM` parameters
    /// whose `shm_ref` is the index of a [`PartKind::BUFFER`] part. The
    /// process identity is the TA's UUID (`TEE_UUID` memory layout),
    /// zero-padded; the images are `ldelf`, then the TA.
    pub const OPTEE_MSG: Self = Self(1);
}

#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(transparent)]
pub struct PartKind(pub u32);

impl PartKind {
    /// The wrapped ABI's message.
    pub const PAYLOAD: Self = Self(1);
    /// Data that the payload refers to by part index.
    pub const BUFFER: Self = Self(2);

    const fn is_known(self) -> bool {
        matches!(self.0, 1 | 2)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct Header {
    pub protocol: Protocol,
    pub part_count: u32,
}

/// `offset` is from the start of the message.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C)]
pub struct Part {
    pub kind: PartKind,
    pub flags: PartFlags,
    pub offset: u64,
    pub len: u64,
}

#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(transparent)]
pub struct PartFlags(u32);

impl PartFlags {
    pub const NONE: Self = Self(0);
    /// A reader that does not know the part's kind must reject the message.
    pub const REQUIRED: Self = Self(1);

    const KNOWN: u32 = Self::REQUIRED.0;

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    const fn is_known(self) -> bool {
        self.0 & !Self::KNOWN == 0
    }
}

impl Part {
    /// Within the message, once [`Envelope::parse`] has accepted it.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the message fits in memory"
    )]
    pub const fn range(&self) -> core::ops::Range<usize> {
        self.offset as usize..(self.offset + self.len) as usize
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("shorter than its header or part table")]
    Truncated,
    #[error("too many parts")]
    TooManyParts,
    #[error("a part overlaps the table, extends past the message, or is misaligned")]
    Misplaced,
    #[error("parts overlap")]
    Overlapping,
    #[error("unknown part flags")]
    UnknownFlags,
    #[error("an unknown part is required")]
    UnknownRequiredPart,
    #[error("not exactly one payload")]
    Payload,
}

const fn table_end(part_count: usize) -> u64 {
    (size_of::<Header>() + part_count * size_of::<Part>()) as u64
}

/// A message whose framing has been checked; its data is read in place.
pub struct Envelope<'a> {
    bytes: &'a [u8],
    protocol: Protocol,
    parts: [Part; MAX_PARTS],
    part_count: usize,
    payload: usize,
}

impl<'a> Envelope<'a> {
    /// # Errors
    ///
    /// See the [module docs](self).
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let (header, rest) = Header::read_from_prefix(bytes).map_err(|_| Error::Truncated)?;
        let part_count = usize::try_from(header.part_count).map_err(|_| Error::TooManyParts)?;
        if part_count > MAX_PARTS {
            return Err(Error::TooManyParts);
        }
        let mut parts = [Part::default(); MAX_PARTS];
        for (i, part) in parts.iter_mut().take(part_count).enumerate() {
            *part = Part::read_from_prefix(&rest[i * size_of::<Part>()..])
                .map_err(|_| Error::Truncated)?
                .0;
        }
        let parts_slice = &parts[..part_count];
        let mut payload = None;
        for (i, part) in parts_slice.iter().enumerate() {
            if !part.flags.is_known() {
                return Err(Error::UnknownFlags);
            }
            let end = part.offset.checked_add(part.len).ok_or(Error::Misplaced)?;
            if part.offset < table_end(part_count)
                || end > bytes.len() as u64
                || !part.offset.is_multiple_of(ALIGN)
            {
                return Err(Error::Misplaced);
            }
            let disjoint = |other: &Part| {
                part.len == 0
                    || other.len == 0
                    || end <= other.offset
                    || other.offset + other.len <= part.offset
            };
            if !parts_slice[..i].iter().all(disjoint) {
                return Err(Error::Overlapping);
            }
            if !part.kind.is_known() && part.flags.contains(PartFlags::REQUIRED) {
                return Err(Error::UnknownRequiredPart);
            }
            if part.kind == PartKind::PAYLOAD && payload.replace(i).is_some() {
                return Err(Error::Payload);
            }
        }
        Ok(Self {
            bytes,
            protocol: header.protocol,
            parts,
            part_count,
            payload: payload.ok_or(Error::Payload)?,
        })
    }

    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    pub fn parts(&self) -> &[Part] {
        &self.parts[..self.part_count]
    }

    pub fn payload(&self) -> &'a [u8] {
        &self.bytes[self.parts[self.payload].range()]
    }

    pub fn payload_part(&self) -> &Part {
        &self.parts[self.payload]
    }

    pub fn part(&self, index: usize) -> Option<&Part> {
        self.parts().get(index)
    }

    /// `None` unless part `index` is a [`PartKind::BUFFER`].
    pub fn buffer(&self, index: usize) -> Option<&'a [u8]> {
        let part = self.parts().get(index)?;
        (part.kind == PartKind::BUFFER).then(|| &self.bytes[part.range()])
    }
}

/// Where a writer puts each part: in order after the table, each aligned.
pub struct Layout {
    header: Header,
    parts: [Part; MAX_PARTS],
    len: u64,
}

impl Layout {
    /// # Errors
    ///
    /// [`Error::TooManyParts`]; [`Error::Payload`] unless exactly one part is
    /// a [`PartKind::PAYLOAD`].
    pub fn new(protocol: Protocol, parts: &[(PartKind, u64)]) -> Result<Self, Error> {
        if parts.len() > MAX_PARTS {
            return Err(Error::TooManyParts);
        }
        if parts
            .iter()
            .filter(|(kind, _)| *kind == PartKind::PAYLOAD)
            .count()
            != 1
        {
            return Err(Error::Payload);
        }
        let mut layout = Self {
            header: Header {
                protocol,
                part_count: u32::try_from(parts.len()).map_err(|_| Error::TooManyParts)?,
            },
            parts: [Part::default(); MAX_PARTS],
            len: table_end(parts.len()),
        };
        for (part, &(kind, len)) in layout.parts.iter_mut().zip(parts) {
            let offset = layout
                .len
                .checked_next_multiple_of(ALIGN)
                .ok_or(Error::Misplaced)?;
            *part = Part {
                kind,
                flags: PartFlags::NONE,
                offset,
                len,
            };
            layout.len = offset.checked_add(len).ok_or(Error::Misplaced)?;
        }
        Ok(layout)
    }

    pub fn message_len(&self) -> u64 {
        self.len
    }

    pub fn parts(&self) -> &[Part] {
        &self.parts[..self.header.part_count as usize]
    }

    /// Writes the header and part table; part data is the caller's.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] if `message` is shorter than
    /// [`Self::message_len`].
    pub fn write_table(&self, message: &mut [u8]) -> Result<(), Error> {
        if (message.len() as u64) < self.len {
            return Err(Error::Truncated);
        }
        let header = self.header.as_bytes();
        message[..header.len()].copy_from_slice(header);
        let table = self.parts().as_bytes();
        message[header.len()..header.len() + table.len()].copy_from_slice(table);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(parts: &[(PartKind, u64)]) -> ([u8; 256], Layout) {
        let layout = Layout::new(Protocol::OPTEE_MSG, parts).unwrap();
        let mut bytes = [0u8; 256];
        layout.write_table(&mut bytes).unwrap();
        (bytes, layout)
    }

    fn write_part(bytes: &mut [u8], index: usize, part: Part) {
        let offset = size_of::<Header>() + index * size_of::<Part>();
        bytes[offset..offset + size_of::<Part>()].copy_from_slice(part.as_bytes());
    }

    #[test]
    fn written_envelopes_parse() {
        let (mut bytes, layout) = message(&[(PartKind::PAYLOAD, 5), (PartKind::BUFFER, 3)]);
        bytes[layout.parts()[0].range()].copy_from_slice(b"hello");
        bytes[layout.parts()[1].range()].copy_from_slice(b"abc");
        let envelope =
            Envelope::parse(&bytes[..usize::try_from(layout.message_len()).unwrap()]).unwrap();
        assert_eq!(envelope.protocol(), Protocol::OPTEE_MSG);
        assert_eq!(envelope.payload(), b"hello");
        assert_eq!(envelope.buffer(1), Some(&b"abc"[..]));
        assert_eq!(envelope.buffer(0), None, "the payload is not a buffer");
        assert!(
            envelope
                .parts()
                .iter()
                .all(|p| p.offset.is_multiple_of(ALIGN))
        );
    }

    #[test]
    fn framing_is_checked() {
        let (bytes, layout) = message(&[(PartKind::PAYLOAD, 8), (PartKind::BUFFER, 8)]);
        let good = layout.parts()[1];
        let with = |part: Part| {
            let mut bytes = bytes;
            write_part(&mut bytes, 1, part);
            Envelope::parse(&bytes).err()
        };
        assert_eq!(with(good), None);
        assert_eq!(with(Part { offset: 8, ..good }), Some(Error::Misplaced));
        assert_eq!(
            with(Part {
                offset: u64::MAX - 7,
                len: 16,
                ..good
            }),
            Some(Error::Misplaced),
            "offset + len overflows"
        );
        assert_eq!(
            with(Part {
                len: u64::MAX,
                ..good
            }),
            Some(Error::Misplaced)
        );
        assert_eq!(
            with(Part {
                offset: 300,
                ..good
            }),
            Some(Error::Misplaced)
        );
        assert_eq!(
            with(Part {
                offset: good.offset + 1,
                ..good
            }),
            Some(Error::Misplaced)
        );
        let payload = layout.parts()[0];
        assert_eq!(
            with(Part {
                offset: payload.offset,
                ..good
            }),
            Some(Error::Overlapping)
        );
        assert_eq!(
            with(Part {
                flags: PartFlags(2),
                ..good
            }),
            Some(Error::UnknownFlags)
        );
        assert_eq!(
            with(Part {
                kind: PartKind::PAYLOAD,
                ..good
            }),
            Some(Error::Payload)
        );
        let unknown = Part {
            kind: PartKind(99),
            ..good
        };
        assert_eq!(with(unknown), None, "unknown parts are skipped");
        assert_eq!(
            with(Part {
                flags: PartFlags::REQUIRED,
                ..unknown
            }),
            Some(Error::UnknownRequiredPart)
        );
        assert_eq!(Envelope::parse(&bytes[..4]).err(), Some(Error::Truncated));
        let mut too_many = bytes;
        too_many[4] = 17;
        assert_eq!(Envelope::parse(&too_many).err(), Some(Error::TooManyParts));
        assert_eq!(
            Layout::new(Protocol::OPTEE_MSG, &[(PartKind::BUFFER, 1)]).err(),
            Some(Error::Payload)
        );
        let huge = [(PartKind::PAYLOAD, 1), (PartKind::BUFFER, u64::MAX - 8)];
        assert_eq!(
            Layout::new(Protocol::OPTEE_MSG, &huge).err(),
            Some(Error::Misplaced)
        );
    }
}
