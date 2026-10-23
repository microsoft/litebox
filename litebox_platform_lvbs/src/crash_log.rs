// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Crash log facility for LVBS
//! Log to internal VTL1 only ringbuffer, optionally mirroring
//! to serial port if debug is enabled. On panic, crash logger
//! will encrypt VTL1 buffer and dump it into VTL0 ringbuffer.
//! See `CrashDumpHeader` for crash dump format.

use aes_gcm::{AeadInOut, Aes256Gcm, KeyInit, Nonce};
use core::{
    panic::PanicInfo,
    sync::atomic::{AtomicBool, Ordering},
};
use litebox_common_lvbs::VsmError;
use log;
use rand_core::CryptoRngCore;
use rsa::{
    Oaep, RsaPublicKey,
    pkcs8::{DecodePublicKey, EncodePublicKey},
};
use sha2::{Digest, Sha256};
use spin::{Mutex, Once};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};
use zeroize::Zeroizing;

use crate::arch::ioport::{serial_print_panic_string, serial_print_string};

// Allocated in .bss which is in .data (x86_64_vtl1.ld), so keep
// reasoable size. Must be small enough to fit in VTL0 buffer (64K)
// along with crash dump metadata.
// TODO: Check VTL0 ringbuffer is always big enough
const CRASH_LOG_BUFFER_SIZE: usize = 16 * 1024;
// Large enough for RSA-2048 PEM publik key and SPKI header
const CRASH_LOG_MAX_PUBLIC_KEY_SIZE: usize = 512;

/// Unencrypted header describing crash dump. It will act as the AEAD
/// for the AES-GCM ecryptioon of the VTL1 ringbuffer.
/// Crash dump format:
/// ```text
/// +-----------------+-------------+------------+------+
/// | CrashDumpHeader | Wrapped Key | Ciphertext | Tag  |
/// +-----------------+-------------+------------+------+
/// ```
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct CrashDumpHeader {
    magic: [u8; 8],
    version: u32,
    header_size: u32,
    wrapped_key_size: u32,
    ciphertext_size: u32,
    crash_dump_key_id: [u8; CRASH_DUMP_KEY_ID_SIZE],
    nonce: [u8; CRASH_DUMP_NONCE_SIZE],
}

/// Allocation free ring buffer allows early log capture before heap setup.
struct ConstRingBuffer<const N: usize> {
    buf: [u8; N],
    head: usize,
    len: usize,
}

impl<const N: usize> ConstRingBuffer<N> {
    const fn new() -> Self {
        Self {
            buf: [0u8; N],
            head: 0,
            len: 0,
        }
    }

    fn write(&mut self, data: &[u8]) {
        if N == 0 || data.is_empty() {
            return;
        }
        let data = if data.len() > N {
            &data[data.len() - N..]
        } else {
            data
        };
        let tail = (self.head + self.len) % N;
        let first_len = data.len().min(N - tail);
        self.buf[tail..tail + first_len].copy_from_slice(&data[..first_len]);
        self.buf[..data.len() - first_len].copy_from_slice(&data[first_len..]);

        self.head = (self.head + data.len()) % N;
        self.len = (self.len + data.len()).min(N);
    }

    // Rotate buffer such that head is at position 0. Although O(n),
    // but only called once, on crash dump, removing the need to
    // allocate another buffer to copy into.
    fn read_contiguous(&mut self) -> &mut [u8] {
        self.buf[..N].rotate_left(self.head);
        self.head = 0;
        &mut self.buf[..self.len]
    }

    fn len(&self) -> usize {
        self.len
    }
}

const CRASH_DUMP_MAGIC: [u8; 8] = *b"LVBSDUMP";
const CRASH_DUMP_VERSION: u32 = 0x00_00_00_01;
// RSA-2048 DER is ~294 bytes, PEM is ~450 bytes
const CRASH_DUMP_KEY_MAX_SIZE: usize = 512;
// SHA-256 hash of crash dump key
const CRASH_DUMP_KEY_ID_SIZE: usize = 32;
// Up to AES-256-GCM
const CRASH_DUMP_DATA_KEY_SIZE: usize = 32;
// RSA-2048 encryption
const CRASH_DUMP_WRAPPED_DATA_KEY_SIZE: usize = 256;
const CRASH_DUMP_NONCE_SIZE: usize = 12;
const CRASH_DUMP_TAG_SIZE: usize = 16;

/// Construct parts of the sealed envelope before a panic to avoid
/// locks snd seeding delays in rng when generating nonce and DEK
struct PreparedEnvelope {
    // Prepared AES-256-GCM cipher consisting of:
    //     - KEK: Public key used to encrypt symmetric key
    //            crash_dump_key: [u8; CRASH_DUMP_KEY_SIZE],
    //     - DEK: Generated symmetric key to encrypt crash data
    //            data_key: Zeroizing<[u8; CRASH_DUMP_DATA_KEY_SIZE]>,
    cipher: Aes256Gcm,
    // Shorter hash of public KEK DER copied into crash dump header
    crash_dump_key_id: [u8; CRASH_DUMP_KEY_ID_SIZE],
    // DEK encrypted with KEK
    wrapped_data_key: [u8; CRASH_DUMP_WRAPPED_DATA_KEY_SIZE],
    nonce: [u8; CRASH_DUMP_NONCE_SIZE],
}

impl PreparedEnvelope {
    pub fn new(key_der: &[u8], rng: &mut impl CryptoRngCore) -> Result<Self, VsmError> {
        if key_der.is_empty() || key_der.len() > CRASH_DUMP_KEY_MAX_SIZE {
            return Err(VsmError::InvalidKey);
        }
        // Only SPKI supported. TODO: check if PKCS1 is needed.
        let crash_dump_key =
            RsaPublicKey::from_public_key_der(key_der).map_err(|_| VsmError::InvalidKey)?;
        let crash_dump_key_id: [u8; CRASH_DUMP_KEY_ID_SIZE] = Sha256::digest(
            crash_dump_key
                .to_public_key_der()
                .map_err(|_| VsmError::InvalidKey)?
                .as_bytes(),
        )
        .into();

        let mut data_key = Zeroizing::new([0u8; CRASH_DUMP_DATA_KEY_SIZE]);
        rng.fill_bytes(&mut *data_key);
        let wrapped_data_key = crash_dump_key
            .encrypt(rng, Oaep::new::<Sha256>(), &*data_key)
            .map_err(|_| VsmError::InvalidKey)?
            .as_slice()
            .try_into()
            .map_err(|_| VsmError::InvalidKey)?;

        let cipher = Aes256Gcm::new_from_slice(&*data_key).map_err(|_| VsmError::InvalidKey)?;

        Ok(Self {
            cipher,
            crash_dump_key_id,
            wrapped_data_key,
            nonce: [0u8; CRASH_DUMP_NONCE_SIZE],
        })
    }

    fn seal(&self, aead: &[u8], data: &mut [u8]) -> Result<[u8; CRASH_DUMP_TAG_SIZE], VsmError> {
        let tag = self
            .cipher
            .encrypt_inout_detached(&Nonce::from(self.nonce), aead, data.into())
            .map_err(|_| VsmError::InvalidKey)?;
        Ok(tag.into())
    }
}

/// Logger implements `log` facade and crash dump logic
pub struct CrashLogger {
    ring_buf: Mutex<ConstRingBuffer<CRASH_LOG_BUFFER_SIZE>>,
    envelope: Mutex<Option<PreparedEnvelope>>,
    serial_mirror: AtomicBool,
    panic_dump_started: AtomicBool,
}

impl CrashLogger {
    const fn new() -> Self {
        Self {
            ring_buf: Mutex::new(ConstRingBuffer::new()),
            envelope: Mutex::new(None),
            serial_mirror: AtomicBool::new(false),
            panic_dump_started: AtomicBool::new(false),
        }
    }

    pub fn mirror_to_serial(&self, enable: bool) {
        self.serial_mirror.store(enable, Ordering::Relaxed);
    }

    pub fn set_public_key(
        &self,
        key_der: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<(), VsmError> {
        let p = PreparedEnvelope::new(key_der, rng)?;
        if key_der.is_empty() || key_der.len() > CRASH_LOG_MAX_PUBLIC_KEY_SIZE {
            return Err(VsmError::InvalidKey);
        }
        //TODO; Check if we are already panicking
        self.envelope.lock().replace(p);
        Ok(())
    }

    pub fn dump_on_panic(&self, _info: &PanicInfo) -> Result<(), VsmError> {
        if self.panic_dump_started.swap(true, Ordering::SeqCst) {
            serial_print_panic_string("Crash dump already progress");
            return Err(VsmError::OutOfMemory);
        }

        let Some(envelope) = &*self.envelope.lock() else {
            return Err(VsmError::InvalidKey);
        };

        let ring_buffer = &mut *self.ring_buf.lock();

        let aead = CrashDumpHeader {
            magic: CRASH_DUMP_MAGIC,
            version: CRASH_DUMP_VERSION,
            header_size: u32::try_from(core::mem::size_of::<CrashDumpHeader>())
                .map_err(|_| VsmError::IntegerOverflow)?,
            wrapped_key_size: u32::try_from(CRASH_DUMP_WRAPPED_DATA_KEY_SIZE)
                .map_err(|_| VsmError::IntegerOverflow)?,
            ciphertext_size: u32::try_from(ring_buffer.len())
                .map_err(|_| VsmError::IntegerOverflow)?,
            crash_dump_key_id: envelope.crash_dump_key_id,
            nonce: envelope.nonce,
        };

        let tag = envelope.seal(aead.as_bytes(), ring_buffer.read_contiguous())?;
        // TODO: ringbuffer must already be created, otherwwisr pvmap might hold some locks?
        let Some(vtl0_buf) = crate::mshv::ringbuffer::ringbuffer() else {
            // TODO: Make errors from module more descriptive
            return Err(VsmError::InvalidKey);
        };
        let mut vtl0_buf = vtl0_buf.lock();
        vtl0_buf.write(aead.as_bytes());
        vtl0_buf.write(&envelope.wrapped_data_key);
        vtl0_buf.write(&envelope.crash_dump_key_id);
        vtl0_buf.write(ring_buffer.read_contiguous());
        vtl0_buf.write(&tag);

        Ok(())
    }
}

impl log::Log for CrashLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        let mut buf: arrayvec::ArrayString<1024> = arrayvec::ArrayString::new();
        if litebox_util_log::format_record(&mut buf, record).is_ok() {
            self.ring_buf.lock().write(buf.as_bytes());
        }
        if self.serial_mirror.load(Ordering::Relaxed) {
            serial_print_string(&buf);
        }
        //TODO: thers should be some policy on the minimum key modulus
    }

    fn flush(&self) {}
}

pub fn crash_logger() -> &'static CrashLogger {
    static CRASH_LOGGER_ONCE: Once<CrashLogger> = Once::new();
    CRASH_LOGGER_ONCE.call_once(|| {
        serial_print_string("***Setting up logger...");
        CrashLogger::new()
    })
}
