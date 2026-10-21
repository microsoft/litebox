// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Crash log facility for LVBS
//! Log to internal VTL1 only ringbuffer, optionally mirroring
//! to serial port. On panic, crash logger will optionally
//! encrypt VTL1 ringbuffer and dump it into VTL0 ringbuffer.
//! See `CrashDumpHeader` for crash dump format.

use crate::arch::ioport;
use aes_gcm::{AeadInOut, Aes256Gcm, KeyInit, Nonce};
use alloc::{boxed::Box, vec};
use core::fmt::Write;
use core::mem::size_of;
use core::{
    panic::PanicInfo,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};
use litebox_common_lvbs::VsmError;
use log;
use rand_core::CryptoRngCore;
use rsa::traits::PublicKeyParts;
use rsa::{
    Oaep, RsaPublicKey,
    pkcs1::DecodeRsaPublicKey,
    pkcs8::{DecodePublicKey, EncodePublicKey},
};
use sha2::{Digest, Sha256};
use spin::{Mutex, MutexGuard, Once};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};
use zeroize::Zeroizing;

const CRASH_LOG_BUFFER_SIZE: usize = 32 * 1024;

const CRASH_DUMP_MAGIC: [u8; 8] = *b"LVBSDUMP";
const CRASH_DUMP_VERSION: u32 = 0x00_00_00_01;

// Hold up to RSA-4096 in SPKI_DER format ~550 bytes
const CRASH_DUMP_KEY_MAX_SIZE: usize = 600;

// Based on RSA-4096 key
const CRASH_DUMP_WRAPPED_KEY_MAX_SIZE: usize = 512;

const CRASH_DUMP_KEY_MIN_RSA_BITS: usize = 2048;
const CRASH_DUMP_KEY_MAX_RSA_BITS: usize = 4096;

// SHA-256 hash of crash dump key
const CRASH_DUMP_KEY_ID_SIZE: usize = 32;

// AES-256-GCM
const CRASH_DUMP_DATA_KEY_SIZE: usize = 32;
const CRASH_DUMP_NONCE_SIZE: usize = 12;
const CRASH_DUMP_TAG_SIZE: usize = 16;

const CRASH_DUMP_WAIT_COUNT: usize = 1 << 31;
const CRASH_DUMP_TRY_LOCK_COUNT: usize = 1 << 20;

const INVALID_CPU_ID: usize = usize::MAX;

/// Crash dump format:
/// ```text
/// +-----------------+-------------+--------------+------+
/// | CrashDumpHeader | Wrapped Key | (Cipher)Text | Tag  |
/// +-----------------+-------------+--------------+------+
/// ```
/// CrashDumpHeader - Crash dump metadata (AAD)
/// Wrapped Key     - Optional Data Encryption Key (DEK - AES-256-GCM)
///                   wrapped by public RSA key
/// (Cipher)Text    - VTL1 ringbuffer optionally encrypted by DEK
/// Tag             - AES-256-GCM tag if logs are encrypted
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
const _: () = {
    assert!(size_of::<CrashDumpHeader>() == 68);
};

/// Fixed-capacity byte buffer that wraps around when full.
struct RingBuffer {
    buf: Box<[u8]>,
    head: usize,
    len: usize,
    // On panic, crash log is encrypted in place on a CPU. Flag
    // prevents some other CPUs from logging during encryption.
    panic_mode: bool,
}

impl RingBuffer {
    fn new(capacity: usize) -> Self {
        Self {
            // Convert to fixed size heap to avoid Vec dynamic resize
            buf: vec![0u8; capacity].into_boxed_slice(),
            head: 0,
            len: 0,
            panic_mode: false,
        }
    }

    fn write(&mut self, data: &[u8]) {
        let capacity = self.buf.len();
        if capacity == 0 || data.is_empty() {
            return;
        }
        let data = if data.len() > capacity {
            &data[data.len() - capacity..]
        } else {
            data
        };
        let tail = (self.head + self.len) % capacity;
        let first_len = data.len().min(capacity - tail);
        self.buf[tail..tail + first_len].copy_from_slice(&data[..first_len]);
        self.buf[..data.len() - first_len].copy_from_slice(&data[first_len..]);

        let len = self.len + data.len();
        if len > capacity {
            self.head = (self.head + len - capacity) % capacity;
            self.len = capacity;
        } else {
            self.len = len;
        }
    }

    // Rotate buffer such that head is at position 0
    fn make_contiguous(&mut self) -> &mut [u8] {
        self.buf.rotate_left(self.head);
        self.head = 0;
        &mut self.buf[..self.len]
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.len
    }
}

/// Construct parts of the sealed envelope before a panic to avoid
/// locks and seeding delays in rng when generating nonce and DEK
struct PreparedEnvelope {
    // Prepared AES-256-GCM cipher consisting of:
    //     - KEK: Public RSA key used to encrypt symmetric key
    //            crash_dump_key: [u8; CRASH_DUMP_KEY_SIZE],
    //     - DEK: Generated symmetric key (AES-256-GCM) to encrypt crash data
    //            data_key: Zeroizing<[u8; CRASH_DUMP_DATA_KEY_SIZE]>,
    cipher: Aes256Gcm,
    // Hash of public KEK DER copied into crash dump header
    crash_dump_key_id: [u8; CRASH_DUMP_KEY_ID_SIZE],
    // DEK encrypted with KEK
    wrapped_data_key: Box<[u8]>,
    nonce: [u8; CRASH_DUMP_NONCE_SIZE],
}

impl PreparedEnvelope {
    pub fn new(key_der: &[u8], rng: &mut impl CryptoRngCore) -> Result<Self, VsmError> {
        if key_der.is_empty() || key_der.len() > CRASH_DUMP_KEY_MAX_SIZE {
            return Err(VsmError::InvalidKey("Crash dump key too big"));
        }
        let crash_dump_key = RsaPublicKey::from_public_key_der(key_der)
            .or_else(|_| RsaPublicKey::from_pkcs1_der(key_der))
            .map_err(|_| VsmError::InvalidKey("Unknown DER format"))?;

        let bits = crash_dump_key.n().bits();
        if !(CRASH_DUMP_KEY_MIN_RSA_BITS..=CRASH_DUMP_KEY_MAX_RSA_BITS).contains(&bits) {
            return Err(VsmError::InvalidKey("Unsupported RSA public key size"));
        }

        let crash_dump_key_id: [u8; CRASH_DUMP_KEY_ID_SIZE] = Sha256::digest(
            crash_dump_key
                .to_public_key_der()
                .map_err(|_| VsmError::InvalidKey("DER conversion"))?
                .as_bytes(),
        )
        .into();

        let mut data_key = Zeroizing::new([0u8; CRASH_DUMP_DATA_KEY_SIZE]);
        rng.fill_bytes(&mut *data_key);
        let wrapped_data_key = crash_dump_key
            .encrypt(rng, Oaep::new::<Sha256>(), &*data_key)
            .map_err(|_| VsmError::CipherOpFailed("Unable to wrap key"))?
            .into_boxed_slice();

        let cipher = Aes256Gcm::new_from_slice(&*data_key)
            .map_err(|_| VsmError::CipherOpFailed("Unable to create AES-GCM cipher"))?;

        Ok(Self {
            cipher,
            crash_dump_key_id,
            wrapped_data_key,
            nonce: [0u8; CRASH_DUMP_NONCE_SIZE],
        })
    }

    fn seal(&self, aad: &[u8], data: &mut [u8]) -> Result<[u8; CRASH_DUMP_TAG_SIZE], VsmError> {
        let tag = self
            .cipher
            .encrypt_inout_detached(&Nonce::from(self.nonce), aad, data.into())
            .map_err(|_| VsmError::CipherOpFailed("AES-GCM encryption failed"))?;
        Ok(tag.into())
    }
}

/// Logger implements `log` facade and crash dump logic
pub struct CrashLogger {
    ring_buf: Mutex<RingBuffer>,
    envelope: Mutex<Option<PreparedEnvelope>>,
    serial_mirror: AtomicBool,
    dump_done: AtomicBool,
    dumping_cpu: AtomicUsize,
}

impl CrashLogger {
    fn new() -> Self {
        Self {
            ring_buf: Mutex::new(RingBuffer::new(CRASH_LOG_BUFFER_SIZE)),
            envelope: Mutex::new(None),
            serial_mirror: AtomicBool::new(false),
            dump_done: AtomicBool::new(false),
            dumping_cpu: AtomicUsize::new(INVALID_CPU_ID),
        }
    }

    pub fn mirror_to_serial(&self, enable: bool) {
        self.serial_mirror.store(enable, Ordering::SeqCst);
    }

    pub const fn max_size() -> usize {
        size_of::<CrashDumpHeader>()
            + CRASH_DUMP_WRAPPED_KEY_MAX_SIZE
            + CRASH_LOG_BUFFER_SIZE
            + CRASH_DUMP_TAG_SIZE
    }

    pub fn set_public_key(
        &self,
        key_der: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<(), VsmError> {
        if self.dumping_cpu.load(Ordering::SeqCst) != INVALID_CPU_ID {
            return Err(VsmError::OperationNotSupported("Cant set key in panic"));
        }
        let envelope = PreparedEnvelope::new(key_der, rng)?;
        self.envelope.lock().replace(envelope);

        // If public key is installed, disable serial logs for release builds
        if cfg!(not(debug_assertions)) {
            log::info!("Crash key set, disabling serial logs...");
            self.mirror_to_serial(false);
        }
        Ok(())
    }

    pub fn panic_dump(&self, info: &PanicInfo) -> Result<(), VsmError> {
        let cpu = crate::arch::get_core_id();

        if let Err(dumping_cpu) = self.dumping_cpu.compare_exchange(
            INVALID_CPU_ID,
            cpu,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            // dumping_cpu != INVALID_CPU_ID => panic in progress
            if cpu == dumping_cpu {
                if let Some(mut com) = ioport::try_com().and_then(try_lock_bounded) {
                    let _ = writeln!(com, "Nested panic on cpu {dumping_cpu}");
                }
            } else {
                // Wait for crash dump completion on dumping cpu instead of halt
                // so cpu can return to VTL0.
                if let Some(mut com) = ioport::try_com().and_then(try_lock_bounded) {
                    let _ = writeln!(com, "Panic dump in progress on cpu {dumping_cpu}");
                }
                for _ in 0..CRASH_DUMP_WAIT_COUNT {
                    if self.dump_done.load(Ordering::SeqCst) {
                        break;
                    }
                    core::hint::spin_loop();
                }
            }
            // Only capture the first panic
            return Err(VsmError::OperationNotSupported("Panic already in progress"));
        }

        if let Some(mut ring) = try_lock_bounded(&self.ring_buf) {
            ring.panic_mode = true;
        }

        // This CPU owns the dump, so log() will take panic-safe path
        log::error!("{info}");

        let result = self.dump_once();
        self.dump_done.store(true, Ordering::SeqCst);
        result
    }

    fn dump_once(&self) -> Result<(), VsmError> {
        let envelope_guard = try_lock_bounded(&self.envelope)
            .ok_or(VsmError::OperationTimeout("Get crash envelope"))?;
        let envelope = envelope_guard.as_ref();

        let (wrapped_data_key_len, tag_size, crash_dump_key_id, nonce) = match envelope {
            Some(e) => (
                e.wrapped_data_key.len(),
                CRASH_DUMP_TAG_SIZE,
                e.crash_dump_key_id,
                e.nonce,
            ),
            None => (
                0,
                0,
                [0u8; CRASH_DUMP_KEY_ID_SIZE],
                [0u8; CRASH_DUMP_NONCE_SIZE],
            ),
        };

        let mut ring_buffer = try_lock_bounded(&self.ring_buf)
            .ok_or(VsmError::OperationTimeout("Get VTL0 ring buffer"))?;
        let log = ring_buffer.make_contiguous();

        let Some(vtl0_buf) = crate::mshv::ringbuffer::ringbuffer() else {
            return Err(VsmError::OutOfMemory);
        };

        // Only crash_log uses vtl0_buf(), so this lock will always succeed.
        // vtl0_buf.lock() does NOT allocate so try_lock() version not needed.
        // TODO: Hide Vtl0RingBuffer in CrashLogger, remove lock and rename
        // ringbuffer.rs to vtl0_ringbuffer.rs. vtl0_buf write()
        // hold a lock as well.
        let mut vtl0_buf = vtl0_buf.lock();
        let overhead = size_of::<CrashDumpHeader>() + wrapped_data_key_len + tag_size;
        let max_vtl0_log_size = vtl0_buf
            .capacity()
            .checked_sub(overhead)
            .ok_or(VsmError::IntegerOverflow)?;

        let start = log.len().saturating_sub(max_vtl0_log_size);
        // Drop the oldest bytes if the whole log can't fit.
        let log = &mut log[start..];

        let header = CrashDumpHeader {
            magic: CRASH_DUMP_MAGIC,
            version: CRASH_DUMP_VERSION,
            header_size: u32::try_from(size_of::<CrashDumpHeader>())
                .map_err(|_| VsmError::IntegerOverflow)?,
            wrapped_key_size: u32::try_from(wrapped_data_key_len)
                .map_err(|_| VsmError::IntegerOverflow)?,
            ciphertext_size: u32::try_from(log.len()).map_err(|_| VsmError::IntegerOverflow)?,
            crash_dump_key_id,
            nonce,
        };

        let tag = envelope
            .map(|e| e.seal(header.as_bytes(), log))
            .transpose()?;

        vtl0_buf.write(header.as_bytes());
        if let Some(e) = envelope {
            vtl0_buf.write(&e.wrapped_data_key);
        }
        vtl0_buf.write(log);
        if let Some(tag) = &tag {
            vtl0_buf.write(tag);
        }

        Ok(())
    }

    fn cpu_in_panic(&self) -> Option<usize> {
        let panic_cpu = self.dumping_cpu.load(Ordering::SeqCst);
        (panic_cpu != INVALID_CPU_ID).then_some(panic_cpu)
    }
}

impl log::Log for CrashLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        let mut buf: arrayvec::ArrayString<1024> = arrayvec::ArrayString::new();
        let _ = litebox_util_log::format_record(&mut buf, record);

        let Some(mut ring_buf) = try_lock_bounded(&self.ring_buf) else {
            return;
        };
        if ring_buf.panic_mode && self.cpu_in_panic() != Some(crate::arch::get_core_id()) {
            return;
        }
        ring_buf.write(buf.as_bytes());
        // Don't hold the ring across the slow serial write.
        drop(ring_buf);

        if self.serial_mirror.load(Ordering::SeqCst)
            && let Some(mut com) = ioport::try_com().and_then(try_lock_bounded)
        {
            com.write_string(&buf);
        }
    }

    fn flush(&self) {}
}

static CRASH_LOGGER_ONCE: Once<CrashLogger> = Once::new();

pub fn crash_logger() -> &'static CrashLogger {
    CRASH_LOGGER_ONCE.call_once(CrashLogger::new)
}

/// Returns the crash logger only if it already exists; never allocates,
/// so safe on the panic path.
pub fn try_crash_logger() -> Option<&'static CrashLogger> {
    CRASH_LOGGER_ONCE.get()
}

fn try_lock_bounded<T>(mutex: &Mutex<T>) -> Option<MutexGuard<'_, T>> {
    for _tries in 0..CRASH_DUMP_TRY_LOCK_COUNT {
        if let Some(guard) = mutex.try_lock() {
            return Some(guard);
        }
        core::hint::spin_loop();
    }
    None
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::RingBuffer;
    use alloc::vec::Vec;

    fn contents(ring: &mut RingBuffer) -> Vec<u8> {
        ring.make_contiguous().to_vec()
    }

    #[test]
    fn empty_and_zero_capacity_buffers_read_nothing() {
        let mut ring = RingBuffer::new(8);
        ring.write(b"");
        assert_eq!(ring.len(), 0);
        assert_eq!(ring.make_contiguous(), []);

        let mut ring = RingBuffer::new(0);
        ring.write(b"abc");
        assert_eq!(ring.len(), 0);
        assert_eq!(ring.make_contiguous(), []);
    }

    #[test]
    fn single_write_before_wrap() {
        let mut ring = RingBuffer::new(8);
        ring.write(b"abc");
        assert_eq!(ring.len(), 3);
        assert_eq!(contents(&mut ring), b"abc");
    }

    #[test]
    fn consecutive_writes_before_wrap_keep_order() {
        let mut ring = RingBuffer::new(8);
        ring.write(b"abc");
        ring.write(b"de");
        assert_eq!(contents(&mut ring), b"abcde");
    }

    #[test]
    fn partial_overwrite_drops_oldest_bytes() {
        let mut ring = RingBuffer::new(4);
        ring.write(b"abc");
        ring.write(b"def");
        assert_eq!(ring.len(), 4);
        assert_eq!(contents(&mut ring), b"cdef");
    }

    #[test]
    fn oversized_write_keeps_last_n_bytes() {
        let mut ring = RingBuffer::new(4);
        ring.write(b"ab");
        ring.write(b"0123456789");
        assert_eq!(contents(&mut ring), b"6789");
    }

    #[test]
    fn writes_after_read_continue_in_order() {
        let mut ring = RingBuffer::new(8);
        ring.write(b"abcdef");
        assert_eq!(contents(&mut ring), b"abcdef");
        ring.write(b"ghij");
        assert_eq!(contents(&mut ring), b"cdefghij");
    }

    #[test]
    fn matches_reference_model_after_every_write() {
        const N: usize = 7;
        const CHUNK_LENS: [usize; 12] = [1, 0, 3, 6, 7, 2, 9, 4, 5, 13, 1, 1];
        // Fresh ring per prefix so reads don't reset `head` between writes.
        for steps in 0..=CHUNK_LENS.len() {
            std::println!("Step {steps}");
            let mut ring = RingBuffer::new(N);
            let mut model = Vec::new();
            let mut next = 0u8;
            for &chunk_len in &CHUNK_LENS[..steps] {
                let chunk: Vec<u8> = (0..chunk_len)
                    .map(|_| {
                        next = next.wrapping_add(1);
                        next
                    })
                    .collect();
                ring.write(&chunk);
                model.extend_from_slice(&chunk);
                let overflow = model.len().saturating_sub(N);
                model.drain(..overflow);
            }
            assert_eq!(ring.len(), model.len(), "after {steps} writes");
            assert_eq!(contents(&mut ring), model, "after {steps} writes");
        }
    }

    #[test]
    fn spki_and_pkcs1_keys_give_same_key_id() {
        use rand_core::SeedableRng;
        use rsa::{BigUint, RsaPublicKey, pkcs1::EncodeRsaPublicKey, pkcs8::EncodePublicKey};

        // Encryption only needs an odd modulus of the right size, not a real key pair.
        let key = RsaPublicKey::new(
            BigUint::from_bytes_be(&[0xff; 256]),
            BigUint::from(65_537u32),
        )
        .unwrap();
        let spki = key.to_public_key_der().unwrap();
        let pkcs1 = key.to_pkcs1_der().unwrap();
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([7; 32]);

        let from_spki = super::PreparedEnvelope::new(spki.as_bytes(), &mut rng).unwrap();
        let from_pkcs1 = super::PreparedEnvelope::new(pkcs1.as_bytes(), &mut rng).unwrap();
        assert_eq!(from_spki.crash_dump_key_id, from_pkcs1.crash_dump_key_id);
    }
}
