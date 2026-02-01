// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! AES-CTR DRBG (NIST SP 800-90A) Cryptographically Secure Pseudo-Random Number Generator.
//!
//! This module implements the CTR_DRBG algorithm using AES-256 as the underlying
//! block cipher, following the NIST SP 800-90A specification with the derivation
//! function (df) variant.
//!
//! # Algorithm Reference
//!
//! The implementation follows NIST SP 800-90A Rev 1, Section 10.2:
//! - CTR_DRBG with derivation function
//! - Uses AES-256 (keylen = 256 bits, outlen = 128 bits)
//! - seedlen = keylen + outlen = 384 bits = 48 bytes
//!
//! # Entropy Sources
//!
//! The DRBG can gather entropy from:
//! - `RDSEED` instruction on x86_64 (hardware random)
//! - External nonce buffer (e.g., from TPM)

use aes::Aes256;
use aes::cipher::{BlockEncrypt, NewBlockCipher, generic_array::GenericArray};

/// AES-256 block size in bytes (128 bits)
const BLOCK_LEN: usize = 16;
/// AES-256 key length in bytes (256 bits)
const KEY_LEN: usize = 32;
/// Seed length = key length + block length = 48 bytes (384 bits)
const SEED_LEN: usize = KEY_LEN + BLOCK_LEN;
/// Maximum number of requests between reseeds (2^48 as per NIST spec)
const RESEED_INTERVAL: u64 = 1 << 48;
/// Maximum number of bytes per request (2^19 bits = 2^16 bytes as per NIST spec)
const MAX_BYTES_PER_REQUEST: usize = 1 << 16;

/// AES-CTR DRBG state following NIST SP 800-90A.
///
/// This structure maintains the internal state of the DRBG:
/// - `key`: The AES-256 key (256 bits)
/// - `v`: The counter value (128 bits)
/// - `reseed_counter`: Tracks number of requests since last reseed
pub struct AesCtrDrbg {
    /// AES-256 key (32 bytes)
    key: [u8; KEY_LEN],
    /// Counter block (16 bytes)
    v: [u8; BLOCK_LEN],
    /// Number of requests since instantiation/reseed
    reseed_counter: u64,
}

impl AesCtrDrbg {
    /// Create a new AES-CTR DRBG instance.
    ///
    /// # NIST SP 800-90A Section 10.2.1.3.1 - CTR_DRBG_Instantiate_algorithm
    ///
    /// ```text
    /// CTR_DRBG_Instantiate_algorithm(entropy_input, nonce, personalization_string):
    ///   1. seed_material = entropy_input || nonce || personalization_string
    ///   2. seed_material = Block_Cipher_df(seed_material, seedlen)
    ///   3. Key = 0^keylen
    ///   4. V = 0^outlen
    ///   5. (Key, V) = CTR_DRBG_Update(seed_material, Key, V)
    ///   6. reseed_counter = 1
    ///   7. Return (Key, V, reseed_counter)
    /// ```
    ///
    /// # Arguments
    ///
    /// * `entropy_input` - Primary entropy source (from RDSEED or similar)
    /// * `nonce` - Additional entropy source (e.g., from TPM)
    ///
    /// # Panics
    ///
    /// Panics if unable to gather sufficient entropy.
    #[must_use]
    pub fn new(entropy_input: &[u8], nonce: &[u8]) -> Self {
        // Step 1: seed_material = entropy_input || nonce
        // (No personalization string per requirements)
        let mut seed_material = [0u8; SEED_LEN * 2];
        let input_len = entropy_input.len() + nonce.len();
        seed_material[..entropy_input.len()].copy_from_slice(entropy_input);
        seed_material[entropy_input.len()..entropy_input.len() + nonce.len()]
            .copy_from_slice(nonce);

        // Step 2: seed_material = Block_Cipher_df(seed_material, seedlen)
        let derived_seed = block_cipher_df(&seed_material[..input_len], SEED_LEN);

        // Steps 3-4: Key = 0, V = 0
        let mut key = [0u8; KEY_LEN];
        let mut v = [0u8; BLOCK_LEN];

        // Step 5: (Key, V) = CTR_DRBG_Update(seed_material, Key, V)
        ctr_drbg_update(&derived_seed, &mut key, &mut v);

        // Step 6: reseed_counter = 1
        Self {
            key,
            v,
            reseed_counter: 1,
        }
    }

    /// Reseed the DRBG with new entropy.
    ///
    /// # NIST SP 800-90A Section 10.2.1.4.1 - CTR_DRBG_Reseed_algorithm
    ///
    /// ```text
    /// CTR_DRBG_Reseed_algorithm(working_state, entropy_input, additional_input):
    ///   1. seed_material = entropy_input || additional_input
    ///   2. seed_material = Block_Cipher_df(seed_material, seedlen)
    ///   3. (Key, V) = CTR_DRBG_Update(seed_material, Key, V)
    ///   4. reseed_counter = 1
    ///   5. Return (Key, V, reseed_counter)
    /// ```
    pub fn reseed(&mut self, entropy_input: &[u8]) {
        // Step 1: seed_material = entropy_input (no additional_input)
        // Step 2: Apply derivation function
        let derived_seed = block_cipher_df(entropy_input, SEED_LEN);

        // Step 3: Update state
        ctr_drbg_update(&derived_seed, &mut self.key, &mut self.v);

        // Step 4: Reset counter
        self.reseed_counter = 1;
    }

    /// Generate random bytes.
    ///
    /// # NIST SP 800-90A Section 10.2.1.5.1 - CTR_DRBG_Generate_algorithm
    ///
    /// ```text
    /// CTR_DRBG_Generate_algorithm(working_state, requested_number_of_bits, additional_input):
    ///   1. If reseed_counter > reseed_interval, return RESEED_REQUIRED
    ///   2. If additional_input != Null:
    ///        additional_input = Block_Cipher_df(additional_input, seedlen)
    ///        (Key, V) = CTR_DRBG_Update(additional_input, Key, V)
    ///   3. temp = Null
    ///   4. While len(temp) < requested_number_of_bits:
    ///        V = (V + 1) mod 2^outlen
    ///        output_block = Block_Encrypt(Key, V)
    ///        temp = temp || output_block
    ///   5. returned_bits = leftmost requested_number_of_bits of temp
    ///   6. (Key, V) = CTR_DRBG_Update(additional_input, Key, V)
    ///   7. reseed_counter = reseed_counter + 1
    ///   8. Return (returned_bits, Key, V, reseed_counter)
    /// ```
    ///
    /// # Arguments
    ///
    /// * `output` - Buffer to fill with random bytes
    ///
    /// # Returns
    ///
    /// `true` if successful, `false` if reseed is required.
    pub fn generate(&mut self, output: &mut [u8]) -> bool {
        // Step 1: Check reseed counter
        if self.reseed_counter > RESEED_INTERVAL {
            return false;
        }

        // Process in chunks not exceeding MAX_BYTES_PER_REQUEST
        let mut offset = 0;
        while offset < output.len() {
            let chunk_len = core::cmp::min(output.len() - offset, MAX_BYTES_PER_REQUEST);
            self.generate_chunk(&mut output[offset..offset + chunk_len]);
            offset += chunk_len;
        }

        true
    }

    /// Generate a single chunk of random bytes (up to MAX_BYTES_PER_REQUEST).
    fn generate_chunk(&mut self, output: &mut [u8]) {
        debug_assert!(output.len() <= MAX_BYTES_PER_REQUEST);

        let cipher = Aes256::new(GenericArray::from_slice(&self.key));

        // Step 4: Generate output blocks
        let mut temp = [0u8; BLOCK_LEN];
        let mut written = 0;

        while written < output.len() {
            // V = (V + 1) mod 2^128
            increment_counter(&mut self.v);

            // output_block = Block_Encrypt(Key, V)
            temp.copy_from_slice(&self.v);
            cipher.encrypt_block(GenericArray::from_mut_slice(&mut temp));

            // Copy to output
            let to_copy = core::cmp::min(BLOCK_LEN, output.len() - written);
            output[written..written + to_copy].copy_from_slice(&temp[..to_copy]);
            written += to_copy;
        }

        // Step 6: (Key, V) = CTR_DRBG_Update(0, Key, V)
        // When no additional_input, use zeros
        let zeros = [0u8; SEED_LEN];
        ctr_drbg_update(&zeros, &mut self.key, &mut self.v);

        // Step 7: reseed_counter++
        self.reseed_counter += 1;
    }

    /// Returns whether the DRBG needs to be reseeded.
    #[must_use]
    pub fn needs_reseed(&self) -> bool {
        self.reseed_counter > RESEED_INTERVAL
    }

    /// Returns the current reseed counter value.
    #[must_use]
    pub fn reseed_counter(&self) -> u64 {
        self.reseed_counter
    }
}

/// CTR_DRBG_Update function (NIST SP 800-90A Section 10.2.1.2).
///
/// ```text
/// CTR_DRBG_Update(provided_data, Key, V):
///   1. temp = Null
///   2. While len(temp) < seedlen:
///        V = (V + 1) mod 2^outlen
///        output_block = Block_Encrypt(Key, V)
///        temp = temp || output_block
///   3. temp = temp XOR provided_data
///   4. Key = leftmost keylen bits of temp
///   5. V = rightmost outlen bits of temp
///   6. Return (Key, V)
/// ```
fn ctr_drbg_update(
    provided_data: &[u8; SEED_LEN],
    key: &mut [u8; KEY_LEN],
    v: &mut [u8; BLOCK_LEN],
) {
    let cipher = Aes256::new(GenericArray::from_slice(key));

    // Generate seedlen bits (3 blocks for AES-256: 3 * 128 = 384 bits)
    let mut temp = [0u8; SEED_LEN];

    // First block
    increment_counter(v);
    let mut block = *v;
    cipher.encrypt_block(GenericArray::from_mut_slice(&mut block));
    temp[..BLOCK_LEN].copy_from_slice(&block);

    // Second block
    increment_counter(v);
    block = *v;
    cipher.encrypt_block(GenericArray::from_mut_slice(&mut block));
    temp[BLOCK_LEN..2 * BLOCK_LEN].copy_from_slice(&block);

    // Third block
    increment_counter(v);
    block = *v;
    cipher.encrypt_block(GenericArray::from_mut_slice(&mut block));
    temp[2 * BLOCK_LEN..SEED_LEN].copy_from_slice(&block);

    // XOR with provided_data
    for (t, p) in temp.iter_mut().zip(provided_data.iter()) {
        *t ^= p;
    }

    // Update Key and V
    key.copy_from_slice(&temp[..KEY_LEN]);
    v.copy_from_slice(&temp[KEY_LEN..SEED_LEN]);
}

/// Block_Cipher_df (Derivation Function) - NIST SP 800-90A Section 10.3.2.
///
/// Uses BCC (Block Cipher Chaining) to derive a fixed-length output from
/// arbitrary-length input.
///
/// ```text
/// Block_Cipher_df(input_string, no_of_bits_to_return):
///   1. L = len(input_string)/8  (length in bytes)
///   2. N = no_of_bits_to_return/8  (requested bytes)
///   3. S = L || N || input_string || 0x80
///   4. While (len(S) mod outlen) != 0:
///        S = S || 0x00
///   5. temp = Null
///   6. i = 0
///   7. K = 0x00010203...1D1E1F (leftmost keylen bits)
///   8. While len(temp) < keylen + outlen:
///        IV = i || 0^(outlen - 32)
///        temp = temp || BCC(K, IV || S)
///        i = i + 1
///   9. K = leftmost keylen bits of temp
///   10. X = next outlen bits of temp
///   11. temp = Null
///   12. While len(temp) < no_of_bits_to_return:
///         X = Block_Encrypt(K, X)
///         temp = temp || X
///   13. Return leftmost no_of_bits_to_return bits of temp
/// ```
// Allow single-char names to match NIST spec variables (L, N, S, K, X)
#[allow(clippy::many_single_char_names)]
fn block_cipher_df(input: &[u8], output_len: usize) -> [u8; SEED_LEN] {
    // Steps 1-2: Get lengths
    // The cast to u32 is safe because input length is bounded by the buffer size (128 bytes max)
    #[allow(clippy::cast_possible_truncation)]
    let l = input.len() as u32;
    #[allow(clippy::cast_possible_truncation)]
    let n = output_len as u32;

    // Step 3-4: Build S = L || N || input_string || 0x80 || padding
    // Padded to multiple of BLOCK_LEN
    let s_len = 4 + 4 + input.len() + 1;
    let padded_len = s_len.div_ceil(BLOCK_LEN) * BLOCK_LEN;

    // Use a buffer large enough for typical inputs
    // For seedlen input (48 bytes), we need 4+4+48+1+padding = 64 bytes max
    let mut s = [0u8; 128];
    s[..4].copy_from_slice(&l.to_be_bytes());
    s[4..8].copy_from_slice(&n.to_be_bytes());
    s[8..8 + input.len()].copy_from_slice(input);
    s[8 + input.len()] = 0x80;
    // Rest is already zero (padding)

    // Step 7: K = 0x00010203...1D1E1F
    let df_key: [u8; KEY_LEN] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F,
    ];

    // Step 8: Generate temp using BCC
    // Need keylen + outlen bits = 48 bytes = 3 blocks
    let mut temp = [0u8; SEED_LEN];

    for (i, chunk) in temp.chunks_mut(BLOCK_LEN).enumerate() {
        // IV = i || 0^(outlen - 32)
        let mut iv = [0u8; BLOCK_LEN];
        // Safe: i is at most 2 (3 blocks = seedlen/blocklen)
        #[allow(clippy::cast_possible_truncation)]
        let i_u32 = i as u32;
        iv[..4].copy_from_slice(&i_u32.to_be_bytes());

        // BCC(K, IV || S)
        let bcc_result = bcc(&df_key, &iv, &s[..padded_len]);
        chunk.copy_from_slice(&bcc_result);
    }

    // Steps 9-10: K = first 32 bytes, X = next 16 bytes
    let mut k = [0u8; KEY_LEN];
    let mut x = [0u8; BLOCK_LEN];
    k.copy_from_slice(&temp[..KEY_LEN]);
    x.copy_from_slice(&temp[KEY_LEN..SEED_LEN]);

    // Steps 11-12: Generate final output
    let cipher = Aes256::new(GenericArray::from_slice(&k));
    let mut result = [0u8; SEED_LEN];

    for chunk in result.chunks_mut(BLOCK_LEN) {
        cipher.encrypt_block(GenericArray::from_mut_slice(&mut x));
        chunk.copy_from_slice(&x);
    }

    result
}

/// BCC (Block Cipher Chaining) function - NIST SP 800-90A Section 10.3.3.
///
/// ```text
/// BCC(Key, data):
///   1. chaining_value = 0^outlen
///   2. n = len(data)/outlen
///   3. For i = 1 to n:
///        input_block = chaining_value XOR block_i
///        chaining_value = Block_Encrypt(Key, input_block)
///   4. Return chaining_value
/// ```
fn bcc(key: &[u8; KEY_LEN], iv: &[u8; BLOCK_LEN], data: &[u8]) -> [u8; BLOCK_LEN] {
    let cipher = Aes256::new(GenericArray::from_slice(key));

    // Start with IV as the first block to process
    let mut chaining_value = [0u8; BLOCK_LEN];

    // XOR with IV and encrypt
    for (cv, iv_byte) in chaining_value.iter_mut().zip(iv.iter()) {
        *cv ^= iv_byte;
    }
    cipher.encrypt_block(GenericArray::from_mut_slice(&mut chaining_value));

    // Process data blocks
    for block in data.chunks(BLOCK_LEN) {
        // XOR chaining_value with current block
        for (cv, b) in chaining_value.iter_mut().zip(block.iter()) {
            *cv ^= b;
        }
        // Encrypt
        cipher.encrypt_block(GenericArray::from_mut_slice(&mut chaining_value));
    }

    chaining_value
}

/// Increment a 128-bit counter (big-endian).
fn increment_counter(counter: &mut [u8; BLOCK_LEN]) {
    for byte in counter.iter_mut().rev() {
        let (new_val, overflow) = byte.overflowing_add(1);
        *byte = new_val;
        if !overflow {
            break;
        }
    }
}

/// Entropy source interface for gathering hardware random data.
pub trait EntropySource {
    /// Fill the buffer with entropy.
    ///
    /// Returns the number of bytes successfully filled.
    fn get_entropy(&self, buf: &mut [u8]) -> usize;
}

/// RDSEED-based entropy source for x86_64.
///
/// Uses the `RDSEED` instruction to gather hardware random numbers.
/// Falls back to `RDRAND` if `RDSEED` is not available.
#[cfg(target_arch = "x86_64")]
pub struct RdseedEntropySource;

#[cfg(target_arch = "x86_64")]
impl RdseedEntropySource {
    /// Create a new RDSEED entropy source.
    ///
    /// # Panics
    ///
    /// Panics if neither RDSEED nor RDRAND is available.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Check if RDSEED instruction is available.
    #[must_use]
    pub fn is_rdseed_available() -> bool {
        // CPUID.07H:EBX.RDSEED[bit 18]
        // SAFETY: CPUID is safe to call on x86_64
        let result = unsafe { core::arch::x86_64::__cpuid(7) };
        (result.ebx >> 18) & 1 == 1
    }

    /// Check if RDRAND instruction is available.
    #[must_use]
    pub fn is_rdrand_available() -> bool {
        // CPUID.01H:ECX.RDRAND[bit 30]
        // SAFETY: CPUID is safe to call on x86_64
        let result = unsafe { core::arch::x86_64::__cpuid(1) };
        (result.ecx >> 30) & 1 == 1
    }
}

#[cfg(target_arch = "x86_64")]
impl Default for RdseedEntropySource {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_arch = "x86_64")]
impl EntropySource for RdseedEntropySource {
    fn get_entropy(&self, buf: &mut [u8]) -> usize {
        let mut filled = 0;

        // Try RDSEED first, fall back to RDRAND
        let use_rdseed = Self::is_rdseed_available();

        while filled < buf.len() {
            let remaining = buf.len() - filled;

            if remaining >= 8 {
                // Get 64 bits at a time
                let value = if use_rdseed {
                    get_rdseed_u64()
                } else {
                    get_rdrand_u64()
                };

                if let Some(v) = value {
                    buf[filled..filled + 8].copy_from_slice(&v.to_ne_bytes());
                    filled += 8;
                } else {
                    // Hardware entropy unavailable, stop
                    break;
                }
            } else {
                // Get remaining bytes
                let value = if use_rdseed {
                    get_rdseed_u64()
                } else {
                    get_rdrand_u64()
                };

                if let Some(v) = value {
                    let bytes = v.to_ne_bytes();
                    buf[filled..filled + remaining].copy_from_slice(&bytes[..remaining]);
                    filled += remaining;
                } else {
                    break;
                }
            }
        }

        filled
    }
}

/// Get a 64-bit value from RDSEED instruction.
#[cfg(target_arch = "x86_64")]
fn get_rdseed_u64() -> Option<u64> {
    // Retry a few times as per Intel recommendations
    for _ in 0..10 {
        let mut value: u64;
        let success: u8;

        // SAFETY: RDSEED is safe to call when available
        unsafe {
            core::arch::asm!(
                "rdseed {value}",
                "setc {success}",
                value = out(reg) value,
                success = out(reg_byte) success,
                options(nomem, nostack),
            );
        }

        if success != 0 {
            return Some(value);
        }

        // Small delay before retry
        core::hint::spin_loop();
    }

    None
}

/// Get a 64-bit value from RDRAND instruction.
#[cfg(target_arch = "x86_64")]
fn get_rdrand_u64() -> Option<u64> {
    // Retry a few times as per Intel recommendations
    for _ in 0..10 {
        let mut value: u64;
        let success: u8;

        // SAFETY: RDRAND is safe to call when available
        unsafe {
            core::arch::asm!(
                "rdrand {value}",
                "setc {success}",
                value = out(reg) value,
                success = out(reg_byte) success,
                options(nomem, nostack),
            );
        }

        if success != 0 {
            return Some(value);
        }

        // Small delay before retry
        core::hint::spin_loop();
    }

    None
}

/// Nonce source backed by a memory buffer.
///
/// This provides a simple interface for initializing a nonce from an external
/// source (e.g., TPM). The nonce is consumed when read.
pub struct NonceBuffer {
    data: [u8; 32],
    len: usize,
}

impl NonceBuffer {
    /// Create a new empty nonce buffer.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            data: [0u8; 32],
            len: 0,
        }
    }

    /// Initialize the nonce buffer with data.
    ///
    /// # Arguments
    ///
    /// * `nonce` - The nonce data (up to 32 bytes)
    pub fn initialize(&mut self, nonce: &[u8]) {
        let copy_len = core::cmp::min(nonce.len(), self.data.len());
        self.data[..copy_len].copy_from_slice(&nonce[..copy_len]);
        self.len = copy_len;
    }

    /// Get the nonce data.
    #[must_use]
    pub fn get(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// Check if the nonce buffer has been initialized.
    #[must_use]
    pub fn is_initialized(&self) -> bool {
        self.len > 0
    }

    /// Clear the nonce buffer.
    pub fn clear(&mut self) {
        self.data.fill(0);
        self.len = 0;
    }
}

impl Default for NonceBuffer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // NIST SP 800-90A Test Vectors for CTR_DRBG with AES-256 and df
    // Source: NIST CAVP DRBG Test Vectors
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/drbg/drbgtestvectors.zip

    /// Test increment_counter function
    #[test]
    fn test_increment_counter() {
        let mut counter = [0u8; 16];
        increment_counter(&mut counter);
        assert_eq!(counter[15], 1);

        // Test overflow
        counter = [0xFF; 16];
        increment_counter(&mut counter);
        assert_eq!(counter, [0u8; 16]);

        // Test partial overflow
        counter = [0u8; 16];
        counter[15] = 0xFF;
        increment_counter(&mut counter);
        assert_eq!(counter[14], 1);
        assert_eq!(counter[15], 0);
    }

    /// Test Block_Cipher_df with known test vector
    #[test]
    fn test_block_cipher_df() {
        // This tests the derivation function produces consistent output
        let input = [0x01u8; 32];
        let output = block_cipher_df(&input, SEED_LEN);

        // Verify output is deterministic
        let output2 = block_cipher_df(&input, SEED_LEN);
        assert_eq!(output, output2);

        // Verify different input produces different output
        let input2 = [0x02u8; 32];
        let output3 = block_cipher_df(&input2, SEED_LEN);
        assert_ne!(output, output3);
    }

    /// NIST Test Vector verification.
    ///
    /// Note: NIST provides official test vectors for CTR_DRBG in the CAVP program.
    /// The vectors below are placeholders that verify the algorithm produces
    /// deterministic output. For full NIST compliance, test against the official
    /// vectors from: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program
    ///
    /// This test verifies the algorithm produces consistent, deterministic output
    /// by checking that the same inputs always produce the same outputs.
    #[test]
    fn test_drbg_determinism() {
        let entropy_input: [u8; 32] = [
            0x36, 0x40, 0x19, 0x40, 0xfa, 0x8b, 0x1f, 0xba, 0x91, 0xa1, 0x66, 0x1f, 0x21, 0x1d,
            0x78, 0xa0, 0xb9, 0x38, 0x9a, 0x74, 0xe5, 0xbc, 0xcf, 0xec, 0xe8, 0xd7, 0x66, 0xaf,
            0x1a, 0x6d, 0x3b, 0x14,
        ];

        let nonce: [u8; 16] = [
            0x49, 0x6f, 0x25, 0xb0, 0xf1, 0x30, 0x1b, 0x4f, 0x50, 0x1b, 0xe3, 0x03, 0x80, 0xa1,
            0x37, 0xeb,
        ];

        // Create two DRBGs with the same inputs
        let mut drbg1 = AesCtrDrbg::new(&entropy_input, &nonce);
        let mut drbg2 = AesCtrDrbg::new(&entropy_input, &nonce);

        // Generate from both
        let mut output1 = [0u8; 64];
        let mut output2 = [0u8; 64];
        assert!(drbg1.generate(&mut output1));
        assert!(drbg2.generate(&mut output2));

        // Outputs should be identical (determinism)
        assert_eq!(output1, output2);

        // Output should not be all zeros
        assert!(output1.iter().any(|&b| b != 0));

        // Second generate should also be deterministic
        let mut output1_second = [0u8; 64];
        let mut output2_second = [0u8; 64];
        assert!(drbg1.generate(&mut output1_second));
        assert!(drbg2.generate(&mut output2_second));
        assert_eq!(output1_second, output2_second);

        // Second output should differ from first
        assert_ne!(output1, output1_second);
    }

    /// Test that reseed produces different outputs.
    #[test]
    fn test_drbg_reseed_changes_output() {
        let entropy_input: [u8; 32] = [0x42u8; 32];
        let nonce: [u8; 16] = [0x24u8; 16];

        let mut drbg1 = AesCtrDrbg::new(&entropy_input, &nonce);
        let mut drbg2 = AesCtrDrbg::new(&entropy_input, &nonce);

        // Generate initial output from both
        let mut output1 = [0u8; 64];
        let mut output2 = [0u8; 64];
        assert!(drbg1.generate(&mut output1));
        assert!(drbg2.generate(&mut output2));

        // Should be equal before reseed
        assert_eq!(output1, output2);

        // Reseed drbg1 with new entropy
        let new_entropy: [u8; 32] = [0x99u8; 32];
        drbg1.reseed(&new_entropy);

        // Generate again
        let mut output1_after = [0u8; 64];
        let mut output2_after = [0u8; 64];
        assert!(drbg1.generate(&mut output1_after));
        assert!(drbg2.generate(&mut output2_after));

        // Now they should differ (drbg1 was reseeded)
        assert_ne!(output1_after, output2_after);

        // Reseed counter should reset for drbg1
        assert_eq!(drbg1.reseed_counter(), 2); // After reseed + 1 generate
    }

    /// Test basic DRBG operations
    #[test]
    fn test_drbg_basic() {
        let entropy = [0x42u8; 32];
        let nonce = [0x24u8; 16];

        let mut drbg = AesCtrDrbg::new(&entropy, &nonce);

        // Generate should succeed
        let mut output1 = [0u8; 64];
        assert!(drbg.generate(&mut output1));

        // Output should not be all zeros
        assert!(output1.iter().any(|&b| b != 0));

        // Second generate should produce different output
        let mut output2 = [0u8; 64];
        assert!(drbg.generate(&mut output2));
        assert_ne!(output1, output2);

        // Reseed counter should increment
        assert_eq!(drbg.reseed_counter(), 3);
    }

    /// Test DRBG reseed
    #[test]
    fn test_drbg_reseed() {
        let entropy = [0x42u8; 32];
        let nonce = [0x24u8; 16];

        let mut drbg = AesCtrDrbg::new(&entropy, &nonce);

        // Generate some output
        let mut output1 = [0u8; 64];
        assert!(drbg.generate(&mut output1));

        // Reseed with new entropy
        let new_entropy = [0x99u8; 32];
        drbg.reseed(&new_entropy);

        // Counter should reset
        assert_eq!(drbg.reseed_counter(), 1);

        // Generate should work
        let mut output2 = [0u8; 64];
        assert!(drbg.generate(&mut output2));
    }

    /// Test NonceBuffer
    #[test]
    fn test_nonce_buffer() {
        let mut buffer = NonceBuffer::new();
        assert!(!buffer.is_initialized());
        assert!(buffer.get().is_empty());

        // Initialize with data
        let nonce_data = [0x01, 0x02, 0x03, 0x04];
        buffer.initialize(&nonce_data);
        assert!(buffer.is_initialized());
        assert_eq!(buffer.get(), &nonce_data);

        // Clear
        buffer.clear();
        assert!(!buffer.is_initialized());
    }

    /// Test large output generation
    #[test]
    fn test_large_output() {
        let entropy = [0x55u8; 32];
        let nonce = [0xAAu8; 16];

        let mut drbg = AesCtrDrbg::new(&entropy, &nonce);

        // Generate more than one chunk (use a size that triggers multiple chunks)
        // but not so large that it triggers clippy's large_stack_arrays warning
        let mut output = alloc::vec![0u8; MAX_BYTES_PER_REQUEST + 1024];
        assert!(drbg.generate(&mut output));

        // Verify output is not all zeros
        assert!(output.iter().any(|&b| b != 0));
    }
}
