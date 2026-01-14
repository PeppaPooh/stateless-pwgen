use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroize;

pub const PRNG_BLOCK: usize = 32;

type HmacSha256 = Hmac<Sha256>;

#[derive(Error, Debug)]
pub enum PrngError {
    #[error("internal error initializing HMAC")] 
    HmacInit,
}

/// Context bytes must be the exact encoding described in policy.rs/generator.rs.
pub struct HkdfStream {
    prk: [u8; 32],
    info: Vec<u8>,
    counter: u8, // next T(n) index to generate (starts at 1)
    block: [u8; PRNG_BLOCK],
    block_pos: usize,
    prev_block: [u8; PRNG_BLOCK], // T(n-1)
}

/// key = 32 bytes from kdf::derive_site_key
pub fn from_key_and_context(key: &[u8; 32], info: &[u8]) -> Result<HkdfStream, PrngError> {
    // PRK = HKDF-Extract(salt, IKM)
    let mut mac = HmacSha256::new_from_slice(b"pwgen-hkdf-salt-v1").map_err(|_| PrngError::HmacInit)?;
    mac.update(key);
    let prk_bytes = mac.finalize().into_bytes();

    let mut prk = [0u8; 32];
    prk.copy_from_slice(&prk_bytes);

    Ok(HkdfStream {
        prk,
        info: info.to_vec(),
        counter: 0,
        block: [0u8; PRNG_BLOCK],
        block_pos: PRNG_BLOCK, // force initial refill
        prev_block: [0u8; PRNG_BLOCK],
    })
}

impl HkdfStream {
    fn refill_block(&mut self) -> Result<(), PrngError> {
        // Generate next T(n)
        self.counter = self.counter.wrapping_add(1);
        debug_assert!(self.counter != 0, "HKDF counter wrapped");

        let mut mac = HmacSha256::new_from_slice(&self.prk).map_err(|_| PrngError::HmacInit)?;
        
        if self.counter == 1 {
            mac.update(&self.info);
            mac.update(&[1]);
        } else {
            mac.update(&self.prev_block);
            mac.update(&self.info);
            mac.update(&[self.counter]);
        }
        let t = mac.finalize().into_bytes();
        self.block.copy_from_slice(&t);
        self.prev_block.copy_from_slice(&t);
        self.block_pos = 0;
        Ok(())
    }

    /// Returns next byte from the stream; refills internally as needed.
    pub fn next_u8(&mut self) -> Result<u8, PrngError> {
        if self.block_pos >= PRNG_BLOCK {
            self.refill_block()?;
        }
        let b = self.block[self.block_pos];
        self.block_pos += 1;
        Ok(b)
    }

    /// Fills out with deterministic bytes.
    pub fn fill(&mut self, out: &mut [u8]) -> Result<(), PrngError> {
        for slot in out.iter_mut() {
            *slot = self.next_u8()?;
        }
        Ok(())
    }

    /// Helper: draw an unbiased integer in [0, n) via rejection sampling.
    pub fn next_index(&mut self, n: usize) -> Result<usize, PrngError> {
        assert!(n > 0, "n must be > 0");
        let limit = (256 / n) * n; // largest multiple of n less than 256
        loop {
            let byte = self.next_u8()? as usize;
            if byte < limit {
                return Ok(byte % n);
            }
        }
    }
}

impl Drop for HkdfStream {
    fn drop(&mut self) {
        self.prk.zeroize();
        self.info.zeroize();
        self.block.zeroize();
        self.prev_block.zeroize();
    }
}
