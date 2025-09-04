use argon2::{Algorithm, Argon2, Params, Version};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

pub const KDF_OUT_LEN: usize = 32;

/// Errors that can occur during key derivation
#[derive(Error, Debug)]
pub enum KdfError {
    #[error("invalid KDF parameters: {0}")]
    InvalidParams(String),

    #[error("argon2 error: {0:?}")]
    Argon2(argon2::Error),
}

/// Lowercases + trims site before salt.
/// Returns 32-byte key. Zeroizes internals where possible.
pub fn derive_site_key(master: &str, site: &str) -> Result<[u8; KDF_OUT_LEN], KdfError> {
    // Normalize site per v0.1
    let site_id = site.trim().to_ascii_lowercase();

    // Derive 16-byte salt = SHA256(b"pwgen-salt-v1:" || site_id)[0..16]
    let mut hasher = Sha256::new();
    hasher.update(b"pwgen-salt-v1:");
    hasher.update(site_id.as_bytes());
    let digest = hasher.finalize(); // 32 bytes
    let mut salt16 = [0u8; 16];
    salt16.copy_from_slice(&digest[..16]);

    // Argon2id parameters
    const MEM_KIB: u32 = 65_536; // 64 MiB
    const T_COST: u32 = 3;       // iterations
    const P_COST: u32 = 1;       // parallelism

    let params = Params::new(MEM_KIB, T_COST, P_COST, Some(KDF_OUT_LEN))
        .map_err(|e| KdfError::InvalidParams(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Copy master into an owned buffer we can zeroize after use
    let mut master_bytes = master.as_bytes().to_vec();

    // Derive key
    let mut out = [0u8; KDF_OUT_LEN];
    argon2
        .hash_password_into(&master_bytes, &salt16, &mut out)
        .map_err(KdfError::Argon2)?;

    // Zeroize sensitive intermediates
    master_bytes.zeroize();
    salt16.zeroize();

    Ok(out)
}
