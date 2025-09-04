use crate::{kdf, policy, prng};
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Error, Debug)]
pub enum GenError {
    #[error(transparent)]
    Policy(#[from] policy::PolicyError),
    #[error(transparent)]
    Kdf(#[from] kdf::KdfError),
    #[error(transparent)]
    Prng(#[from] prng::PrngError),
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),
}

pub fn generate_password(
    master: &str,
    site: &str,
    username: Option<&str>,
    policy_in: &policy::Policy,
    version: u32,
) -> Result<String, GenError> {
    // Normalize inputs
    let site_id = site.trim().to_ascii_lowercase();
    let username_bytes = username.unwrap_or("").as_bytes();

    // Validate policy (also clamps fields)
    let policy = policy::validate(policy_in)?;

    // Derive KDF key (32 bytes)
    let mut key = kdf::derive_site_key(master, &site_id)?;

    // Build PRNG info context
    let mut info = Vec::with_capacity(64);
    info.extend_from_slice(b"pwgen-v1");
    info.extend_from_slice(b"|site=");
    info.extend_from_slice(site_id.as_bytes());
    info.extend_from_slice(b"|user=");
    info.extend_from_slice(username_bytes);
    info.extend_from_slice(b"|policy=");
    let enc = policy::encode(&policy);
    info.extend_from_slice(enc.as_bytes());
    info.extend_from_slice(b"|version=");
    let version_str = itoa::Buffer::new().format(version).to_string();
    info.extend_from_slice(version_str.as_bytes());

    // Create PRNG
    let mut rng = prng::from_key_and_context(&key, &info)?;
    // Zeroize key ASAP after rng constructed
    key.zeroize();

    // Choose length L
    let min = policy.min;
    let max = policy.max;
    let mut forced_sets = policy::forced_sets(&policy);
    let forced_count = forced_sets.len() as u8;

    if min == 0 || max == 0 || min > max || min > 128 || max > 128 {
        return Err(GenError::InvalidInput("invalid min/max after validation"));
    }

    if min < forced_count {
        return Err(GenError::InvalidInput("min less than number of forced sets"));
    }

    let length: u8 = if min == max {
        min
    } else {
        let range = (max - min + 1) as usize;
        let draw = rng.next_index(range) as u8;
        min + draw
    };

    if forced_count > length {
        return Err(GenError::InvalidInput("forced_count exceeds chosen length"));
    }

    // Build characters
    let union = policy::allowed_alphabet(&policy);
    if union.is_empty() {
        return Err(GenError::InvalidInput("allowed union is empty"));
    }

    let mut out = Vec::<u8>::with_capacity(length as usize);

    // Forced picks: fixed order lower -> upper -> digit -> symbol
    for (_set, alphabet) in forced_sets.drain(..) {
        let idx = rng.next_index(alphabet.len());
        out.push(alphabet[idx]);
    }

    // Fill remaining with union
    let remaining = length as usize - out.len();
    for _ in 0..remaining {
        let idx = rng.next_index(union.len());
        out.push(union[idx]);
    }

    // Deterministic Fisher–Yates shuffle
    for i in (1..out.len()).rev() {
        let j = rng.next_index(i + 1);
        out.swap(i, j);
    }

    debug_assert_eq!(out.len() as u8, length);

    // Convert to String (ASCII), return
    let s = String::from_utf8(out.clone()).expect("output must be valid ASCII");

    // Zeroize temporary buffers where practical
    // Note: 'out' contains final password; caller may want to hold it, so we can't zeroize after move.
    // We clear intermediate containers that we still own.
    // 'union' and 'info' contain policy/context (non-secret), but we can drop naturally.
    Ok(s)
}
