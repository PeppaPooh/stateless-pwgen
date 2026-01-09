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

/// Generates a deterministic password from the given inputs.
///
/// # Arguments
///
/// * `master` - Master secret
/// * `site` - Site identifier (will be trimmed and lowercased)
/// * `username` - Optional username
/// * `policy_in` - Policy (will be validated; assumes it has been validated via `policy::validate()`)
/// * `version` - Version/rotation number
///
/// # Precondition
///
/// Assumes `policy_in` has been validated via `policy::validate()`. The policy validation
/// ensures all invariants are satisfied, so this function does not re-check policy bounds.
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

    // Validate policy - this is the single source of truth for policy validation
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
    // Policy has been validated, so we know: 1 ≤ min ≤ max ≤ 128, min ≥ forced_count, allow is nonempty
    let min = policy.min;
    let max = policy.max;
    let mut forced_sets = policy::forced_sets(&policy);
    let forced_count = forced_sets.len() as u8;

    // Defense-in-depth: these should never happen after validation, but check in debug builds
    debug_assert!(min >= 1 && min <= 128, "min should be in [1,128] after validation");
    debug_assert!(max >= 1 && max <= 128, "max should be in [1,128] after validation");
    debug_assert!(min <= max, "min should be ≤ max after validation");
    debug_assert!(min >= forced_count, "min should be ≥ forced_count after validation");

    let length: u8 = if min == max {
        min
    } else {
        let range = (max - min + 1) as usize;
        let draw = rng.next_index(range) as u8;
        min + draw
    };

    // Defense-in-depth: chosen length is between min and max, and min ≥ forced_count, so forced_count ≤ length
    debug_assert!(length >= min && length <= max, "chosen length should be in [min, max]");
    debug_assert!(forced_count <= length, "forced_count should be ≤ length after validation");

    // Build characters
    // Policy validation ensures allow is nonempty, so union will be nonempty
    let union = policy::allowed_alphabet(&policy);
    debug_assert!(!union.is_empty(), "allowed alphabet should be nonempty after validation");

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
