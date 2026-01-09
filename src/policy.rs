use thiserror::Error;

// Fixed, ordered ASCII character sets
const LOWER_BYTES: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER_BYTES: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGIT_BYTES: &[u8] = b"0123456789";
const SYMBOL_BYTES: &[u8] = b"!\"#$%&'()*+,-./:;<=>?@[\\]^_{|}~";

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Charset {
    Lower,
    Upper,
    Digit,
    Symbol,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Policy {
    pub min: u8,
    pub max: u8,
    pub allow: [bool; 4], // order: lower, upper, digit, symbol
    pub force: [bool; 4], // subset of allow
}

#[derive(Error, Debug)]
pub enum PolicyError {
    #[error("invalid length bounds (require 1 ≤ min ≤ max ≤ 128)")]
    InvalidBounds,

    #[error("allowed character sets must be nonempty")]
    EmptyAllowed,

    #[error("forced sets must be subset of allowed sets")]
    ForceNotSubset,

    #[error("min length must be at least the number of forced sets")]
    MinLessThanForcedCount,
}

pub fn default_policy() -> Policy {
    Policy {
        min: 12,
        max: 16,
        allow: [true, true, true, true],
        force: [false, false, false, false],
    }
}

/// Validates invariants and returns normalized copy (clamps to [1,128]).
///
/// This is the **canonical validator** for all policy invariants. If this function
/// returns `Ok(policy)`, the policy is safe to use for generation. The returned policy
/// satisfies:
///
/// - `1 ≤ min ≤ max ≤ 128`
/// - `allow` is not empty
/// - `force ⊆ allow`
/// - `min ≥ forced_count` (where forced_count is the number of forced sets)
///
/// After validation, the generator should not need to re-check any policy-related invariants.
pub fn validate(policy: &Policy) -> Result<Policy, PolicyError> {
    // Clamp to [1,128] - this ensures min and max are always in valid range
    let min = policy.min.clamp(1, 128);
    let max = policy.max.clamp(1, 128);

    // Enforce 1 ≤ min ≤ max ≤ 128
    if min > max {
        return Err(PolicyError::InvalidBounds);
    }

    let allow = policy.allow;
    let force = policy.force;

    // Allowed union must be nonempty
    if !allow.iter().any(|&b| b) {
        return Err(PolicyError::EmptyAllowed);
    }

    // Enforce force ⊆ allow: each forced set must be in allowed sets
    for i in 0..4 {
        if force[i] && !allow[i] {
            return Err(PolicyError::ForceNotSubset);
        }
    }

    // Enforce min ≥ forced_count (where forced_count is the number of forced sets)
    let forced_count = force.iter().filter(|&&b| b).count() as u8;
    if min < forced_count {
        return Err(PolicyError::MinLessThanForcedCount);
    }

    Ok(Policy { min, max, allow, force })
}

/// Canonical, deterministic encoding used in PRNG context
/// Format: b"min=" <u8> b";max=" <u8> b";allow=" <csv> b";force=" <csv>
/// csv order: lower,upper,digit,symbol; empty union encodes as empty string
pub fn encode(policy: &Policy) -> String {
    let allow_csv = csv_from_flags(policy.allow);
    let force_csv = csv_from_flags(policy.force);
    format!(
        "min={};max={};allow={};force={}",
        policy.min, policy.max, allow_csv, force_csv
    )
}

fn csv_from_flags(flags: [bool; 4]) -> String {
    let mut parts: Vec<&'static str> = Vec::with_capacity(4);
    if flags[0] {
        parts.push("lower");
    }
    if flags[1] {
        parts.push("upper");
    }
    if flags[2] {
        parts.push("digit");
    }
    if flags[3] {
        parts.push("symbol");
    }
    parts.join(",")
}

/// Returns concatenated allowed alphabet (in fixed set order).
pub fn allowed_alphabet(policy: &Policy) -> Vec<u8> {
    let mut out = Vec::with_capacity(LOWER_BYTES.len() + UPPER_BYTES.len() + DIGIT_BYTES.len() + SYMBOL_BYTES.len());
    if policy.allow[0] {
        out.extend_from_slice(LOWER_BYTES);
    }
    if policy.allow[1] {
        out.extend_from_slice(UPPER_BYTES);
    }
    if policy.allow[2] {
        out.extend_from_slice(DIGIT_BYTES);
    }
    if policy.allow[3] {
        out.extend_from_slice(SYMBOL_BYTES);
    }
    out
}

/// Returns a Vec<(Charset, &'static [u8])> for all forced sets that are allowed.
pub fn forced_sets(policy: &Policy) -> Vec<(Charset, &'static [u8])> {
    let mut v = Vec::with_capacity(4);
    if policy.force[0] && policy.allow[0] {
        v.push((Charset::Lower, LOWER_BYTES));
    }
    if policy.force[1] && policy.allow[1] {
        v.push((Charset::Upper, UPPER_BYTES));
    }
    if policy.force[2] && policy.allow[2] {
        v.push((Charset::Digit, DIGIT_BYTES));
    }
    if policy.force[3] && policy.allow[3] {
        v.push((Charset::Symbol, SYMBOL_BYTES));
    }
    v
}
