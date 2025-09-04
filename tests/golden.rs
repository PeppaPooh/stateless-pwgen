use pwgen::{generator, policy, kdf, prng};

/// Golden test vectors - frozen input→output pairs to guard against accidental changes.
/// These tests ensure the implementation remains deterministic and consistent.

/// Golden test vectors for KDF key derivation
#[test]
fn kdf_golden_vectors() {
    // Test vector 1: Basic case
    let key = kdf::derive_site_key("password123", "example.com").unwrap();
    let expected = [
        190, 24, 69, 116, 140, 249, 56, 190, 96, 127, 81, 49, 252, 32, 166, 163,
        81, 135, 253, 226, 148, 210, 209, 225, 70, 1, 159, 49, 212, 143, 31, 178
    ];
    assert_eq!(key, expected, "KDF golden vector 1 failed");
    
    // Test vector 2: Different master password
    let key = kdf::derive_site_key("different_password", "example.com").unwrap();
    let expected = [
        40, 166, 195, 24, 107, 236, 143, 86, 69, 52, 172, 139, 19, 60, 39, 107,
        47, 116, 3, 31, 48, 172, 142, 36, 249, 255, 183, 223, 155, 218, 115, 218
    ];
    assert_eq!(key, expected, "KDF golden vector 2 failed");
    
    // Test vector 3: Different site
    let key = kdf::derive_site_key("password123", "different.com").unwrap();
    let expected = [
        176, 215, 168, 40, 102, 86, 42, 38, 0, 5, 181, 217, 127, 222, 65, 169,
        24, 249, 255, 114, 44, 228, 87, 7, 216, 120, 207, 35, 24, 112, 172, 8
    ];
    assert_eq!(key, expected, "KDF golden vector 3 failed");
    
    // Test vector 4: Case normalization
    let key = kdf::derive_site_key("password123", "EXAMPLE.COM").unwrap();
    let expected = [
        190, 24, 69, 116, 140, 249, 56, 190, 96, 127, 81, 49, 252, 32, 166, 163,
        81, 135, 253, 226, 148, 210, 209, 225, 70, 1, 159, 49, 212, 143, 31, 178
    ];
    assert_eq!(key, expected, "KDF golden vector 4 (case normalization) failed");
}

/// Golden test vectors for PRNG byte sequences
#[test]
fn prng_golden_vectors() {
    let key = [0u8; 32];
    let info = b"test-context";
    let mut rng = prng::from_key_and_context(&key, info).unwrap();
    
    // Generate first 64 bytes and verify against golden vector
    let mut bytes = [0u8; 64];
    rng.fill(&mut bytes);
    
    let expected = [
        96, 72, 158, 207, 10, 30, 162, 206, 191, 247, 165, 10, 33, 134, 189, 248,
        11, 203, 121, 95, 83, 23, 26, 180, 132, 246, 23, 49, 25, 224, 145, 135,
        197, 180, 29, 12, 218, 156, 221, 162, 8, 41, 146, 141, 254, 100, 143, 0,
        100, 129, 15, 26, 68, 250, 125, 106, 214, 198, 10, 110, 28, 144, 16, 175
    ];
    assert_eq!(bytes, expected, "PRNG golden vector failed");
    
    // Test next_index with specific values
    let mut rng2 = prng::from_key_and_context(&key, info).unwrap();
    let indices: Vec<usize> = (0..20).map(|_| rng2.next_index(10)).collect();
    let expected_indices = vec![6, 2, 8, 7, 0, 0, 2, 6, 1, 7, 5, 0, 3, 4, 9, 8, 1, 3, 1, 5];
    assert_eq!(indices, expected_indices, "PRNG next_index golden vector failed");
}

/// Golden test vectors for policy encoding
#[test]
fn policy_encoding_golden_vectors() {
    // Test vector 1: Default policy
    let pol = policy::default_policy();
    let encoded = policy::encode(&pol);
    assert_eq!(encoded, "min=12;max=16;allow=lower,upper,digit,symbol;force=", 
               "Policy encoding golden vector 1 failed");
    
    // Test vector 2: Policy with forced sets
    let pol = policy::Policy {
        min: 8,
        max: 12,
        allow: [true, true, false, true],
        force: [true, false, false, true],
    };
    let encoded = policy::encode(&pol);
    assert_eq!(encoded, "min=8;max=12;allow=lower,upper,symbol;force=lower,symbol", 
               "Policy encoding golden vector 2 failed");
    
    // Test vector 3: Single character set
    let pol = policy::Policy {
        min: 10,
        max: 10,
        allow: [false, false, true, false],
        force: [false, false, true, false],
    };
    let encoded = policy::encode(&pol);
    assert_eq!(encoded, "min=10;max=10;allow=digit;force=digit", 
               "Policy encoding golden vector 3 failed");
}

/// Golden test vectors for password generation
#[test]
fn password_generation_golden_vectors() {
    // Test vector 1: Basic password generation
    let pol = policy::Policy {
        min: 12,
        max: 12,
        allow: [true, true, true, true],
        force: [false, false, false, false],
    };
    let pol = policy::validate(&pol).unwrap();
    
    let password = generator::generate_password("master123", "example.com", Some("alice"), &pol, 1).unwrap();
    assert_eq!(password, "!uZ5S_;H@x-m", "Password generation golden vector 1 failed");
    
    // Test vector 2: Different version
    let password = generator::generate_password("master123", "example.com", Some("alice"), &pol, 2).unwrap();
    assert_eq!(password, "fF2,:U\\Gzn\\:", "Password generation golden vector 2 failed");
    
    // Test vector 3: Different username
    let password = generator::generate_password("master123", "example.com", Some("bob"), &pol, 1).unwrap();
    assert_eq!(password, ")ionz.dK7\"-p", "Password generation golden vector 3 failed");
    
    // Test vector 4: Different site
    let password = generator::generate_password("master123", "different.com", Some("alice"), &pol, 1).unwrap();
    assert_eq!(password, "U(#\"PK<XqUoN", "Password generation golden vector 4 failed");
    
    // Test vector 5: Forced character sets
    let pol_forced = policy::Policy {
        min: 8,
        max: 8,
        allow: [true, true, true, true],
        force: [true, true, false, false],
    };
    let pol_forced = policy::validate(&pol_forced).unwrap();
    
    let password = generator::generate_password("master123", "test.com", None, &pol_forced, 1).unwrap();
    assert_eq!(password, "Iv(N\\wq=", "Password generation golden vector 5 (forced sets) failed");
    
    // Test vector 6: Variable length
    let pol_var = policy::Policy {
        min: 8,
        max: 16,
        allow: [true, true, true, true],
        force: [false, false, false, false],
    };
    let pol_var = policy::validate(&pol_var).unwrap();
    
    let password = generator::generate_password("master123", "test.com", None, &pol_var, 1).unwrap();
    assert_eq!(password, ";2tbAk?7KL(J_F", "Password generation golden vector 6 (variable length) failed");
    
    // Test vector 7: Single character set
    let pol_single = policy::Policy {
        min: 10,
        max: 10,
        allow: [false, false, true, false],
        force: [false, false, false, false],
    };
    let pol_single = policy::validate(&pol_single).unwrap();
    
    let password = generator::generate_password("master123", "test.com", None, &pol_single, 1).unwrap();
    assert_eq!(password, "4042846870", "Password generation golden vector 7 (digits only) failed");
}

/// Golden test vectors for edge cases
#[test]
fn edge_case_golden_vectors() {
    // Test vector 1: Minimum length with forced sets
    let pol = policy::Policy {
        min: 2,
        max: 2,
        allow: [true, true, false, false],
        force: [true, true, false, false],
    };
    let pol = policy::validate(&pol).unwrap();
    
    let password = generator::generate_password("master123", "test.com", None, &pol, 1).unwrap();
    assert_eq!(password, "qZ", "Edge case golden vector 1 (min length with forced sets) failed");
    
    // Test vector 2: Only symbols
    let pol = policy::Policy {
        min: 8,
        max: 8,
        allow: [false, false, false, true],
        force: [false, false, false, false],
    };
    let pol = policy::validate(&pol).unwrap();
    
    let password = generator::generate_password("master123", "test.com", None, &pol, 1).unwrap();
    assert_eq!(password, "<_?.!}{[", "Edge case golden vector 2 (symbols only) failed");
    
    // Test vector 3: Empty username vs None
    let pol = policy::Policy {
        min: 8,
        max: 8,
        allow: [true, true, true, true],
        force: [false, false, false, false],
    };
    let pol = policy::validate(&pol).unwrap();
    
    let password1 = generator::generate_password("master123", "test.com", Some(""), &pol, 1).unwrap();
    let password2 = generator::generate_password("master123", "test.com", None, &pol, 1).unwrap();
    assert_eq!(password1, password2, "Edge case golden vector 3 (empty username vs None) failed");
    assert_eq!(password1, "^3nk&;vF", "Edge case golden vector 3 (empty username) failed");
}

/// Golden test vectors for character set validation
#[test]
fn character_set_golden_vectors() {
    // Test vector 1: All character sets
    let pol = policy::Policy {
        min: 8,
        max: 8,
        allow: [true, true, true, true],
        force: [false, false, false, false],
    };
    let alphabet = policy::allowed_alphabet(&pol);
    let alphabet_str = String::from_utf8(alphabet).unwrap();
    
    // Verify specific characters are present
    assert!(alphabet_str.contains('a'), "Should contain lowercase 'a'");
    assert!(alphabet_str.contains('z'), "Should contain lowercase 'z'");
    assert!(alphabet_str.contains('A'), "Should contain uppercase 'A'");
    assert!(alphabet_str.contains('Z'), "Should contain uppercase 'Z'");
    assert!(alphabet_str.contains('0'), "Should contain digit '0'");
    assert!(alphabet_str.contains('9'), "Should contain digit '9'");
    assert!(alphabet_str.contains('!'), "Should contain symbol '!'");
    assert!(alphabet_str.contains('~'), "Should contain symbol '~'");
    
    // Test vector 2: Only lowercase and digits
    let pol = policy::Policy {
        min: 8,
        max: 8,
        allow: [true, false, true, false],
        force: [false, false, false, false],
    };
    let alphabet = policy::allowed_alphabet(&pol);
    let alphabet_str = String::from_utf8(alphabet).unwrap();
    
    assert_eq!(alphabet_str.len(), 36, "Lowercase + digits should be 36 characters");
    assert!(alphabet_str.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()), 
            "Should contain only lowercase letters and digits");
}
