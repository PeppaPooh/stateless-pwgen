use pwgen::{generator, policy, kdf, prng};

/// Test vectors for KDF module - these test the deterministic key derivation
#[test]
fn kdf_test_vectors() {
    // Test vector 1: Basic case
    let key1 = kdf::derive_site_key("password123", "example.com").unwrap();
    let key2 = kdf::derive_site_key("password123", "example.com").unwrap();
    assert_eq!(key1, key2, "KDF should be deterministic for same inputs");
    
    // Test vector 2: Different master password
    let key3 = kdf::derive_site_key("different_password", "example.com").unwrap();
    assert_ne!(key1, key3, "Different master passwords should produce different keys");
    
    // Test vector 3: Different site
    let key4 = kdf::derive_site_key("password123", "different.com").unwrap();
    assert_ne!(key1, key4, "Different sites should produce different keys");
    
    // Test vector 4: Case insensitive site normalization
    let key5 = kdf::derive_site_key("password123", "EXAMPLE.COM").unwrap();
    let key6 = kdf::derive_site_key("password123", "  example.com  ").unwrap();
    assert_eq!(key1, key5, "Site should be normalized to lowercase");
    assert_eq!(key1, key6, "Site should be trimmed");
    
    // Test vector 5: Empty and edge case inputs
    let key7 = kdf::derive_site_key("", "test").unwrap();
    let key8 = kdf::derive_site_key("test", "").unwrap();
    assert_ne!(key7, key8, "Empty master vs empty site should be different");
    
    // Test vector 6: Very long inputs
    let long_master = "a".repeat(1000);
    let long_site = "b".repeat(1000);
    let key9 = kdf::derive_site_key(&long_master, "test").unwrap();
    let key10 = kdf::derive_site_key("test", &long_site).unwrap();
    assert_ne!(key9, key10, "Long inputs should work and be different");
}

/// Test vectors for PRNG module - these test deterministic random number generation
#[test]
fn prng_test_vectors() {
    // Test vector 1: Basic PRNG functionality
    let key = [0u8; 32];
    let info = b"test-context";
    let mut rng1 = prng::from_key_and_context(&key, info).unwrap();
    let mut rng2 = prng::from_key_and_context(&key, info).unwrap();
    
    // Generate some bytes and verify they're deterministic
    let mut bytes1 = [0u8; 100];
    let mut bytes2 = [0u8; 100];
    rng1.fill(&mut bytes1);
    rng2.fill(&mut bytes2);
    assert_eq!(bytes1, bytes2, "PRNG should be deterministic for same inputs");
    
    // Test vector 2: Different contexts produce different outputs
    let mut rng3 = prng::from_key_and_context(&key, b"different-context").unwrap();
    let mut bytes3 = [0u8; 100];
    rng3.fill(&mut bytes3);
    assert_ne!(bytes1, bytes3, "Different contexts should produce different outputs");
    
    // Test vector 3: next_index method
    let mut rng4 = prng::from_key_and_context(&key, info).unwrap();
    let mut rng5 = prng::from_key_and_context(&key, info).unwrap();
    
    let indices1: Vec<usize> = (0..50).map(|_| rng4.next_index(10)).collect();
    let indices2: Vec<usize> = (0..50).map(|_| rng5.next_index(10)).collect();
    assert_eq!(indices1, indices2, "next_index should be deterministic");
    
    // Verify all indices are in valid range
    for &idx in &indices1 {
        assert!(idx < 10, "next_index should return values in [0, n)");
    }
    
    // Test vector 4: Edge cases for next_index
    let mut rng6 = prng::from_key_and_context(&key, info).unwrap();
    let idx1 = rng6.next_index(1); // Should always be 0
    assert_eq!(idx1, 0, "next_index(1) should always return 0");
    
    let idx256 = rng6.next_index(256); // Should be in [0, 256)
    assert!(idx256 < 256, "next_index(256) should return values in [0, 256)");
}

/// Test vectors for policy encoding - these test the canonical string representation
#[test]
fn policy_encoding_test_vectors() {
    // Test vector 1: Default policy
    let default_pol = policy::default_policy();
    let encoded = policy::encode(&default_pol);
    assert_eq!(encoded, "min=12;max=16;allow=lower,upper,digit,symbol;force=");
    
    // Test vector 2: Policy with forced sets
    let pol = policy::Policy {
        min: 8,
        max: 12,
        allow: [true, true, false, true],
        force: [true, false, false, true],
    };
    let encoded = policy::encode(&pol);
    assert_eq!(encoded, "min=8;max=12;allow=lower,upper,symbol;force=lower,symbol");
    
    // Test vector 3: Policy with only one allowed set
    let pol = policy::Policy {
        min: 10,
        max: 10,
        allow: [false, false, true, false],
        force: [false, false, true, false],
    };
    let encoded = policy::encode(&pol);
    assert_eq!(encoded, "min=10;max=10;allow=digit;force=digit");
    
    // Test vector 4: Policy with no forced sets
    let pol = policy::Policy {
        min: 6,
        max: 20,
        allow: [true, true, true, true],
        force: [false, false, false, false],
    };
    let encoded = policy::encode(&pol);
    assert_eq!(encoded, "min=6;max=20;allow=lower,upper,digit,symbol;force=");
}

/// Test vectors for allowed alphabet generation
#[test]
fn policy_alphabet_test_vectors() {
    // Test vector 1: All sets allowed
    let pol = policy::Policy {
        min: 8,
        max: 8,
        allow: [true, true, true, true],
        force: [false, false, false, false],
    };
    let alphabet = policy::allowed_alphabet(&pol);
    let expected_len = 26 + 26 + 10 + 31; // lower + upper + digit + symbol
    assert_eq!(alphabet.len(), expected_len);
    
    // Verify all expected characters are present
    let alphabet_str = String::from_utf8(alphabet.clone()).unwrap();
    assert!(alphabet_str.contains('a'), "Should contain lowercase letters");
    assert!(alphabet_str.contains('Z'), "Should contain uppercase letters");
    assert!(alphabet_str.contains('5'), "Should contain digits");
    assert!(alphabet_str.contains('!'), "Should contain symbols");
    
    // Test vector 2: Only lowercase and digits
    let pol = policy::Policy {
        min: 8,
        max: 8,
        allow: [true, false, true, false],
        force: [false, false, false, false],
    };
    let alphabet = policy::allowed_alphabet(&pol);
    assert_eq!(alphabet.len(), 26 + 10); // lower + digit
    
    // Test vector 3: Only symbols
    let pol = policy::Policy {
        min: 8,
        max: 8,
        allow: [false, false, false, true],
        force: [false, false, false, false],
    };
    let alphabet = policy::allowed_alphabet(&pol);
    assert_eq!(alphabet.len(), 31); // symbol only
}

/// Test vectors for forced sets
#[test]
fn policy_forced_sets_test_vectors() {
    // Test vector 1: No forced sets
    let pol = policy::Policy {
        min: 8,
        max: 8,
        allow: [true, true, true, true],
        force: [false, false, false, false],
    };
    let forced = policy::forced_sets(&pol);
    assert_eq!(forced.len(), 0);
    
    // Test vector 2: All sets forced
    let pol = policy::Policy {
        min: 8,
        max: 8,
        allow: [true, true, true, true],
        force: [true, true, true, true],
    };
    let forced = policy::forced_sets(&pol);
    assert_eq!(forced.len(), 4);
    
    // Test vector 3: Some sets forced
    let pol = policy::Policy {
        min: 8,
        max: 8,
        allow: [true, true, true, true],
        force: [true, false, true, false],
    };
    let forced = policy::forced_sets(&pol);
    assert_eq!(forced.len(), 2);
    
    // Test vector 4: Forced sets not in allowed sets (should be filtered out)
    let pol = policy::Policy {
        min: 8,
        max: 8,
        allow: [true, false, true, false],
        force: [true, true, true, true], // force includes sets not in allow
    };
    let forced = policy::forced_sets(&pol);
    assert_eq!(forced.len(), 2); // Only lower and digit should be included
}

/// Comprehensive password generation test vectors
#[test]
fn password_generation_test_vectors() {
    // Test vector 1: Basic deterministic generation
    let pol = policy::Policy {
        min: 12,
        max: 12,
        allow: [true, true, true, true],
        force: [false, false, false, false],
    };
    let pol = policy::validate(&pol).unwrap();
    
    let pwd1 = generator::generate_password("master123", "example.com", Some("alice"), &pol, 1).unwrap();
    let pwd2 = generator::generate_password("master123", "example.com", Some("alice"), &pol, 1).unwrap();
    assert_eq!(pwd1, pwd2, "Same inputs should produce same password");
    assert_eq!(pwd1.len(), 12, "Password should have correct length");
    
    // Test vector 2: Different version produces different password
    let pwd3 = generator::generate_password("master123", "example.com", Some("alice"), &pol, 2).unwrap();
    assert_ne!(pwd1, pwd3, "Different version should produce different password");
    
    // Test vector 3: Different username produces different password
    let pwd4 = generator::generate_password("master123", "example.com", Some("bob"), &pol, 1).unwrap();
    assert_ne!(pwd1, pwd4, "Different username should produce different password");
    
    // Test vector 4: Different site produces different password
    let pwd5 = generator::generate_password("master123", "different.com", Some("alice"), &pol, 1).unwrap();
    assert_ne!(pwd1, pwd5, "Different site should produce different password");
    
    // Test vector 5: Forced character sets
    let pol_forced = policy::Policy {
        min: 8,
        max: 8,
        allow: [true, true, true, true],
        force: [true, true, false, false], // Force lowercase and uppercase
    };
    let pol_forced = policy::validate(&pol_forced).unwrap();
    
    let pwd_forced = generator::generate_password("master123", "test.com", None, &pol_forced, 1).unwrap();
    assert_eq!(pwd_forced.len(), 8);
    
    // Verify forced characters are present
    let has_lower = pwd_forced.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = pwd_forced.chars().any(|c| c.is_ascii_uppercase());
    assert!(has_lower, "Password should contain lowercase letter");
    assert!(has_upper, "Password should contain uppercase letter");
    
    // Test vector 6: Variable length passwords
    let pol_var = policy::Policy {
        min: 8,
        max: 16,
        allow: [true, true, true, true],
        force: [false, false, false, false],
    };
    let pol_var = policy::validate(&pol_var).unwrap();
    
    // Generate multiple passwords and verify they're within bounds
    for _ in 0..10 {
        let pwd = generator::generate_password("master123", "test.com", None, &pol_var, 1).unwrap();
        assert!(pwd.len() >= 8 && pwd.len() <= 16, "Password length should be within bounds");
    }
    
    // Test vector 7: Edge case - minimum length with forced sets
    let pol_edge = policy::Policy {
        min: 2,
        max: 2,
        allow: [true, true, false, false],
        force: [true, true, false, false], // Force exactly 2 sets for length 2
    };
    let pol_edge = policy::validate(&pol_edge).unwrap();
    
    let pwd_edge = generator::generate_password("master123", "test.com", None, &pol_edge, 1).unwrap();
    assert_eq!(pwd_edge.len(), 2);
    
    // Test vector 8: Only one character set allowed
    let pol_single = policy::Policy {
        min: 10,
        max: 10,
        allow: [false, false, true, false], // Only digits
        force: [false, false, false, false],
    };
    let pol_single = policy::validate(&pol_single).unwrap();
    
    let pwd_single = generator::generate_password("master123", "test.com", None, &pol_single, 1).unwrap();
    assert_eq!(pwd_single.len(), 10);
    assert!(pwd_single.chars().all(|c| c.is_ascii_digit()), "Password should contain only digits");
}

/// Test vectors for policy validation edge cases
#[test]
fn policy_validation_test_vectors() {
    // Test vector 1: Valid policy
    let pol = policy::Policy {
        min: 8,
        max: 16,
        allow: [true, true, true, true],
        force: [false, false, false, false],
    };
    let validated = policy::validate(&pol).unwrap();
    assert_eq!(validated.min, 8);
    assert_eq!(validated.max, 16);
    
    // Test vector 2: Clamped bounds
    let pol = policy::Policy {
        min: 0,
        max: 200,
        allow: [true, true, true, true],
        force: [false, false, false, false],
    };
    let validated = policy::validate(&pol).unwrap();
    assert_eq!(validated.min, 1);
    assert_eq!(validated.max, 128);
    
    // Test vector 3: Invalid bounds (min > max)
    let pol = policy::Policy {
        min: 20,
        max: 10,
        allow: [true, true, true, true],
        force: [false, false, false, false],
    };
    let result = policy::validate(&pol);
    assert!(result.is_err(), "min > max should be invalid");
    
    // Test vector 4: Empty allowed sets
    let pol = policy::Policy {
        min: 8,
        max: 16,
        allow: [false, false, false, false],
        force: [false, false, false, false],
    };
    let result = policy::validate(&pol);
    assert!(result.is_err(), "Empty allowed sets should be invalid");
    
    // Test vector 5: Force not subset of allow
    let pol = policy::Policy {
        min: 8,
        max: 16,
        allow: [true, false, true, false],
        force: [true, true, true, true], // force includes sets not in allow
    };
    let result = policy::validate(&pol);
    assert!(result.is_err(), "Force should be subset of allow");
    
    // Test vector 6: Min less than forced count
    let pol = policy::Policy {
        min: 2,
        max: 16,
        allow: [true, true, true, true],
        force: [true, true, true, true], // 4 forced sets but min=2
    };
    let result = policy::validate(&pol);
    assert!(result.is_err(), "Min should be >= number of forced sets");
}

/// Test vectors for character distribution and randomness
#[test]
fn character_distribution_test_vectors() {
    let pol = policy::Policy {
        min: 100,
        max: 100,
        allow: [true, true, true, true],
        force: [false, false, false, false],
    };
    let pol = policy::validate(&pol).unwrap();
    
    // Generate multiple passwords and check character distribution
    let mut all_chars = std::collections::HashSet::new();
    let mut char_counts = std::collections::HashMap::new();
    
    for i in 0..20 {
        let pwd = generator::generate_password("master123", &format!("site{}", i), None, &pol, 1).unwrap();
        
        for ch in pwd.chars() {
            all_chars.insert(ch);
            *char_counts.entry(ch).or_insert(0) += 1;
        }
    }
    
    // Should have reasonable character diversity
    assert!(all_chars.len() > 20, "Should have good character diversity");
    
    // Each character type should appear
    let has_lower = all_chars.iter().any(|&c| c.is_ascii_lowercase());
    let has_upper = all_chars.iter().any(|&c| c.is_ascii_uppercase());
    let has_digit = all_chars.iter().any(|&c| c.is_ascii_digit());
    let has_symbol = all_chars.iter().any(|&c| "!\"#$%&'()*+,-./:;<=>?@[\\]^_{|}~".contains(c));
    
    assert!(has_lower, "Should generate lowercase letters");
    assert!(has_upper, "Should generate uppercase letters");
    assert!(has_digit, "Should generate digits");
    assert!(has_symbol, "Should generate symbols");
}

/// Test that validates the contract: generator should never return InvalidInput
/// for policy-related reasons when called with a validated policy.
#[test]
fn generator_contract_validated_policy() {
    use pwgen::generator::GenError;
    
    // Test various validated policies - none should cause InvalidInput
    let test_policies = vec![
        // Standard policy
        policy::Policy {
            min: 12,
            max: 16,
            allow: [true, true, true, true],
            force: [false, false, false, false],
        },
        // Min equals forced count
        policy::Policy {
            min: 4,
            max: 8,
            allow: [true, true, true, true],
            force: [true, true, true, true],
        },
        // Clamped values
        policy::Policy {
            min: 0,
            max: 200,
            allow: [true, true, true, true],
            force: [false, false, false, false],
        },
        // Single character set
        policy::Policy {
            min: 10,
            max: 10,
            allow: [false, false, true, false],
            force: [false, false, false, false],
        },
        // Max length
        policy::Policy {
            min: 128,
            max: 128,
            allow: [true, true, true, true],
            force: [false, false, false, false],
        },
        // Minimum length with forced sets
        policy::Policy {
            min: 2,
            max: 2,
            allow: [true, true, false, false],
            force: [true, true, false, false],
        },
    ];
    
    for pol in test_policies {
        // Validate the policy first
        let validated = match policy::validate(&pol) {
            Ok(p) => p,
            Err(_) => continue, // Skip invalid policies (we test those separately)
        };
        
        // Generate password - should never return InvalidInput for policy reasons
        let result = generator::generate_password("master123", "test.com", None, &validated, 1);
        
        match result {
            Ok(_) => {
                // Success - this is fine
            }
            Err(GenError::InvalidInput(msg)) => {
                panic!(
                    "generate_password returned InvalidInput for validated policy: {}. \
                     Policy: min={}, max={}, allow={:?}, force={:?}",
                    msg, validated.min, validated.max, validated.allow, validated.force
                );
            }
            Err(GenError::Policy(_)) => {
                // Policy error should not happen after validation
                panic!("generate_password returned Policy error for validated policy");
            }
            Err(GenError::Kdf(_)) | Err(GenError::Prng(_)) => {
                // These are acceptable - not policy-related
            }
        }
    }
}
