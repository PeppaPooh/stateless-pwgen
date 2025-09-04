use pwgen::{generator, policy};

fn gen(
    master: &str,
    site: &str,
    username: Option<&str>,
    min: u8,
    max: u8,
    allow: [bool; 4],
    force: [bool; 4],
    version: u32,
) -> String {
    let pol = policy::Policy { min, max, allow, force };
    let pol = policy::validate(&pol).unwrap();
    generator::generate_password(master, site, username, &pol, version).unwrap()
}

#[test]
fn determinism_same_inputs_same_output() {
    let p1 = gen("master", "example.com", Some("alice"), 12, 16, [true, true, true, true], [false, false, false, false], 1);
    let p2 = gen("master", "example.com", Some("alice"), 12, 16, [true, true, true, true], [false, false, false, false], 1);
    assert_eq!(p1, p2);
}

#[test]
fn length_bounds_and_fixed_length() {
    let p = gen("m", "s", None, 8, 12, [true, true, true, true], [false, false, false, false], 1);
    assert!((8..=12).contains(&p.len()));

    let p_fixed = gen("m", "s", None, 20, 20, [true, true, true, true], [false, false, false, false], 1);
    assert_eq!(p_fixed.len(), 20);
}

#[test]
fn allowed_alphabet_only() {
    let allow = [true, false, true, false]; // lower + digit
    let force = [false, false, false, false];
    let pol = policy::validate(&policy::Policy { min: 16, max: 16, allow, force }).unwrap();
    let s = generator::generate_password("m", "ex", None, &pol, 1).unwrap();

    let alphabet = policy::allowed_alphabet(&pol);
    for &b in s.as_bytes() {
        assert!(alphabet.contains(&b), "byte {} not in allowed alphabet", b);
    }
}

#[test]
fn forced_presence() {
    let allow = [true, true, true, true];
    let force = [true, false, true, false]; // require lower and digit
    let pol = policy::validate(&policy::Policy { min: 8, max: 8, allow, force }).unwrap();
    let s = generator::generate_password("m", "ex", None, &pol, 1).unwrap();

    let sets = policy::forced_sets(&pol);
    for (_cs, alphabet) in sets {
        assert!(s.as_bytes().iter().any(|b| alphabet.contains(b)), "missing required set member");
    }
}

#[test]
fn shuffle_sanity_first_char_varies() {
    // Enable some forced sets and sample across varying site or version to see first char vary
    let allow = [true, true, true, true];
    let force = [true, true, false, false];
    let mut first_chars = std::collections::BTreeSet::new();
    for i in 0..20u32 {
        let s = gen("m", &format!("site-{}", i), None, 12, 16, allow, force, 1);
        first_chars.insert(s.as_bytes()[0]);
    }
    assert!(first_chars.len() > 1, "first character distribution seems constant");
}

#[test]
fn versioning_changes_output() {
    let p1 = gen("m", "ex", None, 12, 16, [true, true, true, true], [false, false, false, false], 1);
    let p2 = gen("m", "ex", None, 12, 16, [true, true, true, true], [false, false, false, false], 2);
    assert_ne!(p1, p2);
}

#[test]
fn username_changes_output() {
    let p1 = gen("m", "ex", None, 12, 16, [true, true, true, true], [false, false, false, false], 1);
    let p2 = gen("m", "ex", Some("alice"), 12, 16, [true, true, true, true], [false, false, false, false], 1);
    assert_ne!(p1, p2);
}

#[test]
fn policy_changes_output() {
    let allow = [true, true, true, true];
    let s1 = gen("m", "ex", None, 12, 12, allow, [false, false, false, false], 1);
    let s2 = gen("m", "ex", None, 12, 12, allow, [false, false, false, true], 1);
    assert_ne!(s1, s2);
}

#[test]
fn edge_cases() {
    // min=1,max=1
    let s = gen("m", "ex", None, 1, 1, [true, false, false, false], [false, false, false, false], 1);
    assert_eq!(s.len(), 1);

    // allow only one set
    let s = gen("m", "ex", None, 8, 8, [false, true, false, false], [false, false, false, false], 1);
    assert!(s.chars().all(|c| "ABCDEFGHIJKLMNOPQRSTUVWXYZ".contains(c)));

    // allow=symbol only
    let s = gen("m", "ex", None, 8, 8, [false, false, false, true], [false, false, false, false], 1);
    assert!(s.chars().all(|c| "!\"#$%&'()*+,-./:;<=>?@[\\]^_{|}~".contains(c)));

    // very small L with forced set exactly fitting
    let p = policy::validate(&policy::Policy { min: 2, max: 2, allow: [true, true, false, false], force: [true, true, false, false] }).unwrap();
    let s = generator::generate_password("m", "ex", None, &p, 1).unwrap();
    assert_eq!(s.len(), 2);
    assert!(s.chars().any(|c| ("abcdefghijklmnopqrstuvwxyz").contains(c)));
    assert!(s.chars().any(|c| ("ABCDEFGHIJKLMNOPQRSTUVWXYZ").contains(c)));
}
