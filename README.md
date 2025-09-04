# pwgen

Deterministic password generator using Argon2id + HKDF. Given a master secret and manually entered site identifier, produces per-site passwords with configurable policy. 


## Why use stateless-pwgen?

- Using the same passwords across sites is a security risk, since a single leak exposes your credentials for attackers to use everywhere else. Even ignoring security, different sites will torture you by differing rules for characters, spaces, capital letters, etc., or require frequent password changes.
- Memorizing numerous passwords across numerous sites, each with different formatting requirements, is stupidly impractical.
- Relying on a cloud-based password manager which use a master password or 2FA to keep track of different, site-specific passwords *can* be sound, but can result in your credentials (including your precious master password!) being exposed if you choose the wrong service. Google "password manager leaks".
- Relying on a local password manager -- whether a well-encrypted one or less sound options like a word document -- will leave you without all your passowords should your device be separated from you, stolen, or broken.
- Cyber security aside, depending on an external service for your passwords is just horrifying. They could stop their service or lose your data or inexplicably fail all your authentications when you use a different device.
- More traditional browser-based password managers, deterministic or not, are often confused by login domain names, and confuse email prompts with password prompts.



For more detailed discussions of deterministic password managers:
https://samuellucas.com/2024/02/25/deterministic-password-managers-revisited.html
https://medium.com/@mahdix/in-defense-of-deterministic-password-managers-67b5a549681e


For a fun illustration of our password hell:
https://neal.fun/password-game/


### "An attacker can reverse engineer your master password from a leaked site-specific password, and then ALL your credentials are compromised!"
This problem is addressed in the following ways:
1. Argon2id is used as the KDF to make guessing expensive.
2. The user-input site identifiers can be used as a second key - you can use aliases for site names, add dates in the string for password versioning, or even set each site identifier as a high-entropy string which you store in a password vault service.

### "I need to change a password for a single site without changing every other password."
Either 1) use the --version flag to rotate different passwords, or 2) put notes in the site identifier

### Limitations
1. stateless-pwgen does not defend against phishing, which a browser-extension password keeper can by noting the different url.
2. GUI is still under development. --master-prompt doesn't show the password, so typos can happen.
3. Does not keep track of usernames or other login info. TODO cache non-password login info


## How to Build

- Default build:

```
cargo build --release
```

- Enable TTY prompt for the master secret:

```
cargo build --release --features tty
```

## How to use

```
pwgen generate \
  --site <STRING> \
  [--master <STRING> | --master-prompt | --master-stdin] \
  [--username <STRING>] \
  [--length <INT> | --min <INT> --max <INT>] \
  [--allow <LIST>] [--force <LIST>] \
  [--no-lower] [--no-upper] [--no-digit] [--no-symbol] \
  [--version <UINT>] \
  [--json] [--verbose]
```

**Required flags:**

- `--site <STRING>`  
  The site identifier for which to generate a password. This value is trimmed of whitespace and converted to lowercase before use. It is used to derive a unique password per site.

- Exactly one master secret source must be provided (choose one of the following):
  - `--master <STRING>`  
    Provide the master secret directly on the command line. **Warning:** This is insecure, as the secret may be visible in process listings or shell history.
  - `--master-prompt`  
    Securely prompt for the master secret on the terminal (TTY). This is the recommended method, but requires building with `--features tty` to enable TTY support.
  - `--master-stdin`  
    Read the entire standard input as the master secret. Useful for scripting or when piping secrets from other tools.

**Optional flags:**

- `--username <STRING>`  
  An optional username to include in the password context. The value is used exactly as provided (no trimming or case normalization). This can be used to generate different passwords for the same site and master secret, based on the username.

- Length options (choose one):
  - `--length <N>`  
    Generate a password of exactly N characters.
  - `--min <N> --max <N>`  
    Specify a minimum and maximum password length. The actual length will be chosen uniformly at random in the range `[min, max]`.  
    If neither is specified, the default is a random length between 12 and 16 characters.  
    The allowed range is capped between 1 and 128.

- Character set options:
  - `--allow <LIST>`  
    Specify which character sets are allowed in the password. The list can include any combination of: `lower`, `upper`, `digit`, `symbol`. Example: `--allow lower,upper,digit`
  - `--force <LIST>`  
    Require at least one character from each specified set (same options as `--allow`). Example: `--force symbol`
  - Shorthand disables:  
    `--no-lower`, `--no-upper`, `--no-digit`, `--no-symbol`  
    Exclude the corresponding character set from the allowed pool.

- `--version <UINT>`  
  Password version or rotation number. Defaults to 1. Changing this value will generate a different password for the same inputs, allowing for password rotation.

- Output options:
  - (default)  
    Prints the generated password to standard output as plain text.
  - `--json`  
    Output a single-line JSON object containing the password and relevant metadata.
  - `--verbose`  
    Print a summary of the generation parameters and context to standard error (stderr), in addition to the password output.

### Examples

- Prompt for master (recommended):

```
pwgen generate --site example.com --master-prompt
```

- Fixed length 20, force at least one symbol:

```
pwgen generate --site example.com --master-stdin --length 20 --force symbol
```

- JSON output with username and policy tweaks:

```
pwgen generate --site example.com --username alice --min 14 --max 18 --no-symbol --json
```

## Exit codes

- 0: success
- 2: invalid user input
- 3: generation failure (reserved; not used in v0.1)
- 4: unexpected/internal error

## Algorithm (v1)

- Site normalization: `site_id = site.trim().to_ascii_lowercase()`
- Salt: `salt = SHA256(b"pwgen-salt-v1:" || site_id)[0..16]`
- KDF: Argon2id with memory=64 MiB, iterations=3, parallelism=1, output=32 bytes
- PRNG: HKDF-SHA256 stream
  - PRK = HKDF-Extract(salt=b"pwgen-hkdf-salt-v1", IKM=KDF key)
  - Expand blocks T(n): HMAC(PRK, [T(n-1) ||] info || n) with n starting at 1
- PRNG context `info` (ASCII/UTF-8 concat):
  - `b"pwgen-v1|site=" + site_id + b"|user=" + username + b"|policy=" + policy::encode(policy) + b"|version=" + decimal(version)`
- Length selection: if `min==max` use fixed; else uniform in `[min,max]` via rejection sampling
- Character selection:
  - Draw one from each forced set (lower→upper→digit→symbol)
  - Fill remaining from union(allowed)
  - Fisher–Yates shuffle with PRNG

## Security notes

- Master secret is zeroized after use; KDF buffers and PRK are zeroized on drop.
- Build with `--features tty` to avoid echoing the master secret on the terminal.
- No DNS/IDNA normalization in v0.1; `--site` is lowercased + trimmed only.

## Development

- Run tests:

```
cargo test
```

- Lint (via compiler warnings): ensure `cargo build` is clean.

## Test vectors (for manual testing)

```text
master = "master123"
site   = "example.com"
username   = "alice"
password = "!uZ5S_;H@x-m"
```

```text
master = "master123"
site   = "different.com"
version = 2
username   = "alice"
password = "_;|}p%]+f*Hk2"
```

```text
master = "master123"
site   = "test.com"
policy = { length=8, force=[lower,upper] }
password = "Iv(N\wq="
```
## License

Licensed under Apache-2.0
