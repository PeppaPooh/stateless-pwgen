use std::io::{self, Read};
use std::process;

use anyhow::{anyhow, Context, Result};
use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};
use zeroize::Zeroize;
use pwgen::generator::{self, GenError};
use pwgen::policy;

/// CLI for deterministic password generator.
#[derive(Debug, Parser)]
#[command(name = "pwgen", version, about = "Deterministic password generator using Argon2id and HKDF")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Generate a password
    Generate(GenerateArgs),
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum CliCharset {
    Lower,
    Upper,
    Digit,
    Symbol,
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("master_input")
        .required(true)
        .args(["master", "master_prompt", "master_stdin"]) 
))]
struct GenerateArgs {
    /// Site identifier (trimmed and lowercased)
    #[arg(long, value_name = "STRING")]
    site: String,

    /// Master secret provided directly (dangerous)
    #[arg(long, value_name = "STRING")]
    master: Option<String>,

    /// Prompt for master secret on the TTY (preferred)
    #[arg(long = "master-prompt")]
    master_prompt: bool,

    /// Read entire stdin as master secret
    #[arg(long = "master-stdin")]
    master_stdin: bool,

    /// Optional username to include in context
    #[arg(long, value_name = "STRING", default_value = "")]
    username: String,

    /// Fixed length
    #[arg(long, value_name = "INT")]
    length: Option<u32>,

    /// Minimum length
    #[arg(long, value_name = "INT", default_value_t = 12)]
    min: u32,

    /// Maximum length
    #[arg(long, value_name = "INT", default_value_t = 16)]
    max: u32,

    /// Allowed character sets (comma-separated)
    #[arg(long = "allow", value_delimiter = ',', value_enum)]
    allow_sets: Vec<CliCharset>,

    /// Forced character sets to include (comma-separated; subset of allow)
    #[arg(long = "force", value_delimiter = ',', value_enum)]
    force_sets: Vec<CliCharset>,

    /// Disallow lowercase letters
    #[arg(long = "no-lower")]
    no_lower: bool,

    /// Disallow uppercase letters
    #[arg(long = "no-upper")]
    no_upper: bool,

    /// Disallow digits
    #[arg(long = "no-digit")]
    no_digit: bool,

    /// Disallow symbols
    #[arg(long = "no-symbol")]
    no_symbol: bool,

    /// Rotation/version number
    #[arg(long, value_name = "UINT", default_value_t = 1)]
    version: u32,

    /// Print a JSON object with details instead of plain password
    #[arg(long)]
    json: bool,

    /// Print extra info (to stderr)
    #[arg(long)]
    verbose: bool,
}

fn main() {
    let cli = Cli::parse();
    let exit_code = match run(cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {:#}", err);
            4
        }
    };
    process::exit(exit_code);
}

fn run(cli: Cli) -> Result<i32> {
    match cli.command {
        Commands::Generate(args) => handle_generate(args),
    }
}

fn handle_generate(args: GenerateArgs) -> Result<i32> {
    // Normalize and validate site
    let site = args.site.trim().to_lowercase();
    if site.is_empty() {
        eprintln!("invalid input: --site must be nonempty after trim");
        return Ok(2);
    }

    // Resolve master secret via exactly one method (clap group enforces one)
    let mut master = match (args.master, args.master_prompt, args.master_stdin) {
        (Some(m), false, false) => m,
        (None, true, false) => read_master_prompt()?,
        (None, false, true) => read_master_stdin()?,
        _ => unreachable!("clap ArgGroup enforces exclusivity"),
    };

    if master.is_empty() {
        master.zeroize();
        eprintln!("invalid input: master secret must be nonempty");
        return Ok(2);
    }

    // Determine length constraints (CLI input shape validation only)
    let (_length, min, max) = normalize_length(args.length, args.min, args.max).map_err(|e| {
        eprintln!("invalid input: {}", e);
        anyhow!(e)
    })?;

    // Determine allowed and forced sets (CLI input shape validation only)
    let (allowed, forced) = normalize_policy_sets(
        &args.allow_sets,
        &args.force_sets,
        args.no_lower,
        args.no_upper,
        args.no_digit,
        args.no_symbol,
    )
    .map_err(|e| {
        eprintln!("invalid input: {}", e);
        anyhow!(e)
    })?;

    // Convert CLI inputs to Policy, handling u32 -> u8 conversion safely
    // All policy invariant validation will be done by policy::validate()
    let pol = match cli_to_policy(min, max, allowed, forced) {
        Ok(p) => p,
        Err(e) => {
            master.zeroize();
            eprintln!("invalid input: {}", e);
            return Ok(2);
        }
    };

    // Validate policy - this is the single source of truth for policy invariants
    let pol = match policy::validate(&pol) {
        Ok(p) => p,
        Err(e) => {
            master.zeroize();
            eprintln!("invalid input: {}", e);
            return Ok(2);
        }
    };

    let username_opt = if args.username.is_empty() {
        None
    } else {
        Some(args.username.as_str())
    };

    if args.verbose {
        let pol_enc = policy::encode(&pol);
        eprintln!(
            "Generating password...\n  site: {}\n  username: {}\n  version: {}\n  policy: {}",
            site,
            username_opt.unwrap_or("<empty>"),
            args.version,
            pol_enc
        );
    }

    let result = generator::generate_password(&master, &site, username_opt, &pol, args.version);

    // Zeroize master ASAP after generation call returns
    master.zeroize();

    match result {
        Ok(password) => {
            if args.json {
                // Manually compose a single-line JSON
                let length_out = password.chars().count();
                let username_json = username_opt.unwrap_or("");
                let policy_str = policy::encode(&pol);
                let algo_version = 1; // placeholder for algorithm versioning
                println!(
                    "{{\"password\":\"{}\",\"length\":{},\"site\":\"{}\",\"username\":\"{}\",\"version\":{},\"policy\":\"{}\",\"algo_version\":{}}}",
                    escape_json_string(&password),
                    length_out,
                    escape_json_string(&site),
                    escape_json_string(username_json),
                    args.version,
                    escape_json_string(&policy_str),
                    algo_version
                );
            } else {
                println!("{}", password);
            }
            Ok(0)
        }
        Err(GenError::Policy(e)) => { eprintln!("policy error: {}", e); Ok(2) }
        Err(GenError::Kdf(e)) => { eprintln!("kdf error: {}", e); Ok(4) }
        Err(GenError::Prng(e)) => { eprintln!("prng error: {}", e); Ok(4) }
        Err(GenError::InvalidInput(msg)) => { eprintln!("invalid input: {}", msg); Ok(2) }
    }
}

/// Converts CLI length inputs to normalized form.
/// 
/// This function only performs basic input shape validation (non-zero, reasonable bounds).
/// Actual policy bounds validation (1 ≤ min ≤ max ≤ 128) is done by `policy::validate()`.
fn normalize_length(length: Option<u32>, min: u32, max: u32) -> std::result::Result<(Option<u32>, u32, u32), String> {
    const MAX_ALLOWED: u32 = 128;
    if let Some(len) = length {
        if len == 0 || len > MAX_ALLOWED {
            return Err(format!("--length must be within [1,{}]", MAX_ALLOWED));
        }
        return Ok((Some(len), len, len));
    }
    // Basic sanity checks for UX - full validation happens in policy::validate()
    if min == 0 || min > MAX_ALLOWED {
        return Err(format!("--min must be within [1,{}]", MAX_ALLOWED));
    }
    if max == 0 || max > MAX_ALLOWED {
        return Err(format!("--max must be within [1,{}]", MAX_ALLOWED));
    }
    if min > max {
        return Err("--min must be ≤ --max".to_string());
    }
    Ok((None, min, max))
}

/// Converts CLI charset inputs to normalized boolean arrays.
/// 
/// This function performs basic CLI input shape validation (early UX feedback).
/// Actual policy invariant validation (allow nonempty, force ⊆ allow) is done by `policy::validate()`.
fn normalize_policy_sets(
    allow_list: &[CliCharset],
    force_list: &[CliCharset],
    no_lower: bool,
    no_upper: bool,
    no_digit: bool,
    no_symbol: bool,
) -> std::result::Result<([bool;4], [bool;4]), String> {
    // Start with defaults = all allowed
    let mut allowed = [true, true, true, true];

    // Apply explicit allow list if provided
    if !allow_list.is_empty() {
        allowed = [
            allow_list.contains(&CliCharset::Lower),
            allow_list.contains(&CliCharset::Upper),
            allow_list.contains(&CliCharset::Digit),
            allow_list.contains(&CliCharset::Symbol),
        ];
    }

    // Apply shorthand toggles to allowed
    if no_lower {
        allowed[0] = false;
    }
    if no_upper {
        allowed[1] = false;
    }
    if no_digit {
        allowed[2] = false;
    }
    if no_symbol {
        allowed[3] = false;
    }

    // Early UX feedback - full validation in policy::validate()
    if !allowed.iter().any(|&b| b) {
        return Err("allowed sets cannot be empty".to_string());
    }

    let forced = [
        force_list.contains(&CliCharset::Lower),
        force_list.contains(&CliCharset::Upper),
        force_list.contains(&CliCharset::Digit),
        force_list.contains(&CliCharset::Symbol),
    ];

    // Early UX feedback - full validation in policy::validate()
    if (forced[0] && !allowed[0]) || (forced[1] && !allowed[1]) || (forced[2] && !allowed[2]) || (forced[3] && !allowed[3]) {
        return Err("forced sets must be subset of allowed".to_string());
    }

    Ok((allowed, forced))
}

fn read_master_prompt() -> Result<String> {
    #[cfg(feature = "tty")]
    {
        let prompt = "Master: ";
        let master = rpassword::prompt_password(prompt).context("failed to read TTY password")?;
        Ok(master)
    }

    #[cfg(not(feature = "tty"))]
    {
        Err(anyhow!(
            "--master-prompt requested but binary built without 'tty' feature (enable with --features tty)"
        ))
    }
}

fn read_master_stdin() -> Result<String> {
    let mut buf = String::new();
    io::stdin()
        .read_to_string(&mut buf)
        .context("failed to read from stdin")?;
    // Keep as provided (no trim), but normalize Windows CRLF
    if buf.ends_with('\n') {
        while buf.ends_with('\n') || buf.ends_with('\r') {
            buf.pop();
        }
    }
    Ok(buf)
}

/// Safely converts CLI inputs (u32) to Policy (u8), ensuring no lossy casts.
/// 
/// This helper ensures that min/max values are within valid range [1, 128] before
/// casting from u32 to u8. The returned Policy is not yet validated - call
/// `policy::validate()` to enforce all invariants.
fn cli_to_policy(
    min: u32,
    max: u32,
    allow: [bool; 4],
    force: [bool; 4],
) -> std::result::Result<policy::Policy, String> {
    const MAX_VALID: u32 = 128;
    
    // Ensure values fit in u8 before casting
    if min == 0 || min > MAX_VALID {
        return Err(format!("min length must be within [1,{}]", MAX_VALID));
    }
    if max == 0 || max > MAX_VALID {
        return Err(format!("max length must be within [1,{}]", MAX_VALID));
    }
    
    // Safe cast: we've verified both values are in [1, 128]
    Ok(policy::Policy {
        min: min as u8,
        max: max as u8,
        allow,
        force,
    })
}

fn escape_json_string(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 8);
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}
