//! `kc4n6` binary — a thin shell over the `keychain_forensic` library (Humble
//! Object): parse args, run the audit, print (text or JSON), set the exit code.
//! All decisions live in the library so they are unit-tested; this file is the
//! irreducible I/O + transport shell.

use std::process::ExitCode;

use clap::Parser;
use keychain_forensic::{render_text, Cli};

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.run() {
        Ok(report) => {
            if cli.json {
                match serde_json::to_string_pretty(&report) {
                    Ok(s) => println!("{s}"),
                    Err(e) => {
                        eprintln!("error serializing report: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            } else {
                print!("{}", render_text(&report));
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("kc4n6: {e}");
            ExitCode::FAILURE
        }
    }
}
