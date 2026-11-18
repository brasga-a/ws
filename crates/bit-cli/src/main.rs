//! Binary entry point for `bit`.
#![forbid(unsafe_code)]

use std::io;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut stdout = io::stdout().lock();
    match bit_cli::run_from_env(&mut stdout) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}
