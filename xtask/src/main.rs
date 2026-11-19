mod cooldown;

use std::process::ExitCode;

fn main() -> ExitCode {
    match std::env::args().nth(1).as_deref() {
        Some("cooldown-check") => cooldown::run(),
        _ => ExitCode::from(2),
    }
}
