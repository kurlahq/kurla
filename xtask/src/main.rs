mod cooldown;
mod gen_unicode;

use std::process::ExitCode;

fn main() -> ExitCode {
    match std::env::args().nth(1).as_deref() {
        Some("cooldown-check") => cooldown::run(),
        Some("gen-unicode") => gen_unicode::run(),
        _ => ExitCode::from(2),
    }
}
