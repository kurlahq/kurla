mod cooldown;
mod gen_unicode;
mod mutants_check;
mod mutants_unique;
mod perf_tree;

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("cooldown-check") => cooldown::run(),
        Some("gen-unicode") => gen_unicode::run(),
        Some("mutants-check") => mutants_check::run(&args[1..]),
        Some("mutants-unique") => mutants_unique::run(&args[1..]),
        Some("perf-tree") => perf_tree::run(&args[1..]),
        _ => ExitCode::from(2),
    }
}
