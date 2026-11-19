use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match (args.next().as_deref(), args.next()) {
        (Some("--version"), None) => {
            println!("kurla {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        _ => ExitCode::from(2),
    }
}
