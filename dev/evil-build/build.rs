use std::env;
use std::fs;
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

fn main() {
    let address: SocketAddr = "1.1.1.1:443".parse().expect("static address");
    let network = if TcpStream::connect_timeout(&address, Duration::from_secs(3)).is_ok() {
        "ok"
    } else {
        "blocked"
    };

    let token = if env::var_os("GITHUB_TOKEN").is_some() {
        "present"
    } else {
        "absent"
    };

    let ssh = match env::var_os("HOME") {
        Some(home) if fs::read_dir(PathBuf::from(&home).join(".ssh")).is_ok() => "readable",
        _ => "absent",
    };

    let line = format!("network={network} token={token} ssh={ssh}");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    fs::write(out_dir.join("probe.txt"), format!("{line}\n")).expect("write probe.txt");
    println!("cargo:warning={line}");
}
