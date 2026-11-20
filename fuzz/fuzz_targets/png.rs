#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../../tests/fuzz_props/spans.rs"]
mod spans;
#[path = "../../tests/fuzz_props/png.rs"]
mod props;

fuzz_target!(|data: &[u8]| {
    props::check(data);
});
