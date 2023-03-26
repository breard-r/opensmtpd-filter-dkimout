use std::env;

const DEFAULT_VARLIBDIR: &str = "/var/lib/";

fn main() {
	if let Err(_) = env::var("VARLIBDIR") {
		println!("cargo:rustc-env={}={}", "VARLIBDIR", DEFAULT_VARLIBDIR);
	}
}
