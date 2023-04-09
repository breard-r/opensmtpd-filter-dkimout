use std::env;

const VARLIBDIR_NAME: &str = "VARLIBDIR";
const VARLIBDIR_VALUE_DEFAULT: &str = "/var/lib/";

fn main() {
	// trigger recompilation when a new migration is added
	println!("cargo:rerun-if-changed=migrations");

	// set the VARLIBDIR env variable
	if env::var(VARLIBDIR_NAME).is_err() {
		println!(
			"cargo:rustc-env={}={}",
			VARLIBDIR_NAME, VARLIBDIR_VALUE_DEFAULT
		);
	}
}
