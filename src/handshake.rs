pub const CONFIG_END: &str = "config|ready";
pub const CONFIG_TAG: &str = "config|";

pub fn read_config() {
	let mut buffer = String::new();
	let stdin = std::io::stdin();
	loop {
		buffer.clear();
		stdin.read_line(&mut buffer).unwrap();
		let entry = buffer.trim_end();
		if entry == CONFIG_END {
			return;
		}
		if !entry.starts_with(CONFIG_TAG) {
			eprintln!("invalid config line: {entry}");
		}
	}
}

pub fn register_filter() {
	println!("register|filter|smtp-in|data-line");
	println!("register|ready");
}
