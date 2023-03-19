use crate::stdin_reader::StdinReader;

pub const CONFIG_END: &[u8] = b"config|ready\n";
pub const CONFIG_TAG: &[u8] = b"config|";

pub fn read_config(reader: &mut StdinReader) {
	loop {
		let line = reader.read_line();
		if line == CONFIG_END {
			return;
		}
		if !line.starts_with(CONFIG_TAG) {
			eprintln!("invalid config line: {line:?}");
		}
	}
}

pub fn register_filter() {
	println!("register|filter|smtp-in|data-line");
	println!("register|ready");
}
