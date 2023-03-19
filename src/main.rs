mod entry;
mod handshake;

use entry::Entry;
use std::io::{BufRead, BufReader};

const DEFAULT_BUFF_SIZE: usize = 1024;

fn main() {
	handshake::read_config();
	handshake::register_filter();
	loop {
		match read_line() {
			Ok(entry) => {
				if !entry.is_end_of_message() {
					println!("Debug: {entry:?}");
				} else {
					println!("Debug: end of message: {entry:?}");
				}
			}
			Err(err) => {
				eprintln!("{err}");
			}
		}
	}
}

pub fn read_line() -> Result<Entry, String> {
	let mut buffer = Vec::with_capacity(DEFAULT_BUFF_SIZE);
	let mut stdin = BufReader::new(std::io::stdin());
	if stdin.read_until(b'\n', &mut buffer).unwrap() == 0 {
		crate::eof();
	}
	Entry::from_bytes(&buffer)
}

fn eof() {
	std::process::exit(0x2a)
}
