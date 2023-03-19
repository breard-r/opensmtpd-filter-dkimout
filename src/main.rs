mod entry;
mod handshake;
mod stdin_reader;

use entry::Entry;
use stdin_reader::StdinReader;

const DEFAULT_BUFF_SIZE: usize = 1024;

fn main() {
	let mut reader = StdinReader::new();
	handshake::read_config(&mut reader);
	handshake::register_filter();
	loop {
		match Entry::from_bytes(&reader.read_line()) {
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
