mod entry;
mod handshake;
mod message;
mod stdin_reader;

use entry::Entry;
use message::Message;
use std::collections::HashMap;
use stdin_reader::StdinReader;

const DEFAULT_BUFF_SIZE: usize = 1024;

fn main() {
	let mut reader = StdinReader::new();
	let mut messages: HashMap<String, Message> = HashMap::new();
	handshake::read_config(&mut reader);
	handshake::register_filter();
	loop {
		match Entry::from_bytes(&reader.read_line()) {
			Ok(entry) => {
				let msg_id = entry.get_msg_id();
				match messages.get_mut(&msg_id) {
					Some(msg) => {
						if !entry.is_end_of_message() {
							msg.append_line(entry.get_data());
						} else {
							msg.sign_and_return();
							messages.remove(&msg_id);
						}
					}
					None => {
						if !entry.is_end_of_message() {
							let msg = Message::from_line(entry.get_data());
							messages.insert(msg_id, msg);
						} else {
							let msg = Message::new();
							msg.sign_and_return();
						}
					}
				}
			}
			Err(err) => {
				eprintln!("{err}");
			}
		}
	}
}
