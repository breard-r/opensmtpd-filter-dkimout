mod entry;
mod handshake;
mod logs;
mod message;
mod stdin_reader;

use entry::Entry;
use message::Message;
use std::collections::HashMap;
use stdin_reader::StdinReader;

const DEFAULT_BUFF_SIZE: usize = 1024;
const DEFAULT_MSG_SIZE: usize = 1024 * 1024;
const LOG_LEVEL_ENV_VAR: &str = "OPENSMTPD_FILTER_DKIMOUT_LOG_LEVEL";

#[macro_export]
macro_rules! display_bytes {
	($bytes: expr) => {
		$bytes
			.iter()
			.map(|b| {
				let v: Vec<u8> = std::ascii::escape_default(*b).collect();
				String::from_utf8_lossy(&v).to_string()
			})
			.collect::<String>()
	};
}

macro_rules! log_messages {
	($list: ident) => {
		log::trace!(
			"message list has {} elements: {}",
			$list.len(),
			$list
				.iter()
				.map(|(k, v)| { format!("{k} ({} lines)", v.nb_lines()) })
				.collect::<Vec<String>>()
				.join(", ")
		)
	};
}

fn main() {
	logs::init_log_system();
	let mut reader = StdinReader::new();
	let mut messages: HashMap<String, Message> = HashMap::new();
	handshake::read_config(&mut reader);
	handshake::register_filter();
	log_messages!(messages);
	loop {
		match Entry::from_bytes(&reader.read_line()) {
			Ok(entry) => {
				let msg_id = entry.get_msg_id();
				match messages.get_mut(&msg_id) {
					Some(msg) => {
						if !entry.is_end_of_message() {
							log::debug!("new line in message: {msg_id}");
							msg.append_line(entry.get_data());
						} else {
							log::debug!("message ready: {msg_id}");
							msg.sign_and_return();
							messages.remove(&msg_id);
							log::debug!("message removed: {msg_id}");
						}
					}
					None => {
						let msg = Message::from_entry(&entry);
						if !entry.is_end_of_message() {
							log::debug!("new message: {msg_id}");
							messages.insert(msg_id, msg);
						} else {
							log::debug!("empty new message: {msg_id}");
							msg.sign_and_return();
						}
					}
				}
			}
			Err(err) => {
				log::error!("invalid filter line: {err}");
			}
		}
		log_messages!(messages);
	}
}
