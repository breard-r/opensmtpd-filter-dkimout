use crate::entry::Entry;
use mailparse::parse_mail;
use std::io::{BufWriter, Write};

pub const RETURN_SEP: &[u8] = b"|";
pub const RETURN_START: &[u8] = b"filter-dataline|";

#[derive(Debug)]
pub struct Message {
	session_id: String,
	token: String,
	content: Vec<u8>,
	nb_lines: usize,
}

impl Message {
	pub fn from_entry(entry: &Entry) -> Self {
		let mut ret = Self {
			session_id: entry.get_session_id().to_string(),
			token: entry.get_token().to_string(),
			content: Vec::with_capacity(crate::DEFAULT_MSG_SIZE),
			nb_lines: 0,
		};
		if !entry.is_end_of_message() {
			ret.append_line(entry.get_data());
		}
		ret
	}

	pub fn append_line(&mut self, line: &[u8]) {
		self.nb_lines += 1;
		if self.content.len() + line.len() > self.content.capacity() {
			self.content.reserve(crate::DEFAULT_MSG_SIZE);
		}
		self.content.extend_from_slice(line);
		match line.last() {
			Some(&c) => {
				if c != b'\r' {
					self.content.push(b'\r');
				}
			}
			None => {
				self.content.push(b'\r');
			}
		}
		self.content.push(b'\n');
	}

	pub fn nb_lines(&self) -> usize {
		self.nb_lines
	}

	pub fn sign_and_return(&self) {
		log::trace!("content:\n{}", crate::display_bytes!(&self.content));
		match parse_mail(&self.content) {
			Ok(parsed_msg) => {
				log::trace!("mail parsed");
				for h in parsed_msg.get_headers() {
					log::trace!("{:?}", h);
				}
				match self.get_body() {
					Some(body) => {
						log::trace!("MailBody:\n{}", crate::display_bytes!(body));
						// TODO: sign the message using DKIM
					}
					None => {
						log::error!("{}: unable to find the body", self.session_id);
					}
				}
			}
			Err(e) => {
				log::error!("{}: unable to parse message: {e}", self.session_id);
			}
		};
		self.print_msg();
	}

	fn get_body(&self) -> Option<&[u8]> {
		match self.content.windows(4).position(|w| w == b"\r\n\r\n") {
			Some(body_index) => Some(&self.content[body_index + 4..]),
			None => None,
		}
	}

	fn print_msg(&self) {
		let i = self.content.len() - 1;
		for line in self.content[0..i].split(|&b| b == b'\n') {
			self.print_line(line);
		}
		self.print_line(b".");
	}

	fn print_line(&self, line: &[u8]) {
		let mut stdout = BufWriter::new(std::io::stdout());
		stdout.write_all(RETURN_START).unwrap();
		stdout.write_all(self.session_id.as_bytes()).unwrap();
		stdout.write_all(RETURN_SEP).unwrap();
		stdout.write_all(self.token.as_bytes()).unwrap();
		stdout.write_all(RETURN_SEP).unwrap();
		stdout.write_all(line).unwrap();
		stdout.write_all(b"\n").unwrap();
	}
}
