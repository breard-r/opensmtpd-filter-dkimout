use crate::entry::Entry;
use std::io::{BufWriter, Write};

pub const RETURN_SEP: &[u8] = b"|";
pub const RETURN_START: &[u8] = b"filter-dataline|";

#[derive(Debug)]
pub struct Message {
	session_id: String,
	token: String,
	lines: Vec<Vec<u8>>,
}

impl Message {
	pub fn from_entry(entry: &Entry) -> Self {
		let mut ret = Self {
			session_id: entry.get_session_id().to_string(),
			token: entry.get_token().to_string(),
			lines: Vec::new(),
		};
		if !entry.is_end_of_message() {
			ret.append_line(entry.get_data());
		}
		ret
	}

	pub fn append_line(&mut self, line: &[u8]) {
		self.lines.push(line.to_vec())
	}

	pub fn sign_and_return(&self) {
		// TODO: sign the message using DKIM
		for line in &self.lines {
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
