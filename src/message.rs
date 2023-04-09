use crate::config::Config;
use crate::entry::Entry;
use crate::parsed_message::ParsedMessage;
use tokio::io::{AsyncWriteExt, BufWriter};

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

	pub async fn sign_and_return(&self, cnf: &Config) -> String {
		log::trace!("content: {}", crate::display_bytes!(&self.content));
		match ParsedMessage::from_bytes(&self.content) {
			Ok(parsed_msg) => {
				log::trace!("mail parsed");
				for h in &parsed_msg.headers {
					log::trace!(
						"ParsedMessage: header: raw: {}",
						crate::display_bytes!(h.raw)
					);
					log::trace!(
						"ParsedMessage: header: name: {}",
						crate::display_bytes!(h.name)
					);
					log::trace!(
						"ParsedMessage: header: value: {}",
						crate::display_bytes!(h.value)
					);
				}
				log::trace!(
					"ParsedMessage: body: {}",
					crate::display_bytes!(parsed_msg.body)
				);
				// TODO: sign the message using DKIM
			}
			Err(_) => {
				log::error!("{}: unable to parse message", self.session_id);
			}
		}
		self.print_msg().await;
		get_msg_id(&self.session_id, &self.token)
	}

	async fn print_msg(&self) {
		let i = self.content.len() - 1;
		for line in self.content[0..i].split(|&b| b == b'\n') {
			self.print_line(line).await;
		}
		self.print_line(b".").await;
	}

	async fn print_line(&self, line: &[u8]) {
		let mut stdout = BufWriter::new(tokio::io::stdout());
		stdout.write_all(RETURN_START).await.unwrap();
		stdout.write_all(self.session_id.as_bytes()).await.unwrap();
		stdout.write_all(RETURN_SEP).await.unwrap();
		stdout.write_all(self.token.as_bytes()).await.unwrap();
		stdout.write_all(RETURN_SEP).await.unwrap();
		stdout.write_all(line).await.unwrap();
		stdout.write_all(b"\n").await.unwrap();
		stdout.flush().await.unwrap();
	}
}

pub fn get_msg_id(session_id: &str, token: &str) -> String {
	format!("{session_id}.{token}")
}
