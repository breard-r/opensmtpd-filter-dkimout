use crate::display_bytes;
use tokio::io::{AsyncBufReadExt, BufReader};

pub struct StdinReader {
	reader: BufReader<tokio::io::Stdin>,
	buffer: Vec<u8>,
}

impl StdinReader {
	pub fn new() -> Self {
		Self {
			reader: BufReader::new(tokio::io::stdin()),
			buffer: Vec::with_capacity(crate::DEFAULT_BUFF_SIZE),
		}
	}

	pub async fn read_line(&mut self) -> Vec<u8> {
		self.buffer.clear();
		log::trace!("reading line from stdin");
		if self
			.reader
			.read_until(b'\n', &mut self.buffer)
			.await
			.unwrap() == 0
		{
			std::process::exit(0)
		}
		log::trace!("line read from stdin: {}", display_bytes!(self.buffer));
		self.buffer.clone()
	}
}
