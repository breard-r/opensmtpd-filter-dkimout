use std::io::{BufRead, BufReader};

pub struct StdinReader {
	reader: BufReader<std::io::Stdin>,
	buffer: Vec<u8>,
}

impl StdinReader {
	pub fn new() -> Self {
		Self {
			reader: BufReader::new(std::io::stdin()),
			buffer: Vec::with_capacity(crate::DEFAULT_BUFF_SIZE),
		}
	}

	pub fn read_line(&mut self) -> Vec<u8> {
		self.buffer.clear();
		if self.reader.read_until(b'\n', &mut self.buffer).unwrap() == 0 {
			std::process::exit(0)
		}
		self.buffer.clone()
	}
}
