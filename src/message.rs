#[derive(Debug)]
pub struct Message {
	lines: Vec<Vec<u8>>,
}

impl Message {
	pub fn new() -> Self {
		Self { lines: Vec::new() }
	}

	pub fn from_line(line: &[u8]) -> Self {
		Self {
			lines: vec![line.to_vec()],
		}
	}

	pub fn append_line(&mut self, line: &[u8]) {
		self.lines.push(line.to_vec())
	}

	pub fn sign_and_return(&self) {
		// TODO: sign the message using DKIM and send it to stdout
	}
}
