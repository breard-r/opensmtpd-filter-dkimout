pub enum CanonicalizationType {
	Relaxed,
	Simple,
}

impl Default for CanonicalizationType {
	fn default() -> Self {
		Self::Relaxed
	}
}

#[derive(Default)]
pub struct Canonicalization {
	header_alg: CanonicalizationType,
	body_alg: CanonicalizationType,
}

impl Canonicalization {
	pub fn set_header_alg(mut self, alg: CanonicalizationType) -> Self {
		self.header_alg = alg;
		self
	}

	pub fn set_body_alg(mut self, alg: CanonicalizationType) -> Self {
		self.body_alg = alg;
		self
	}

	pub fn process_header(&self, header: &[u8]) -> Vec<u8> {
		match self.header_alg {
			CanonicalizationType::Relaxed => header_relaxed(header),
			CanonicalizationType::Simple => header_simple(header),
		}
	}

	pub fn process_body(&self, body: &[u8]) -> Vec<u8> {
		match self.body_alg {
			CanonicalizationType::Relaxed => body_relaxed(body),
			CanonicalizationType::Simple => body_simple(body),
		}
	}
}

fn to_lowercase(c: &mut u8) {
	if *c >= b'A' && *c <= b'Z' {
		*c += 32
	}
}

fn to_space(c: &mut u8) {
	if *c == b'\t' {
		*c = b' '
	}
}

fn header_relaxed(data: &[u8]) -> Vec<u8> {
	let mut data = data.to_vec();

	// Step 1: Convert all header field names (not the header field values) to
	// lowercase. For example, convert "SUBJect: AbC" to "subject: AbC".
	if let Some(index) = data.iter().position(|&e| e == b':') {
		data[..index].iter_mut().for_each(to_lowercase);
	}

	// Step 2: Unfold all header field continuation lines as described in
	// RFC5322; in particular, lines with terminators embedded in
	// continued header field values (that is, CRLF sequences followed by
	// WSP) MUST be interpreted without the CRLF. Implementations MUST
	// NOT remove the CRLF at the end of the header field value.
	loop {
		let last_pos = data.len() - 2;
		match data.windows(2).position(|w| w == b"\r\n") {
			Some(pos) => {
				if pos == last_pos {
					break;
				}
				data.remove(pos + 1);
				data.remove(pos);
			}
			None => {
				break;
			}
		}
	}

	// Step 3: Convert all sequences of one or more WSP characters to a single SP
	// character. WSP characters here include those before and after a
	// line folding boundary.
	data.iter_mut().for_each(to_space);
	while let Some(pos) = data.windows(2).position(|w| w == b"  ") {
		data.remove(pos);
	}

	// Step 4: Delete the SP character, if present, at the end of each unfolded
	// header field value before its final CRLF.
	//
	// Note: this if from errata 5839
	loop {
		let pos = data.len() - 3;
		if data[pos] != b' ' {
			break;
		}
		data.remove(pos);
	}

	// Step 5: Delete any WSP characters remaining before and after the colon
	// separating the header field name from the header field value. The
	// colon separator MUST be retained.
	while let Some(pos) = data.iter().position(|&e| e == b':') {
		if data[pos + 1] == b' ' {
			data.remove(pos + 1);
		} else if data[pos - 1] == b' ' {
			data.remove(pos - 1);
		} else {
			break;
		}
	}

	data
}

fn header_simple(data: &[u8]) -> Vec<u8> {
	data.to_vec()
}

fn body_relaxed(data: &[u8]) -> Vec<u8> {
	let mut data = data.to_vec();

	// Ignore all whitespace at the end of lines.
	while let Some(pos) = data
		.windows(3)
		.position(|w| w == b" \r\n" || w == b"\t\r\n")
	{
		data.remove(pos);
	}

	// Reduce all sequences of WSP within a line to a single SP character.
	while let Some(pos) = data
		.windows(2)
		.position(|w| (w[0] == b' ' || w[0] == b'\t') && (w[1] == b' ' || w[1] == b'\t'))
	{
		data[pos] = b' ';
		data.remove(pos + 1);
	}

	// Ignore all empty lines at the end of the message body.
	while data.ends_with(b"\r\n\r\n") {
		let pos = data.len();
		data.remove(pos - 1);
		data.remove(pos - 2);
	}

	data
}

fn body_simple(data: &[u8]) -> Vec<u8> {
	let mut data = data.to_vec();

	// Ignore all empty lines at the end of the message body.
	while data.ends_with(b"\r\n\r\n") {
		let pos = data.len();
		data.remove(pos - 1);
		data.remove(pos - 2);
	}

	data
}

#[cfg(test)]
mod tests {
	use super::*;

	const HEADER_00: &[u8] = b"Accept-Language:\r\n";
	const HEADER_01: &[u8] = b"Accept-Language: fr-FR, en-US\r\n";
	const HEADER_02: &[u8] = b"accept-language: fr-FR, en-US\r\n";
	const HEADER_03: &[u8] = b"AcCePt-LaNgUaGe: fr-FR, en-US\r\n";
	const HEADER_04: &[u8] = b"Accept-Language:fr-FR, en-US\r\n";
	const HEADER_05: &[u8] = b"Accept-Language	  :			 fr-FR,   en-US		\r\n";
	const HEADER_06: &[u8] = b"Accept-Language: fr-FR,\r\n  en-US,\r\n de-DE\r\n";
	const HEADER_07: &[u8] = b"Accept-Language: fr-FR,\r\nen-US\r\n\r\n";
	const BODY_00: &[u8] = b"\r\n";
	const BODY_01: &[u8] = b"Hello, World!\r\n";
	const BODY_02: &[u8] = b"Hello,  World \t!\r\n\r\n\r\ntest \r\nbis\r\n\r\n";

	#[test]
	fn header_relaxed_01() {
		let c = Canonicalization::default().set_header_alg(CanonicalizationType::Relaxed);
		assert_eq!(
			&c.process_header(HEADER_01),
			b"accept-language:fr-FR, en-US\r\n"
		);
	}

	#[test]
	fn header_relaxed_02() {
		let c = Canonicalization::default().set_header_alg(CanonicalizationType::Relaxed);
		assert_eq!(
			&c.process_header(HEADER_02),
			b"accept-language:fr-FR, en-US\r\n"
		);
	}

	#[test]
	fn header_relaxed_03() {
		let c = Canonicalization::default().set_header_alg(CanonicalizationType::Relaxed);
		assert_eq!(
			&c.process_header(HEADER_03),
			b"accept-language:fr-FR, en-US\r\n"
		);
	}

	#[test]
	fn header_relaxed_04() {
		let c = Canonicalization::default().set_header_alg(CanonicalizationType::Relaxed);
		assert_eq!(
			&c.process_header(HEADER_04),
			b"accept-language:fr-FR, en-US\r\n"
		);
	}

	#[test]
	fn header_relaxed_05() {
		let c = Canonicalization::default().set_header_alg(CanonicalizationType::Relaxed);
		assert_eq!(
			&c.process_header(HEADER_05),
			b"accept-language:fr-FR, en-US\r\n"
		);
	}

	#[test]
	fn header_relaxed_06() {
		let c = Canonicalization::default().set_header_alg(CanonicalizationType::Relaxed);
		assert_eq!(
			&c.process_header(HEADER_06),
			b"accept-language:fr-FR, en-US, de-DE\r\n"
		);
	}

	#[test]
	fn header_relaxed_07() {
		let c = Canonicalization::default().set_header_alg(CanonicalizationType::Relaxed);
		assert_eq!(
			&c.process_header(HEADER_07),
			b"accept-language:fr-FR,en-US\r\n"
		);
	}

	#[test]
	fn header_simple_00() {
		let c = Canonicalization::default().set_header_alg(CanonicalizationType::Simple);
		assert_eq!(&c.process_header(HEADER_00), HEADER_00);
	}

	#[test]
	fn header_simple_01() {
		let c = Canonicalization::default().set_header_alg(CanonicalizationType::Simple);
		assert_eq!(&c.process_header(HEADER_01), HEADER_01);
	}

	#[test]
	fn header_simple_02() {
		let c = Canonicalization::default().set_header_alg(CanonicalizationType::Simple);
		assert_eq!(&c.process_header(HEADER_02), HEADER_02);
	}

	#[test]
	fn header_simple_03() {
		let c = Canonicalization::default().set_header_alg(CanonicalizationType::Simple);
		assert_eq!(&c.process_header(HEADER_03), HEADER_03);
	}

	#[test]
	fn header_simple_04() {
		let c = Canonicalization::default().set_header_alg(CanonicalizationType::Simple);
		assert_eq!(&c.process_header(HEADER_04), HEADER_04);
	}

	#[test]
	fn header_simple_05() {
		let c = Canonicalization::default().set_header_alg(CanonicalizationType::Simple);
		assert_eq!(&c.process_header(HEADER_05), HEADER_05);
	}

	#[test]
	fn header_simple_06() {
		let c = Canonicalization::default().set_header_alg(CanonicalizationType::Simple);
		assert_eq!(&c.process_header(HEADER_06), HEADER_06);
	}

	#[test]
	fn header_simple_07() {
		let c = Canonicalization::default().set_header_alg(CanonicalizationType::Simple);
		assert_eq!(&c.process_header(HEADER_07), HEADER_07);
	}

	#[test]
	fn body_simple_00() {
		let c = Canonicalization::default().set_body_alg(CanonicalizationType::Simple);
		assert_eq!(&c.process_body(BODY_00), BODY_00);
	}

	#[test]
	fn body_simple_01() {
		let c = Canonicalization::default().set_body_alg(CanonicalizationType::Simple);
		assert_eq!(&c.process_body(BODY_01), BODY_01);
	}

	#[test]
	fn body_simple_02() {
		let c = Canonicalization::default().set_body_alg(CanonicalizationType::Simple);
		assert_eq!(
			&c.process_body(BODY_02),
			b"Hello,  World \t!\r\n\r\n\r\ntest \r\nbis\r\n"
		);
	}

	#[test]
	fn body_relaxed_00() {
		let c = Canonicalization::default().set_body_alg(CanonicalizationType::Relaxed);
		assert_eq!(&c.process_body(BODY_00), BODY_00);
	}

	#[test]
	fn body_relaxed_01() {
		let c = Canonicalization::default().set_body_alg(CanonicalizationType::Relaxed);
		assert_eq!(&c.process_body(BODY_01), BODY_01);
	}

	#[test]
	fn body_relaxed_02() {
		let c = Canonicalization::default().set_body_alg(CanonicalizationType::Relaxed);
		assert_eq!(
			&c.process_body(BODY_02),
			b"Hello, World !\r\n\r\n\r\ntest\r\nbis\r\n"
		);
	}
}
