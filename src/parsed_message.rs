pub struct ParsedMessage<'a> {
	pub headers: Vec<ParsedHeader<'a>>,
	pub body: &'a [u8],
}

impl<'a> ParsedMessage<'a> {
	pub fn from_bytes(data: &'a [u8]) -> Result<Self, ()> {
		let (mut raw_headers, body) = match data.windows(4).position(|w| w == b"\r\n\r\n") {
			Some(body_index) => (&data[..body_index + 2], &data[body_index + 4..]),
			None => return Err(()),
		};
		let mut headers = Vec::with_capacity(128);
		while !raw_headers.is_empty() {
			let end_index = header_end_pos(raw_headers)?;
			let h = ParsedHeader::from_bytes(&raw_headers[..end_index])?;
			headers.push(h);
			raw_headers = &raw_headers[end_index..];
		}
		headers.shrink_to_fit();
		Ok(Self { headers, body })
	}
}

fn is_wsp(c: u8) -> bool {
	c == b' ' || c == b'\t'
}

fn header_end_pos(data: &[u8]) -> Result<usize, ()> {
	let mut ret = 0;
	let max_len = data.len();
	loop {
		ret += data[ret..]
			.windows(2)
			.position(|w| w == b"\r\n")
			.ok_or(())? + 2;
		if ret == max_len {
			return Ok(ret);
		}
		if !is_wsp(data[ret]) {
			return Ok(ret);
		}
	}
}

pub struct ParsedHeader<'a> {
	pub name: &'a [u8],
	pub name_lower: String,
	pub value: &'a [u8],
	pub raw: &'a [u8],
}

impl<'a> ParsedHeader<'a> {
	fn from_bytes(data: &'a [u8]) -> Result<Self, ()> {
		let colon_pos = data.iter().position(|&w| w == b':').ok_or(())?;
		let name = &data[..colon_pos];
		let value = &data[colon_pos + 1..];
		Ok(Self {
			name,
			name_lower: String::from_utf8(name.to_vec())
				.map_err(|_| ())?
				.to_lowercase(),
			value,
			raw: data,
		})
	}
}
