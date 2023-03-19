use nom::bytes::streaming::{tag, take_till1, take_while1};
use nom::IResult;

#[derive(Debug)]
pub struct Entry {
	session_id: String,
	token: String,
	data: Vec<u8>,
}

impl Entry {
	pub fn get_session_id(&self) -> &str {
		&self.session_id
	}

	pub fn get_token(&self) -> &str {
		&self.token
	}

	pub fn get_data(&self) -> &[u8] {
		&self.data
	}

	pub fn is_end_of_message(&self) -> bool {
		self.data == vec![b'.']
	}

	pub fn from_bytes(input: &[u8]) -> Result<Entry, String> {
		let (_, entry) = parse_entry(input).map_err(|e| format!("parsing error: {e}"))?;
		Ok(entry)
	}
}

fn is_eol(c: u8) -> bool {
	c == b'\n'
}

fn is_body_char(c: u8) -> bool {
	!(c as char).is_control()
}

fn is_parameter_char(c: u8) -> bool {
	is_body_char(c) && (c as char) != '|'
}

fn parse_string_parameter(input: &[u8]) -> IResult<&[u8], String> {
	let (input, s) = take_while1(is_parameter_char)(input)?;
	Ok((input, String::from_utf8(s.to_vec()).unwrap()))
}

fn parse_delimiter(input: &[u8]) -> IResult<&[u8], &[u8]> {
	tag("|")(input)
}

fn parse_data(input: &[u8]) -> IResult<&[u8], Vec<u8>> {
	let (input, s) = take_till1(is_eol)(input)?;
	Ok((input, s.to_vec()))
}

fn parse_entry(input: &[u8]) -> IResult<&[u8], Entry> {
	let (input, _type) = tag("filter")(input)?;
	let (input, _) = parse_delimiter(input)?;
	let (input, _version) = parse_string_parameter(input)?;
	let (input, _) = parse_delimiter(input)?;
	let (input, _timestamp) = parse_string_parameter(input)?;
	let (input, _) = parse_delimiter(input)?;
	let (input, _subsystem) = tag("smtp-in")(input)?;
	let (input, _) = parse_delimiter(input)?;
	let (input, _phase) = tag("data-line")(input)?;
	let (input, _) = parse_delimiter(input)?;
	let (input, session_id) = parse_string_parameter(input)?;
	let (input, _) = parse_delimiter(input)?;
	let (input, token) = parse_string_parameter(input)?;
	let (input, _) = parse_delimiter(input)?;
	let (input, data) = parse_data(input)?;
	let entry = Entry {
		session_id,
		token,
		data,
	};
	Ok((input, entry))
}
