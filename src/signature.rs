use crate::algorithm::Algorithm;
use crate::canonicalization::Canonicalization;
use crate::config::Config;
use crate::parsed_message::{ParsedHeader, ParsedMessage};
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use sha2::{Digest, Sha256};
use sqlx::types::time::OffsetDateTime;
use sqlx::SqlitePool;
use tokio::time::{sleep, Duration};

pub struct Signature {
	algorithm: Algorithm,
	canonicalization: Canonicalization,
	selector: String,
	sdid: String,
	timestamp: i64,
	headers: Vec<String>,
	body_hash: Vec<u8>,
	signature: Vec<u8>,
}

impl Signature {
	pub async fn new(db: &SqlitePool, cnf: &Config, msg: &ParsedMessage<'_>) -> Result<Self> {
		let algorithm = cnf.algorithm();
		let sdid = get_sdid(cnf, msg)?;
		let (selector, signing_key) = get_db_data(db, &sdid, algorithm).await?;
		let mut sig = Self {
			algorithm,
			canonicalization: cnf.canonicalization(),
			selector,
			sdid,
			timestamp: OffsetDateTime::now_utc().unix_timestamp(),
			headers: get_headers(cnf, msg),
			body_hash: Vec::new(),
			signature: Vec::new(),
		};
		sig.compute_body_hash::<Sha256>(msg);
		let header_hash = sig.compute_header_hash::<Sha256>(msg);
		sig.signature = algorithm.sign(&signing_key, &header_hash)?;
		Ok(sig)
	}

	pub fn get_header(&self) -> String {
		format!(
			"DKIM-Signature: v=1; a={algorithm}; c={canonicalization}; d={sdid};\r\n\tt={timestamp}; s={selector};\r\n\th={headers};\r\n\tbh={body_hash};\r\n\tb={signature}",
			algorithm=self.algorithm.display(),
			canonicalization=self.canonicalization.to_string(),
			selector=self.selector,
			sdid=self.sdid,
			timestamp=self.timestamp,
			headers=self.headers.join(":"),
			body_hash=general_purpose::STANDARD.encode(&self.body_hash),
			signature=general_purpose::STANDARD.encode(&self.signature),
		)
	}

	fn compute_body_hash<H: Digest>(&mut self, msg: &ParsedMessage<'_>) {
		let mut hasher = H::new();
		let body = self.canonicalization.process_body(msg.body);
		hasher.update(&body);
		self.body_hash = hasher.finalize().to_vec();
	}

	fn compute_header_hash<H: Digest>(&mut self, msg: &ParsedMessage<'_>) -> Vec<u8> {
		let mut hasher = H::new();
		for header_name in &self.headers {
			if let Some(raw_header) = get_header(msg, header_name) {
				let header = self.canonicalization.process_header(raw_header.raw);
				hasher.update(&header);
			}
		}
		hasher.update(self.get_header().as_bytes());
		hasher.finalize().to_vec()
	}
}

fn get_sdid(cnf: &Config, msg: &ParsedMessage<'_>) -> Result<String> {
	if let Some(header) = get_header(msg, "from") {
		if let Some(arb_pos) = header.value.iter().rposition(|&c| c == b'@') {
			let name = &header.value[arb_pos + 1..];
			let end_pos = name
				.iter()
				.position(|&c| c == b'>')
				.unwrap_or(name.len() - 2);
			if let Ok(sdid) = String::from_utf8(name[..end_pos].to_vec()) {
				if cnf.domains().contains(&sdid) {
					return Ok(sdid);
				} else {
					return Err(anyhow!(
						"unable to sign for a domain outside of the configured list: {sdid}"
					));
				}
			}
		}
	}
	Err(anyhow!("unable to determine the SDID"))
}

fn get_headers(cnf: &Config, msg: &ParsedMessage<'_>) -> Vec<String> {
	let nb_headers = cnf.headers().len() + cnf.headers_optional().len();
	let mut lst = Vec::with_capacity(nb_headers);
	for header_name in cnf.headers() {
		if let Some(name) = get_header_name(msg, header_name) {
			lst.push(name);
		} else {
			lst.push(header_name.to_string());
		}
	}
	for header_name in cnf.headers_optional() {
		if let Some(name) = get_header_name(msg, header_name) {
			lst.push(name);
		}
	}
	lst.sort();
	lst
}

fn get_header_name(msg: &ParsedMessage<'_>, header_name: &str) -> Option<String> {
	match get_header(msg, header_name) {
		Some(header) => String::from_utf8(header.name.to_vec()).ok(),
		None => None,
	}
}

fn get_header<'a>(
	msg: &'a ParsedMessage<'a>,
	header_name: &'a str,
) -> Option<&'a ParsedHeader<'a>> {
	let header_name = header_name.to_lowercase();
	msg.headers
		.iter()
		.find(|&header| header.name_lower == header_name)
}

async fn get_db_data(
	db: &SqlitePool,
	sdid: &str,
	algorithm: Algorithm,
) -> Result<(String, String)> {
	let mut ctn = 0;
	loop {
		let res: Option<(String, String)> = sqlx::query_as(crate::db::SELECT_LATEST_SIGNING_KEY)
			.bind(sdid)
			.bind(algorithm.to_string())
			.fetch_optional(db)
			.await?;
		if let Some((selector, private_key)) = res {
			return Ok((selector, private_key));
		}
		if ctn == crate::SIG_RETRY_NB_RETRY {
			return Err(anyhow!("unable to retrieve key material"));
		}
		ctn += 1;
		sleep(Duration::from_secs(crate::SIG_RETRY_SLEEP_TIME)).await;
	}
}
