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
	expiration: Option<u64>,
	headers: Vec<String>,
	body_hash: Vec<u8>,
	signature: Vec<u8>,
}

impl Signature {
	pub async fn new(db: &SqlitePool, cnf: &Config, msg: &ParsedMessage<'_>) -> Result<Self> {
		let algorithm = cnf.algorithm();
		let sdid = get_sdid(cnf, msg)?;
		let (selector, signing_key) = get_db_data(db, &sdid, algorithm).await?;
		let timestamp = OffsetDateTime::now_utc().unix_timestamp();
		let expiration = cnf.expiration().map(|x| x + timestamp as u64);
		let mut sig = Self {
			algorithm,
			canonicalization: cnf.canonicalization(),
			selector,
			sdid,
			timestamp,
			expiration,
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
		let expiration = self
			.expiration
			.map(|x| format!(" x={x};"))
			.unwrap_or(String::new());
		format!(
			"DKIM-Signature: v=1; a={algorithm}; k={key_type}; c={canonicalization};\r\n\tt={timestamp};{expiration}\r\n\td={sdid};\r\n\ts={selector};\r\n\th={headers};\r\n\tbh={body_hash};\r\n\tb={signature}",
			algorithm=self.algorithm.display(),
			key_type=self.algorithm.key_type(),
			canonicalization=self.canonicalization.to_string(),
			selector=self.selector,
			sdid=self.sdid,
			timestamp=self.timestamp,
			expiration=expiration,
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
		let dkim_header = format!("{}\r\n", self.get_header());
		let mut dkim_header = self.canonicalization.process_header(dkim_header.as_bytes());
		dkim_header.pop();
		dkim_header.pop();
		hasher.update(dkim_header);
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

#[cfg(test)]
mod tests {
	use super::*;

	const KEY_ED25519: &str = "Av46g0s6+qCczlLeIkSmD/yD7GX5pDjl8SVTSeVZIhc=";
	const KEY_RSA2048: &str = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDDYGEHGABdLxLbvqiuaGdYV9ndsFzdO31AaZoSfCVF0TVPeJ5B/YWyUzc6YIr7qFyfA4tiRPu3/Fy2vzYzG2lcYBkSzJsQWkiOWv6C3CpxYX2tBrAKnJx3ADyr9P3whztyKQBbSNLy+CCNJQ5967Z+PCOeiFAX4XvfCFMpwxsUo6Pv2SYi9PwOq8HwzUQHyy39zOs68XIUF85DCXiQ1kztXzu8HX8nuLX7AnLrf0ZiFGrbSbUjj/F7XVPh2QJxcBLZjrnpve73nrrYsIVnbCvfV563CuFq0PvsUofW7Ckbpwdx26AD59ssaOBNp/uK04xqPSQZyADEngcfkOBdqeHlAgMBAAECggEAYqZQd6d7z5FMQV5Uh7O5staw8Anz6dT22kY4AGtk2orXEyiBKCrdjfwMn9JNeuI42iWNBHJ2cyDeo3uK32VQ3s66+k4LYcdkaVSyu9p1J8ilD2+YBdOsAT5CZEUQz5lIv8zKHE16DiqRLRNv7M7O15CAH7UOU/CLfkMS0rxr+Q//dw94mUTXSy+XKwWgdQSxjiqcfEFEArtP4QH+BM2j7Jk+cMm4OlOklOLlcktSgrCSGp4uqt9BYTq86XFSVaZHbirKAheO7mv9xSXj46zenWaSwWDJ/zYSQHUzTwdCcm35gHeGvUvBo/njCzfvNM6xWl+vrMzD9i4pB0PZ6yi0IQKBgQD/97QWjwdCt7ubRv453lLZ2CXDNt/QFKOr+ESlDPkCxmb/DIY8HDqbJpdyPrCm6MHL8lUBLNixSUfkrCFFaGgpHyG6E5qJT0/UVVwSWUAWciOY7SOZXMPgvkahU39GzPDE8m+mihyDPT98vUqX4HTZJzannaSESGeVtADYXN416QKBgQDDZrYuD4bzjft7XNmmbdl52sfCcKgduzmooSMjeIKffSZuCvpVBA0kEgqLalLaMSCjcx95djufqDkU+RBT7lAbZDYd+lD4m4dNzGqy1hgTVfBaPOYCg4iC2WKiHZDIw8n630gFyRZDAn+KINbcSn7V2ZxqDa1ZE6wAWgiBn98CnQKBgQDSmFnytXqjycbw2lgQBHrmAJARLPS3nkOLGZhgs2usfNAAx60ph5AwVnAD7tAogxfvVFHbxaoDMueTnItDL8ODEboN/lMG5dooOJKoBgZUcVQYXgMMCuad4e76jFgLSFJPt6dkvfz3fUzetF7K1kFM6JZvEaRpsaiH4rFPUhkBAQKBgHwXepL94WJDRPYvHToIgRhVzI67JMjc4d0pmDsqiSnoPMOdzSS4ke/aVT/8oelXUbb7oX1tjKf0GWwsUCY9Ljp3Bbc8BLgdbWwG6avxMxD0ftOP4TKvfb47d9wkkpItZNQhgIfMEIs1xvFdsZXs6We97wua6/+p8o22n7hSYzoxAoGBAM9zQgkeV2U++yi4memcNX1sLnRHaBUSShj+IXhOM8Hpw5deyxFKUh2sD537CJxKOx+8XMKvWilY2MFRCZIlTAQBasEfj9+YZSLY7kFHfWKcUKhqVQ+5M+LgbuZjf6X/0Y+2Lqc585NoxmMDc4GC/1t4eagXqMvcuh10S2JP9RWp";
	const MSG_01_RAW: &[u8] = include_bytes!("../test_samples/single_message_raw.txt");
	const MSG_01_HEADERS: &[&str] = &[
		"Date",
		"From",
		"Resent-Date",
		"Subject",
		"To",
		"cc",
		"reply-to",
	];

	#[test]
	fn test_simple_simple() {
		let ref_sig_header = "DKIM-Signature: v=1; a=ed25519-sha256; k=ed25519; c=simple/simple;\r\n\tt=1681595158;\r\n\td=example.org;\r\n\ts=dkim-b3fb546a27bb44dd88a1fd2b4b3e2e96;\r\n\th=Date:From:Resent-Date:Subject:To:cc:reply-to;\r\n\tbh=z85OKVJZHnmg3qFlSpLbpPCZ00irfBdrzQUtabiSl3A=;\r\n\tb=854DPGA77UnhEagQIK+x/PLz/YEzoxZO2PDDk6ojASwhUqcuSkOdy9XiuTsQSgpaSQwjui3OuYm9VG6/j3G+AQ==";
		let msg = ParsedMessage::from_bytes(MSG_01_RAW).unwrap();
		let mut sig = Signature {
			algorithm: Algorithm::Ed25519Sha256,
			canonicalization: "simple/simple".parse().unwrap(),
			selector: "dkim-b3fb546a27bb44dd88a1fd2b4b3e2e96".into(),
			sdid: "example.org".into(),
			timestamp: 1681595158,
			expiration: None,
			headers: MSG_01_HEADERS.iter().map(|h| h.to_string()).collect(),
			body_hash: Vec::new(),
			signature: Vec::new(),
		};
		sig.compute_body_hash::<Sha256>(&msg);
		let header_hash = sig.compute_header_hash::<Sha256>(&msg);
		sig.signature = sig.algorithm.sign(KEY_ED25519, &header_hash).unwrap();
		assert_eq!(sig.get_header(), ref_sig_header);
	}

	#[test]
	fn test_relaxed_relaxed() {
		let ref_sig_header = "DKIM-Signature: v=1; a=rsa-sha256; k=rsa; c=relaxed/relaxed;\r\n\tt=1681593844; x=1682889844;\r\n\td=example.org;\r\n\ts=dkim-681d955d9fc84d978d71a7d7f8ce7dd6;\r\n\th=Date:From:Resent-Date:Subject:To:cc:reply-to;\r\n\tbh=z85OKVJZHnmg3qFlSpLbpPCZ00irfBdrzQUtabiSl3A=;\r\n\tb=o83MyMVH6fz4lhGG5za33rmE/D8RJLezFw9Jqds2l6Pt9uDUZCHbh6YjWJjBBbaKJBlrGWGyKBe4x5ns84oHjGyehd8mbyJc9mu1HjJZQVH7bZPPb0N0gt9tl+7hz9S5GvPE6hE4c3VxynhV/KxoJXa6tdM8JUlTKhcaZyacl1kFcgUlFriyMcID9451evmlmEJ8hiGnxqpXdThxVluKNqV9jYlLAlH4/eIqKWh9RkAqeQufTd8jbfokoF7KDCYRaM+y7uoi3Ir6KKt3NuwrYYv6lmhkzuhF4/4+o6CeNtCQ4boAlVBiGFBX5MDKeHg410yfQZqHm/2mlV9pNU+H4g==";
		let msg = ParsedMessage::from_bytes(MSG_01_RAW).unwrap();
		let mut sig = Signature {
			algorithm: Algorithm::Rsa2048Sha256,
			canonicalization: "relaxed/relaxed".parse().unwrap(),
			selector: "dkim-681d955d9fc84d978d71a7d7f8ce7dd6".into(),
			sdid: "example.org".into(),
			timestamp: 1681593844,
			expiration: Some(1682889844),
			headers: MSG_01_HEADERS.iter().map(|h| h.to_string()).collect(),
			body_hash: Vec::new(),
			signature: Vec::new(),
		};
		sig.compute_body_hash::<Sha256>(&msg);
		let header_hash = sig.compute_header_hash::<Sha256>(&msg);
		sig.signature = sig.algorithm.sign(KEY_RSA2048, &header_hash).unwrap();
		assert_eq!(sig.get_header(), ref_sig_header);
	}
}
