use crate::algorithm::Algorithm;
use crate::canonicalization::Canonicalization;
use clap::Parser;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Config {
	#[arg(short, long, default_value_t = Algorithm::default())]
	algorithm: Algorithm,
	#[arg(short = 'b', long, value_name = "FILE")]
	key_data_base: Option<PathBuf>,
	#[arg(short, long, default_value_t = Canonicalization::default())]
	canonicalization: Canonicalization,
	#[arg(short, long)]
	domain: Vec<String>,
	#[arg(short = 'D', long, value_name = "FILE")]
	domain_file: Option<PathBuf>,
	#[arg(short = 'f', long, value_name = "FILE")]
	revocation_list: Option<PathBuf>,
	#[arg(short, long)]
	header: Vec<String>,
	#[arg(short = 'o', long)]
	header_optional: Vec<String>,
	#[arg(short = 'p', long, default_value_t = NonZeroU64::new(crate::DEFAULT_CNF_CRYPTOPERIOD).unwrap())]
	cryptoperiod: NonZeroU64,
	#[arg(short, long, default_value_t = crate::DEFAULT_CNF_REVOCATION)]
	revocation: u64,
	#[arg(short = 'u', long)]
	dns_update_cmd: String,
	#[arg(short, long, action = clap::ArgAction::Count)]
	verbose: u8,
	#[arg(short = 'x', long, default_value_t = crate::DEFAULT_CNF_EXPIRATION)]
	expiration: u64,
}

impl Config {
	pub fn init() -> Result<Self, String> {
		let mut cnf = Self::parse();
		cnf.key_data_base = process_key_data_base(cnf.key_data_base);
		cnf.domain = process_domains(&cnf.domain, &cnf.domain_file)?;
		cnf.header = process_headers(&cnf.header, crate::DEFAULT_CNF_HEADERS);
		cnf.header_optional = process_headers(&cnf.header_optional, crate::DEFAULT_CNF_HEADERS_OPT);
		Ok(cnf)
	}

	pub fn algorithm(&self) -> Algorithm {
		self.algorithm
	}

	pub fn key_data_base(&self) -> PathBuf {
		self.key_data_base.clone().unwrap()
	}

	pub fn canonicalization(&self) -> Canonicalization {
		self.canonicalization
	}

	pub fn domains(&self) -> &[String] {
		&self.domain
	}

	pub fn revocation_list(&self) -> Option<&Path> {
		match &self.revocation_list {
			Some(p) => Some(p),
			None => None,
		}
	}

	pub fn headers(&self) -> &[String] {
		&self.header
	}

	pub fn headers_optional(&self) -> &[String] {
		&self.header_optional
	}

	pub fn cryptoperiod(&self) -> NonZeroU64 {
		self.cryptoperiod
	}

	pub fn revocation(&self) -> u64 {
		self.revocation
	}

	pub fn dns_update_cmd(&self) -> &str {
		&self.dns_update_cmd
	}

	pub fn verbosity(&self) -> log::LevelFilter {
		crate::logs::log_level(self.verbose)
	}

	pub fn expiration(&self) -> Option<u64> {
		if self.expiration != 0 {
			Some(self.expiration)
		} else {
			None
		}
	}
}

fn process_key_data_base(opt: Option<PathBuf>) -> Option<PathBuf> {
	match opt {
		Some(p) => Some(p),
		None => {
			let mut path = PathBuf::from(crate::DEFAULT_LIB_DIR);
			path.push(crate::DEFAULT_CNF_KEY_DB);
			Some(path)
		}
	}
}

fn process_domains(lst: &[String], domain_file: &Option<PathBuf>) -> Result<Vec<String>, String> {
	let mut domain_set: HashSet<String> = lst.iter().map(|e| e.to_string()).collect();
	if let Some(path) = domain_file {
		let f = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
		for line in BufReader::new(f).lines() {
			let line = line.map_err(|e| format!("{}: {e}", path.display()))?;
			let domain = line.trim();
			if !domain.is_empty() && !domain.starts_with('#') {
				domain_set.insert(domain.to_string().to_lowercase());
			}
		}
	}
	Ok(domain_set.into_iter().collect::<Vec<_>>())
}

fn process_headers(lst: &[String], default: &str) -> Vec<String> {
	let ret = if lst.is_empty() {
		let default_lst = vec![default.to_string()];
		do_process_headers(&default_lst)
	} else {
		do_process_headers(lst)
	};
	ret.into_iter().collect::<Vec<_>>()
}

fn do_process_headers(lst: &[String]) -> HashSet<String> {
	let mut ret = HashSet::with_capacity(128);
	for input in lst {
		for h in input.split(':') {
			ret.insert(h.to_string().to_lowercase());
		}
	}
	ret
}
