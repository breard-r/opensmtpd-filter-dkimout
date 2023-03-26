use crate::algorithm::Algorithm;
use crate::canonicalization::Canonicalization;
use clap::Parser;
use std::collections::HashSet;
use std::fs::File;
//use std::io::BufReader;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Config {
	#[arg(short, long, default_value_t = Algorithm::default())]
	algorithm: Algorithm,
	#[arg(short, long, default_value_t = Canonicalization::default())]
	canonicalization: Canonicalization,
	#[arg(short, long)]
	domain: Vec<String>,
	#[arg(short = 'D', long, value_name = "FILE")]
	domain_file: Option<PathBuf>,
	#[arg(short, long, value_name = "FILE")]
	revocation_list: Option<PathBuf>,
	#[arg(short = 'x', long, default_value_t = 1296000)]
	expiration: u64,
}

impl Config {
	pub fn init() -> Result<Self, String> {
		let mut cnf = Self::parse();
		let mut domain_set: HashSet<String> = cnf.domain.into_iter().collect();
		if let Some(path) = &cnf.domain_file {
			let f = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
			for line in BufReader::new(f).lines() {
				let line = line.map_err(|e| format!("{}: {e}", path.display()))?;
				let domain = line.trim();
				if !domain.is_empty() && !domain.starts_with('#') {
					domain_set.insert(domain.to_string());
				}
			}
		}
		cnf.domain = domain_set.into_iter().collect::<Vec<_>>();
		Ok(cnf)
	}

	pub fn algorithm(&self) -> Algorithm {
		self.algorithm
	}

	pub fn canonicalization(&self) -> Canonicalization {
		self.canonicalization
	}

	pub fn domains(&self) -> &[String] {
		&self.domain
	}

	pub fn expiration(&self) -> Option<u64> {
		if self.expiration != 0 {
			Some(self.expiration)
		} else {
			None
		}
	}
}