use clap::Parser;
use std::collections::HashSet;
use std::fs::File;
//use std::io::BufReader;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Config {
	#[arg(short, long)]
	domain: Vec<String>,
	#[arg(short = 'D', long, value_name = "FILE")]
	domain_file: Option<PathBuf>,
	#[arg(short, long, value_name = "FILE")]
	revocation_list: Option<PathBuf>,
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

	pub fn domains(&self) -> &[String] {
		&self.domain
	}
}
