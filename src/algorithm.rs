use std::str::FromStr;

#[derive(Clone, Copy, Debug)]
pub enum Algorithm {
	Ed25519Sha256,
	Rsa2048Sha256,
	Rsa3072Sha256,
	Rsa4096Sha256,
}

impl Algorithm {
	pub fn display(&self) -> String {
		match self {
			Self::Ed25519Sha256 => String::from("ed25519-sha256"),
			Self::Rsa2048Sha256 | Self::Rsa3072Sha256 | Self::Rsa4096Sha256 => {
				String::from("rsa-sha256")
			}
		}
	}
}

impl Default for Algorithm {
	fn default() -> Self {
		Self::Rsa2048Sha256
	}
}

impl ToString for Algorithm {
	fn to_string(&self) -> String {
		match self {
			Self::Ed25519Sha256 => String::from("ed25519-sha256"),
			Self::Rsa2048Sha256 => String::from("rsa2048-sha256"),
			Self::Rsa3072Sha256 => String::from("rsa3072-sha256"),
			Self::Rsa4096Sha256 => String::from("rsa4096-sha256"),
		}
	}
}

impl FromStr for Algorithm {
	type Err = String;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s.to_lowercase().as_str() {
			"ed25519-sha256" => Ok(Self::Ed25519Sha256),
			"rsa2048-sha256" => Ok(Self::Rsa2048Sha256),
			"rsa3072-sha256" => Ok(Self::Rsa3072Sha256),
			"rsa4096-sha256" => Ok(Self::Rsa4096Sha256),
			_ => Err(format!("{s}: invalid signing algorithm")),
		}
	}
}
