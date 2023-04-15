use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::ed25519::SignatureEncoding;
use ed25519_dalek::{Signer, SigningKey as Ed25519SigningKey};
use rand::thread_rng;
use rsa::pkcs1v15::SigningKey as RsaSigningKey;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use rsa::sha2::Sha256;
use rsa::signature::hazmat::PrehashSigner;
use rsa::{RsaPrivateKey, RsaPublicKey};
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

	pub fn key_type(&self) -> String {
		match self {
			Self::Ed25519Sha256 => String::from("ed25519"),
			Self::Rsa2048Sha256 | Self::Rsa3072Sha256 | Self::Rsa4096Sha256 => String::from("rsa"),
		}
	}

	pub fn gen_keys(&self) -> (String, String) {
		match self {
			Self::Ed25519Sha256 => gen_ed25519_kp(),
			Self::Rsa2048Sha256 => gen_rsa_kp(2048),
			Self::Rsa3072Sha256 => gen_rsa_kp(3072),
			Self::Rsa4096Sha256 => gen_rsa_kp(4096),
		}
	}

	pub fn sign(&self, encoded_pk: &str, data: &[u8]) -> Result<Vec<u8>> {
		let pk = general_purpose::STANDARD.decode(encoded_pk)?;
		match self {
			Self::Ed25519Sha256 => {
				let signing_key = Ed25519SigningKey::from_bytes(pk.as_slice().try_into()?);
				let signature = signing_key.try_sign(data)?;
				Ok(signature.to_vec())
			}
			Self::Rsa2048Sha256 | Self::Rsa3072Sha256 | Self::Rsa4096Sha256 => {
				let private_key = RsaPrivateKey::from_pkcs8_der(&pk)?;
				let signing_key = RsaSigningKey::<Sha256>::new_with_prefix(private_key);
				let signature = signing_key.sign_prehash(data)?;
				Ok(signature.to_vec())
			}
		}
	}
}

impl Default for Algorithm {
	fn default() -> Self {
		crate::DEFAULT_CNF_ALGORITHM
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

fn gen_ed25519_kp() -> (String, String) {
	let mut csprng = thread_rng();
	let priv_key = Ed25519SigningKey::generate(&mut csprng);
	let pub_key = priv_key.verifying_key();
	let priv_key = general_purpose::STANDARD.encode(priv_key.to_bytes());
	let pub_key = general_purpose::STANDARD.encode(pub_key.to_bytes());
	(priv_key, pub_key)
}

fn gen_rsa_kp(bits: usize) -> (String, String) {
	let mut csprng = thread_rng();
	loop {
		if let Ok(priv_key) = RsaPrivateKey::new(&mut csprng, bits) {
			let pub_key = RsaPublicKey::from(&priv_key);
			let priv_key = match priv_key.to_pkcs8_der() {
				Ok(d) => d,
				Err(_) => {
					continue;
				}
			};
			let pub_key = match pub_key.to_public_key_der() {
				Ok(d) => d,
				Err(_) => {
					continue;
				}
			};
			let priv_key = general_purpose::STANDARD.encode(priv_key.as_bytes());
			let pub_key = general_purpose::STANDARD.encode(pub_key.as_bytes());
			return (priv_key, pub_key);
		}
		log::trace!("failed to generate an RSA-{bits} key");
	}
}
