use crate::config::Config;
use crate::Algorithm;
use anyhow::Result;
use sqlx::types::time::OffsetDateTime;
use sqlx::SqlitePool;
use std::path::Path;
use tokio::fs::OpenOptions;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::time::Duration;
use uuid::Uuid;

pub async fn key_rotation(db: &SqlitePool, cnf: &Config) -> Duration {
	let mut durations = Vec::with_capacity(cnf.domains().len());
	let expiration = cnf
		.expiration()
		.map(Duration::from_secs)
		.unwrap_or_else(|| Duration::from_secs(cnf.cryptoperiod().get() / 10));
	for domain in cnf.domains() {
		if let Ok(d) = renew_key_if_expired(db, cnf, domain, cnf.algorithm(), expiration).await {
			durations.push(d);
		}
	}
	if let Some(path) = cnf.revocation_list() {
		match publish_expired_keys(db, path).await {
			Ok(d) => durations.push(d),
			Err(err) => log::error!("{err}"),
		};
	}
	durations.push(Duration::from_secs(crate::KEY_CHECK_MIN_DELAY));
	durations.sort();
	durations[durations.len() - 1]
}

async fn publish_expired_keys(db: &SqlitePool, file_path: &Path) -> Result<Duration> {
	let res: Vec<(String, String, String, String)> = sqlx::query_as(crate::db::SELECT_EXPIRED_KEYS)
		.fetch_all(db)
		.await?;
	if !res.is_empty() {
		let rev_file = OpenOptions::new()
			.write(true)
			.create(true)
			.append(true)
			.open(file_path)
			.await?;
		let mut buff = BufWriter::new(rev_file);
		for (selector, sdid, algorithm, private_key) in res {
			buff.write_all(algorithm.as_bytes()).await?;
			buff.write_all(b" ").await?;
			buff.write_all(private_key.as_bytes()).await?;
			buff.write_all(b" ").await?;
			buff.write_all(selector.as_bytes()).await?;
			buff.write_all(b"._domainkey.").await?;
			buff.write_all(sdid.as_bytes()).await?;
			buff.write_all(b"\n").await?;
			buff.flush().await?;
			sqlx::query(crate::db::UPDATE_PUBLISHED_KEY)
				.bind(&selector)
				.bind(&sdid)
				.bind(&algorithm)
				.execute(db)
				.await?;
			log::info!(
				"{algorithm} private key for {selector}._domainkey.{sdid} has been published"
			);
		}
	}
	let res: Option<(i64,)> = sqlx::query_as(crate::db::SELECT_NEAREST_KEY_PUBLICATION)
		.fetch_optional(db)
		.await?;
	match res {
		Some((next_pub_ts,)) => {
			let now_ts = OffsetDateTime::now_utc().unix_timestamp();
			let delta = 0.max(next_pub_ts - now_ts);
			Ok(Duration::from_secs(delta as u64))
		}
		None => Ok(Duration::from_secs(crate::KEY_CHECK_MIN_DELAY)),
	}
}

async fn renew_key_if_expired(
	db: &SqlitePool,
	cnf: &Config,
	domain: &str,
	algorithm: Algorithm,
	expiration: Duration,
) -> Result<Duration> {
	let res: Option<(i64,)> = sqlx::query_as(crate::db::SELECT_LATEST_KEY)
		.bind(domain)
		.bind(algorithm.to_string())
		.fetch_optional(db)
		.await?;
	match res {
		Some((not_after,)) => {
			let not_after = OffsetDateTime::from_unix_timestamp(not_after)?;
			log::debug!("{domain}: key is valid until {not_after}");
			if not_after - expiration <= OffsetDateTime::now_utc() {
				generate_key(db, cnf, domain, algorithm).await?;
			}
		}
		None => {
			log::debug!("no key found for domain {domain}");
			generate_key(db, cnf, domain, algorithm).await?;
		}
	};
	Ok(Duration::from_secs(10))
}

async fn generate_key(
	db: &SqlitePool,
	cnf: &Config,
	domain: &str,
	algorithm: Algorithm,
) -> Result<()> {
	let selector = format!("dkim-{}", Uuid::new_v4().simple());
	let now = OffsetDateTime::now_utc();
	let not_after = now + Duration::from_secs(cnf.cryptoperiod().get());
	let revocation = not_after + Duration::from_secs(cnf.revocation());
	let (priv_key, pub_key) = algorithm.gen_keys();
	sqlx::query(crate::db::INSERT_KEY)
		.bind(selector)
		.bind(domain)
		.bind(algorithm.to_string())
		.bind(now.unix_timestamp())
		.bind(not_after.unix_timestamp())
		.bind(revocation.unix_timestamp())
		.bind(priv_key)
		.bind(pub_key)
		.execute(db)
		.await?;
	// TODO: dns_update_cmd
	log::debug!("{domain}: new {} key generated", algorithm.to_string());
	Ok(())
}
