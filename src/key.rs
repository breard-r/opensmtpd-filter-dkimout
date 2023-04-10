use crate::config::Config;
use crate::Algorithm;
use sqlx::types::time::OffsetDateTime;
use sqlx::SqlitePool;
use tokio::time::Duration;
use uuid::Uuid;

const INSERT_KEY: &str = "INSERT INTO key_db (
	selector,
	sdid,
	algorithm,
	creation,
	not_after,
	revocation,
	published,
	private_key,
	public_key
) VALUES (
	$1,
	$2,
	$3,
	$4,
	$5,
	$6,
	FALSE,
	$7,
	$8
)";
const SELECT_LATEST_KEY: &str = "SELECT not_after
FROM key_db
WHERE
	sdid = $1
	AND algorithm = $2
	AND published IS FALSE
ORDER BY not_after DESC
LIMIT 1";

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
	durations.push(Duration::from_secs(crate::KEY_CHECK_MIN_DELAY));
	durations.sort();
	durations[durations.len() - 1]
}

async fn renew_key_if_expired(
	db: &SqlitePool,
	cnf: &Config,
	domain: &str,
	algorithm: Algorithm,
	expiration: Duration,
) -> Result<Duration, ()> {
	let res: Option<(i64,)> = sqlx::query_as(SELECT_LATEST_KEY)
		.bind(domain)
		.bind(algorithm.to_string())
		.fetch_optional(db)
		.await
		.map_err(|_| ())?;
	match res {
		Some((not_after,)) => {
			let not_after = OffsetDateTime::from_unix_timestamp(not_after).map_err(|_| ())?;
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
) -> Result<(), ()> {
	let selector = format!("dkim-{}", Uuid::new_v4().simple());
	let now = OffsetDateTime::now_utc();
	let not_after = now + Duration::from_secs(cnf.cryptoperiod().get());
	let revocation = not_after + Duration::from_secs(cnf.revocation());
	let (priv_key, pub_key) = algorithm.gen_keys();
	sqlx::query(INSERT_KEY)
		.bind(selector)
		.bind(domain)
		.bind(algorithm.to_string())
		.bind(now.unix_timestamp())
		.bind(not_after.unix_timestamp())
		.bind(revocation.unix_timestamp())
		.bind(priv_key)
		.bind(pub_key)
		.execute(db)
		.await
		.map_err(|_| ())?;
	// TODO: dns_update_cmd
	log::debug!("{domain}: new {} key generated", algorithm.to_string());
	Ok(())
}
