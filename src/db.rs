use crate::config::Config;
use anyhow::Result;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{ConnectOptions, SqlitePool};

pub const INSERT_KEY: &str = "INSERT INTO key_db (
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
pub const SELECT_EXPIRED_KEYS: &str = "SELECT selector, sdid, algorithm, private_key
FROM key_db
WHERE
	revocation <= unixepoch()
	AND published IS FALSE
ORDER BY revocation";
pub const SELECT_LATEST_KEY: &str = "SELECT not_after
FROM key_db
WHERE
	sdid = $1
	AND algorithm = $2
	AND published IS FALSE
ORDER BY not_after DESC
LIMIT 1";
pub const SELECT_LATEST_SIGNING_KEY: &str = "SELECT selector, private_key
FROM key_db
WHERE
	sdid = $1
	AND algorithm = $2
	AND published IS FALSE
ORDER BY not_after DESC
LIMIT 1";
pub const SELECT_NEAREST_KEY_PUBLICATION: &str = "SELECT revocation
FROM key_db
WHERE published IS FALSE
ORDER BY revocation
LIMIT 1";
pub const UPDATE_PUBLISHED_KEY: &str = "UPDATE key_db
SET published = TRUE
WHERE
	selector = $1
	AND sdid = $2
	AND algorithm = $3";

pub async fn init(cnf: &Config) -> Result<SqlitePool> {
	let mut db_options = SqliteConnectOptions::new()
		.filename(cnf.key_data_base())
		.create_if_missing(true);
	db_options.log_statements(log::LevelFilter::Trace);
	let db_pool = SqlitePoolOptions::new().connect_with(db_options).await?;
	sqlx::migrate!().run(&db_pool).await?;
	Ok(db_pool)
}
