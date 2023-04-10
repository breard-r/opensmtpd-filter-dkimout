use crate::config::Config;
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
pub const SELECT_LATEST_KEY: &str = "SELECT not_after
FROM key_db
WHERE
	sdid = $1
	AND algorithm = $2
	AND published IS FALSE
ORDER BY not_after DESC
LIMIT 1";

pub async fn init(cnf: &Config) -> Result<SqlitePool, String> {
	do_init(cnf).await.map_err(|e| e.to_string())
}

async fn do_init(cnf: &Config) -> Result<SqlitePool, sqlx::Error> {
	let mut db_options = SqliteConnectOptions::new()
		.filename(cnf.key_data_base())
		.create_if_missing(true);
	db_options.log_statements(log::LevelFilter::Trace);
	let db_pool = SqlitePoolOptions::new().connect_with(db_options).await?;
	sqlx::migrate!().run(&db_pool).await?;
	Ok(db_pool)
}
