use crate::config::Config;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{ConnectOptions, SqlitePool};

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
