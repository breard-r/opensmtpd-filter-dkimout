use crate::config::Config;
use sqlx::SqlitePool;

pub async fn key_rotation(db: &SqlitePool, cnf: &Config) {
	use tokio::time::{sleep, Duration};
	sleep(Duration::from_secs(10)).await;
}
