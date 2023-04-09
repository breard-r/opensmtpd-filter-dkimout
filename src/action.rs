use crate::config::Config;
use crate::entry::read_entry;
use crate::key::key_rotation;
use crate::message::Message;
use crate::stdin_reader::StdinReader;
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::sync::RwLock;

pub enum ActionResult {
	EndOfStream,
	KeyRotation,
	MessageSent(String),
	MessageSentError(String),
	NewEntry(crate::entry::Entry),
	NewEntryError(String),
}

pub async fn new_action(
	reader_lock: Option<Arc<RwLock<StdinReader>>>,
	db_opt: Option<(&SqlitePool, &Config)>,
	msg_tpl: Option<Message>,
) -> ActionResult {
	if let Some(reader_lock) = reader_lock {
		return read_entry(reader_lock).await;
	}
	if let Some((db, cnf)) = db_opt {
		match msg_tpl {
			Some(msg) => {
				return msg.sign_and_return(cnf).await;
			}
			None => {
				key_rotation(db, cnf).await;
				return ActionResult::KeyRotation;
			}
		}
	}
	ActionResult::MessageSentError("new_action: invalid parameters".to_string())
}
