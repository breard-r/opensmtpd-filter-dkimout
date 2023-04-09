use crate::config::Config;
use crate::entry::read_entry;
use crate::key::key_rotation;
use crate::message::Message;
use crate::stdin_reader::StdinReader;
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::sync::RwLock;

pub enum Action<'a> {
	ReadLine(Arc<RwLock<StdinReader>>),
	RotateKeys((&'a SqlitePool, &'a Config)),
	SendMessage((Message, &'a Config)),
}

pub enum ActionResult {
	EndOfStream,
	KeyRotation,
	MessageSent(String),
	MessageSentError(String),
	NewEntry(crate::entry::Entry),
	NewEntryError(String),
}

pub async fn new_action(action: Action<'_>) -> ActionResult {
	match action {
		Action::ReadLine(reader_lock) => read_entry(reader_lock).await,
		Action::RotateKeys((db, cnf)) => {
			key_rotation(db, cnf).await;
			ActionResult::KeyRotation
		}
		Action::SendMessage((msg, cnf)) => msg.sign_and_return(cnf).await,
	}
}
