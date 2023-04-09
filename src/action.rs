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
	NewEntry(crate::entry::Entry),
	NewEntryError(String),
}

pub async fn new_action(action: Action<'_>) -> ActionResult {
	match action {
		Action::ReadLine(reader_lock) => match read_entry(reader_lock).await {
			Some(r) => match r {
				Ok(entry) => ActionResult::NewEntry(entry),
				Err(err) => ActionResult::NewEntryError(err),
			},
			None => ActionResult::EndOfStream,
		},
		Action::RotateKeys((db, cnf)) => {
			key_rotation(db, cnf).await;
			ActionResult::KeyRotation
		}
		Action::SendMessage((msg, cnf)) => {
			let msg_id = msg.sign_and_return(cnf).await;
			ActionResult::MessageSent(msg_id)
		}
	}
}
