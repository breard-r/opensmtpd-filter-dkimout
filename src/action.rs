use crate::config::Config;
use crate::entry::read_entry;
use crate::key::key_rotation;
use crate::message::Message;
use crate::stdin_reader::StdinReader;
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::sleep;

pub enum Action<'a> {
	ReadLine(Arc<RwLock<StdinReader>>),
	RotateKeys((&'a SqlitePool, &'a Config)),
	SendMessage((&'a SqlitePool, &'a Config, Message)),
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
				Err(err) => ActionResult::NewEntryError(err.to_string()),
			},
			None => ActionResult::EndOfStream,
		},
		Action::RotateKeys((db, cnf)) => {
			let duration = key_rotation(db, cnf).await;
			sleep(duration).await;
			ActionResult::KeyRotation
		}
		Action::SendMessage((db, cnf, msg)) => {
			let msg_id = msg.sign_and_return(db, cnf).await;
			ActionResult::MessageSent(msg_id)
		}
	}
}
