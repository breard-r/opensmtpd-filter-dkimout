use crate::config::Config;
use crate::entry::read_entry;
use crate::message::Message;
use crate::stdin_reader::StdinReader;
use std::sync::Arc;
use tokio::sync::RwLock;

pub enum ActionResult {
	EndOfStream,
	MessageSent(String),
	MessageSentError(String),
	NewEntry(crate::entry::Entry),
	NewEntryError(String),
}

pub async fn new_action(
	reader_lock: Option<Arc<RwLock<StdinReader>>>,
	msg_tpl: Option<(Message, &Config)>,
) -> ActionResult {
	if let Some(reader_lock) = reader_lock {
		return read_entry(reader_lock).await;
	}
	if let Some((msg, cnf)) = msg_tpl {
		return msg.sign_and_return(cnf).await;
	}
	ActionResult::MessageSentError("new_action: invalid parameters".to_string())
}
