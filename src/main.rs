mod action;
mod algorithm;
mod canonicalization;
mod config;
mod db;
mod entry;
mod handshake;
mod key;
mod logs;
mod message;
mod parsed_message;
mod stdin_reader;

use action::{new_action, Action, ActionResult};
use algorithm::Algorithm;
use canonicalization::CanonicalizationType;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use key::key_rotation;
use message::Message;
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::Arc;
use stdin_reader::StdinReader;
use tokio::sync::RwLock;

const DEFAULT_BUFF_SIZE: usize = 1024;
const DEFAULT_CNF_ALGORITHM: Algorithm = Algorithm::Rsa2048Sha256;
const DEFAULT_CNF_CANONICALIZATION_BODY: CanonicalizationType = CanonicalizationType::Relaxed;
const DEFAULT_CNF_CANONICALIZATION_HEADER: CanonicalizationType = CanonicalizationType::Relaxed;
const DEFAULT_CNF_CRYPTOPERIOD: u64 = 15552000;
const DEFAULT_CNF_EXPIRATION: u64 = 1296000;
const DEFAULT_CNF_HEADERS: &str = "from:reply-to:subject:date:to:cc";
const DEFAULT_CNF_HEADERS_OPT: &str = "resent-date:resent-from:resent-to:resent-cc:in-reply-to:references:list-id:list-help:list-unsubscribe:list-subscribe:list-post:list-owner:list-archive";
const DEFAULT_CNF_KEY_DB: &str = "key-db.sqlite3";
const DEFAULT_CNF_REVOCATION: u64 = 1728000;
const DEFAULT_LIB_DIR: &str = env!("VARLIBDIR");
const DEFAULT_MSG_SIZE: usize = 1024 * 1024;
const LOG_LEVEL_ENV_VAR: &str = "OPENSMTPD_FILTER_DKIMOUT_LOG_LEVEL";

#[macro_export]
macro_rules! display_bytes {
	($bytes: expr) => {
		$bytes
			.iter()
			.map(|b| {
				let v: Vec<u8> = std::ascii::escape_default(*b).collect();
				String::from_utf8_lossy(&v).to_string()
			})
			.collect::<String>()
	};
}

macro_rules! log_messages {
	($list: ident) => {
		log::trace!(
			"message list has {} elements: {}",
			$list.len(),
			$list
				.iter()
				.map(|(k, v)| { format!("{k} ({} lines)", v.nb_lines()) })
				.collect::<Vec<String>>()
				.join(", ")
		)
	};
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
	match config::Config::init() {
		Ok(cnf) => {
			logs::init_log_system(&cnf);
			log::debug!("{cnf:?}");
			match db::init(&cnf).await {
				Ok(pool) => main_loop(&cnf, &pool).await,
				Err(e) => eprintln!("{e}"),
			}
		}
		Err(e) => eprintln!("{e}"),
	}
	Ok(())
}

async fn main_loop(cnf: &config::Config, db: &SqlitePool) {
	let mut actions = FuturesUnordered::new();
	let mut reader = StdinReader::new();
	let mut messages: HashMap<String, Message> = HashMap::new();
	tokio::join!(
		handshake::read_config(&mut reader),
		key_rotation(db, cnf),
	);
	handshake::register_filter();
	log_messages!(messages);
	let reader_lock = Arc::new(RwLock::new(reader));
	actions.push(new_action(Action::ReadLine(reader_lock.clone())));
	actions.push(new_action(Action::RotateKeys((db, cnf))));
	loop {
		if actions.len() <= 1 {
			break;
		}
		if let Some(action_res) = actions.next().await {
			match action_res {
				ActionResult::EndOfStream => {
					log::debug!("end of input stream");
				}
				ActionResult::KeyRotation => {
					actions.push(new_action(Action::RotateKeys((db, cnf))));
				}
				ActionResult::MessageSent(msg_id) => {
					log::debug!("message removed: {msg_id}");
				}
				ActionResult::NewEntry(entry) => {
					let msg_id = entry.get_msg_id();
					match messages.get_mut(&msg_id) {
						Some(msg) => {
							if !entry.is_end_of_message() {
								log::debug!("new line in message: {msg_id}");
								msg.append_line(entry.get_data());
							} else {
								log::debug!("message ready: {msg_id}");
								if let Some(m) = messages.remove(&msg_id) {
									actions.push(new_action(Action::SendMessage((m, cnf))));
								}
							}
						}
						None => {
							let msg = Message::from_entry(&entry);
							log::debug!("new message: {msg_id}");
							if !entry.is_end_of_message() {
								messages.insert(msg_id.clone(), msg);
							} else {
								actions.push(new_action(Action::SendMessage((msg, cnf))));
							}
						}
					}
					log_messages!(messages);
					actions.push(new_action(Action::ReadLine(reader_lock.clone())));
				}
				ActionResult::NewEntryError(err) => {
					log::error!("invalid filter line: {err}");
					actions.push(new_action(Action::ReadLine(reader_lock.clone())));
				}
			}
		}
	}
}
