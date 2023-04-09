use crate::display_bytes;
use crate::stdin_reader::StdinReader;

pub const CONFIG_END: &[u8] = b"config|ready\n";
pub const CONFIG_TAG: &[u8] = b"config|";

pub async fn read_config(reader: &mut StdinReader) {
	loop {
		match reader.read_line().await {
			Some(line) => {
				if line == CONFIG_END {
					log::trace!("configuration is ready");
					return;
				}
				if !line.starts_with(CONFIG_TAG) {
					log::warn!("invalid config line: {}", display_bytes!(line));
				}
			}
			None => {
				log::debug!("end of input stream");
				std::process::exit(0);
			}
		}
	}
}

pub fn register_filter() {
	log::trace!("registering the filter");
	println!("register|filter|smtp-in|data-line");
	println!("register|ready");
	log::trace!("filter registered");
}
