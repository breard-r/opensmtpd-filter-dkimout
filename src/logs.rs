use crate::config::Config;
use env_logger::{Builder, Env, Target};
use log::LevelFilter;
use std::io::Write;

pub fn init_log_system(cnf: &Config) {
	let env = Env::new().filter_or(crate::LOG_LEVEL_ENV_VAR, "warn");
	let mut builder = Builder::from_env(env);
	builder.format(|buf, record| {
		writeln!(
			buf,
			"{}: {}",
			record.level().to_string().to_lowercase(),
			record.args()
		)
	});
	builder.target(Target::Stderr);
	builder.filter_level(cnf.verbosity());
	builder.init();
}

pub fn log_level(level_nb: u8) -> LevelFilter {
	match level_nb {
		0 => LevelFilter::Info,
		1 => LevelFilter::Debug,
		_ => LevelFilter::Trace,
	}
}
