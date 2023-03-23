use env_logger::{Builder, Env, Target};
use std::io::Write;

pub fn init_log_system() {
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
	builder.init();
}
