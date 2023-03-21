use env_logger::{Builder, Env, Target};

pub fn init_log_system() {
	let env = Env::new()
		.filter_or(crate::LOG_LEVEL_ENV_VAR, "warn")
		.write_style_or(crate::LOG_STYLE_ENV_VAR, "never");
	let mut builder = Builder::from_env(env);
	builder.target(Target::Stderr);
	builder.init();
}
