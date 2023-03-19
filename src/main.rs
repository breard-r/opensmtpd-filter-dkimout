mod handshake;

fn main() {
	handshake::read_config();
	handshake::register_filter();
}
