CREATE TABLE key_db (
	selector		TEXT,
	sdid			TEXT,
	algorithm		TEXT,
	creation		INTEGER,
	not_after		INTEGER,
	revocation		INTEGER,
	published		BOOLEAN,
	private_key		TEXT,
	public_key		TEXT
);
