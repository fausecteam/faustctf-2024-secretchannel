import { Pool } from "pg";

const db = new Pool();
let setupDone = false;

export async function setup() {
	if (setupDone) {
		return;
	}
	setupDone = true;
	await db.query("CREATE TABLE IF NOT EXISTS messages (id SERIAL PRIMARY KEY, content VARCHAR(255), typ VARCHAR(255), mimetype VARCHAR(255))");
	await db.query("CREATE TABLE IF NOT EXISTS securestorage (key VARCHAR(255) PRIMARY KEY, value VARCHAR(255))");
	
	console.log("Initialized database");
}

export async function store(key: string, value: any) {
	await db.query("INSERT INTO securestorage VALUES ($1, $2)", [key, JSON.stringify(value)]);
}

export async function load(key: string) {
	const res = await db.query("SELECT value FROM securestorage WHERE key = $1", [key]);

	if (res.rowCount == 0) {
		Promise.reject();
	}

	return JSON.parse(res.rows[0].value);
}

export async function insert_message(message: string) {
	const res = await db.query("INSERT INTO messages (content, typ) VALUES ($1, 'text') RETURNING id", [message]);

	return res.rows[0].id;
}

export async function insert_file(path: string, typ: string, mimetype?: string) {
	const res = await db.query("INSERT INTO messages (content, typ, mimetype) VALUES ($1, $2, $3) RETURNING id", [path, typ, mimetype]);

	return res.rows[0].id;
}

export class Message {
	id: number;
	content: string;
	typ: string;
	mimetype?: string;
};

export async function load_message(id: number): Promise<Message> {
	const res = await db.query("SELECT * FROM messages WHERE id = $1", [id]);

	if (res.rowCount == 0) {
		Promise.reject();
	}

	return res.rows[0];
}

export async function update_mimetype(id: number, mimetype: string): Promise<void> {
	const res = await db.query("UPDATE messages SET mimetype = $2 WHERE id = $1", [id, mimetype]);

	if (res.rowCount == 0) {
		Promise.reject();
	}
}
