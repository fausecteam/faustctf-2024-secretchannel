import { Request, Response, default as express } from 'express';
import { default as multer } from 'multer';
import { default as fs } from 'fs';

import * as utils from './utils.js';
import * as db from './db.js'

const port = 3000;

const app = express();
const upload = multer(
	{
		dest: "/tmp/uploads"
	}
);

app.use(express.static('public'));

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.set('view engine', 'pug')
app.set('views', './views')

type Token = {
	id: number,
	action: string,
	pw: string
};

function create_token(id: number, action: string, pw: string): string {
	return utils.encrypt({
		'id': id,
		'action': action,
		'pw': pw
	});
}

function load_token<T>(params: any, res: Response, { action, handler }: { action?: string, handler: (arg0: Token) => T }): T | null {
	if (!params.token) {
		res.status(400).send('Missing Token');
		return null;
	}

	if (!params.pw) {
		res.status(400).send('Missing Password');
		return null;
	}

	const token = utils.verify(params.token);

	if (token && token.pw === params.pw && (action === undefined || token.action === action)) {
		return handler(token);
	} else if (!token) {
		res.status(400).send('Invalid Token');
		return null;
	} else if (token.pw !== params.pw) {
		res.status(401).render('wrong_password', {token, token_enc: params.token});
		return null;
	} else {
		res.status(403).send('Token misses permission');
		return null;
	}
}

app.get('/', (_: Request, res: Response) => {
	res.render('index');
});

app.post('/', async (req: Request, res: Response) => {
	load_token(req.body, res, {
		handler: async (token) => {
			const msg = await db.load_message(token.id);
			switch (token.action) {
				case 'read':
					res.render('view', {
						content: msg.content,
						typ: msg.typ,
						token: token,
						orig_token: encodeURIComponent(req.body.token),
						orig_pw: encodeURIComponent(req.body.pw),
					});
					break;
				case 'upload':
					res.render('upload', {
						orig_token: req.body.token,
						orig_pw: req.body.pw,
					});
                    break;
				case 'manage':
					res.render('manage', {
                        id: token.id,
						manage_token: req.body.token,
						orig_pw: req.body.pw,
						msgtyp: msg.typ
					})
					break;
			}
		}
	});
});

app.get('/create', (_: Request, res: Response) => {
	res.render('create');
});

app.post("/create", upload.single('file'), async (req: Request, res: Response) => {
	if (!req.body["type"]) {
		res.status(400).send("Missing type");
		return;
	}

	const typ = req.body["type"];

	if (typ === "text" && !req.body.content) {
		res.status(400).send("Missing message");
		return;
	} else if (typ === "file" && !req.file) {
		res.status(400).send("Missing file");
		return;
	}

	if (!["text", "file", "fileupload"].includes(typ)) {
		res.status(400).send("Invalid message type");
		return;
	}

	if (!req.body.pw) {
		res.status(400).send("Missing password");
		return;
	}

	let id = null;
	let path = "";
	switch (typ) {
		case 'text':
			id = await db.insert_message(req.body.content);
			break;
		case 'file':
			path = "/upload/" + utils.randToken(32);
			if (Array.isArray(req.file)) {
				res.status(400).send("Only a single file upload is supported");
				return;
			}
			fs.cpSync(req.file.path, path);
			fs.rmSync(req.file.path);
			id = await db.insert_file(path, 'file', req.file.mimetype);
			break;
		case 'fileupload':
			path = "/upload/" + utils.randToken(32);
			id = await db.insert_file(path, 'fileupload');
			break;
	}
	const token = create_token(id, 'manage', req.body.pw);
	res.render('show_token_manage', {
		id: id,
		token: token,
		manage_token: token,
		orig_pw: req.body.pw,
		msgtyp: typ
	})
});

app.post("/upload", upload.single('file'), async (req: Request, res: Response) => {
	load_token(req.body, res, {
		action: 'upload',
		handler: async (token) => {
			const msg = await db.load_message(token.id);

			if (Array.isArray(req.file)) {
				res.status(400).send("Only a single file upload is supported");
				return;
			}

			fs.cpSync(req.file.path, msg.content, { errorOnExist: true });
			fs.rmSync(req.file.path);
			db.update_mimetype(token.id, req.file.mimetype);

			res.redirect("/");
		}
	});
});

app.post("/manage", (req: Request, res: Response) => {
	load_token(req.body, res, {
		action: 'manage',
		handler: async (token) => {
			if (!req.body.action) {
				res.status(400).send("Missing action");
				return;
			}
			if (!req.body.newpw) {
				res.status(400).send("Missing new password");
				return;
			}
			const msg = await db.load_message(token.id);
			if (req.body.action === 'upload' && msg.typ !== 'fileupload') {
				res.status(400).send("Invalid action");
				return;
			}

			res.render('show_token_create', {
				id: token.id,
				token: create_token(token.id, req.body.action, req.body.newpw),
				manage_token: req.body.token,
				orig_pw: req.body.pw,
				action: req.body.action,
                msgtyp: msg.typ
			})
		}
	});
});

app.get('/viewfile', (req, res) => {
	load_token(req.query, res, {
		action: "read",
		handler: async (token) => {
			const msg = await db.load_message(token.id);
			if (msg.mimetype) {
				res.type(msg.mimetype);
			}
			res.sendFile(msg.content);
		}
	});
});

db.setup().then(() => {
	app.listen(port, () => {
		console.log(`Server is running on port ${port}`)
	});
});
