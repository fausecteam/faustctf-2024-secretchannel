import crypto from 'crypto';
import * as db from './db.js'

let key: Buffer;
db.setup().then(
	() => db.load('crypto.key'),
	(err) => console.log(err)
).then(
	(value) => {
		if (value) {
			key = Buffer.from(value, 'hex');
		}
	},
	() => {
		key = crypto.randomBytes(64);
		db.store('crypto.key', key.toString('hex'));
	}
);

export function encrypt (object: any): string {
    let data = JSON.stringify(object);

    let aes_key = key.subarray(0, 32);
    let hmac_key = key.subarray(32);

    let iv = crypto.randomBytes(16);
    let cipher = crypto.createCipheriv('aes-256-cbc', aes_key, iv);

    let ciphertext = Buffer.concat([
        cipher.update(data, 'utf8'),
        cipher.final()
    ]);
    let hmac = crypto.createHmac('sha256', hmac_key).update(ciphertext).digest();

    return Buffer.concat([iv, ciphertext, hmac]).toString('base64');
}

export function verify (data: string): any {
    let aes_key = key.subarray(0, 32);
    let hmac_key = key.subarray(32);

    let buffer = Buffer.from(data, 'base64');
    let iv = buffer.subarray(0, 16);
    let ciphertext = buffer.subarray(16, -32);
    let hmac = buffer.subarray(-32);

    let cipher_mac = crypto.createHmac('sha256', hmac_key).update(ciphertext).digest();

    if (!cipher_mac.equals(hmac)) {
        return null;
    }

    let cipher = crypto.createDecipheriv('aes-256-cbc', aes_key, iv);
    let plaintext = cipher.update(ciphertext, undefined, 'utf8') + cipher.final('utf8');

    return JSON.parse(plaintext);
}

export function randToken(n: number): string {
	return crypto.randomBytes(n).toString('hex');
}
