/* 
 * (C) 2015 - 2018 TekMonks. All rights reserved.
 */
const crypto = require("crypto");
const CRYPT_ALGO = "aes-256-ctr";

const encrypt = (text, key) => {
	if (Buffer.isBuffer(text)) text = text.toString("utf-8");
	const iv = Buffer.from(crypto.randomBytes(16)).toString("hex").slice(0, 16);
	const password_hash = crypto.createHash("md5").update(key, "utf-8").digest("hex").toUpperCase();
	const cipher = crypto.createCipheriv(CRYPT_ALGO, password_hash, iv);
	let crypted = cipher.update(text, "utf8", "hex");
	crypted += cipher.final("hex");
	return crypted + iv;
};

const decrypt = (text, key) => {
	if (Buffer.isBuffer(text)) text = text.toString("utf-8");
	const iv = text.slice(text.length - 16, text.length);
	text = text.substring(0, text.length - 16);
	const password_hash = crypto.createHash("md5").update(key, "utf-8").digest("hex").toUpperCase();
	const decipher = crypto.createDecipheriv(CRYPT_ALGO, password_hash, iv);
	let decrypted = decipher.update(text, "hex", "utf8");
	decrypted += decipher.final("utf8");
	return decrypted;
};

module.exports = {encrypt, decrypt};
