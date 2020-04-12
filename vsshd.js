/** 
 * Very Secure Shell - server process.
 * (C) 2020 TekMonks. All rights reserved.
 * See enclosed LICENSE file.
 */

const tcpip = require("net");
const path = require("path");
const crypto = require("crypto");
const io = require(`${__dirname}/lib/io`);
const { spawn } = require("child_process");
const crypt = require(`${__dirname}/lib/crypt`);
const conf = require(path.resolve(`${__dirname}/conf/vssh.json`));

main();

function main() {
    const keyOpts1 = {type: "spki",format: "pem"}; const keyOpts2 = {type: "pkcs8",format: "pem"};
    const {publicKey, privateKey} = crypto.generateKeyPairSync("rsa", 
        {modulusLength: 4096, publicKeyEncoding: keyOpts1, privateKeyEncoding: keyOpts2});

    if (!conf.host) conf.host = "::";   // listen on all IPv4 and IPv6 interfaces

    tcpip.createServer(socket => _handleClient(socket, publicKey, privateKey)).listen(
        conf.port, conf.host, _=>console.log(`VSSH daemon listening on ${conf.host}:${conf.port}`)
    ).on("error", err => {console.error(`VSSH Error: ${err}`); process.exit(1);});
}

function _handleClient(client, publicKey, privateKey) {
    const letsTalk = aesKey => {
        if (!aesKey) {console.error(`Key exchange failed for ${client.remoteAddress}`); client.end(); client.destroy(); return;}

        client.write(crypt.encrypt('"OK"', aesKey));    // tell client comm channels are open

        let shellExited = false; 
        const shell = spawn(path.resolve(conf.shell));
        shell.stdout.on("data", data => io.writeData(client, data, aesKey));
        shell.stderr.on("data", data => io.writeData(client, data, aesKey));
        shell.on("close", _code => {shellExited = true; client.end(); client.destroy();});

        client.on("data", data => io.readData(client, data, aesKey, data=>shell.stdin.write(data)));
        client.on("close", _=>{if (!shellExited) shell.kill("SIGINT");});
        client.on("error", _=>{if (!shellExited) shell.kill("SIGINT");});
    };

    _performKeyExchange(client, publicKey, privateKey, letsTalk);
}

function _performKeyExchange(client, publicKey, privateKey, callback) {
    client.write(publicKey);
    const errorHandler = err=>{console.error(`Error during key exchange: ${err}`); callback();}
    const eventemitterError = client.once("error", errorHandler);
    client.once("data", chunk => {
        eventemitterError.removeListener("error", errorHandler);
        try {
            const aesKey = crypto.privateDecrypt(privateKey, chunk);
            if (aesKey.length != 256) {console.error(`Error during key exchange, length.`);callback(); return;}
            callback(aesKey);
        } catch (err) {
            console.error(`Error during key exchange: ${err}`);
            callback();
        }
    });
}
