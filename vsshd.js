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
const conf = require(`${__dirname}/conf/vssh.json`);
const _requireSafe = path => {try{return require(path);}catch (err){}}
const users = _requireSafe(`${__dirname}/conf/users.json`);

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

const _getClientAddr = client => `${client.remoteAddress}:${client.remotePort}`;

function _handleClient(client, publicKey, privateKey) {
    const letsTalk = aesKey => {
        if (!aesKey) {console.error(`Key exchange failed for ${_getClientAddr(client)}.`); client.end(); client.destroy(); return;}

        client.write(crypt.encrypt('"OK"', aesKey));    // tell client comm channels are open

        let cmdRunning = false;
        client.once("close", _=>{if (!cmdRunning) console.error("Client disconnected without command.")});
        client.once("error", err=>{if (!cmdRunning) {console.error(`Client error before command ${err}`); client.end(); client.destroy();}});
        client.once("data", data => {cmdRunning = true; _runShell(client, crypt.decrypt(data, aesKey), aesKey)});
    };

    _performKeyExchange(client, publicKey, privateKey, letsTalk);
}

function _runShell(client, upw, aesKey) {
    const launchShell = (uid, pw, client, aesKey) => {
        const shell = spawn(path.resolve(conf.shell[0]), _addUIDAndPW(conf.shell.slice(1), uid, pw));
        shell.stdout.on("data", data => io.writeData(client, data, aesKey));
        shell.stderr.on("data", data => io.writeData(client, data, aesKey));
        return shell;
    }

    let shellExited = false; const uid = decodeURI(upw.split("&")[0]); const pw = decodeURI(upw.split("&")[1]);

    if (users && users[uid].toLowerCase() != crypt.hash(pw).toLowerCase()) {
        io.writeData(client, "Bad password", aesKey);
        client.end(); client.destroy();
        console.log(`Access denied: ${_getClientAddr(client)}, user: ${uid}, bad password.`);
        return;
    }

    console.log(`Access granted: ${_getClientAddr(client)}, user: ${uid}.`);

    let shell = launchShell(uid, pw, client, aesKey);
    shell.on("close", code => {
        if (code == 0) {shellExited = true; client.end(); client.destroy(); console.log(`Closed ${_getClientAddr(client)}, user: ${uid}.`)}
        else if (conf.respawnShellOnError) {
            console.error(`Respawning shell for ${_getClientAddr(client)}, code was: ${code}.`);
            shell = launchShell(uid, pw, client, aesKey);    // respawn on errors 
        }
    });

    client.on("data", data => io.readData(client, data, aesKey, data=>shell.stdin.write(data)));
    client.on("close", _=>{if (!shellExited) shell.kill("SIGINT");});
    client.on("error", _=>{if (!shellExited) shell.kill("SIGINT");});
}

function _performKeyExchange(client, publicKey, privateKey, callback) {
    console.log(`[access] ${_getClientAddr(client)} Protocol: ${client.remoteFamily}.`);
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

function _addUIDAndPW(args, uid, pw) {
    for (const [i,arg] of args.entries()) {
        if (arg == "$uid") args[i] = uid;
        if (arg == "$pw") args[i] = pw;
    }

    return args;
}