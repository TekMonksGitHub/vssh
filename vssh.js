/** 
 * Very Secure Shell - client side.
 * (C) 2020 TekMonks. All rights reserved.
 * See enclosed LICENSE file.
 */

const tcpip = require("net");
const crypto = require("crypto");
const io = require(`${__dirname}/lib/io`);
const crypt = require(`${__dirname}/lib/crypt`);

main();

function main() {

    const args = process.argv.slice(2);
    if (args.length < 3) {
        console.log("Usage: vssh <user id> <password> <ip> [optional: port]");
        process.exit(1);
    }

    const host = args[2]; const port = (args.length == 4) ? args[3] : 8329;
    const upw = `${encodeURI(args[0])}&${encodeURI(args[1])}`;

    let noReply = true;

    const vsshd = tcpip.connect({port, host, timeout:120000}).ref();
    vsshd.once("data", publicKey => {
        noReply = false; const key = publicKey.toString("utf8");
        const aesKey = crypto.randomBytes(256);
        const encryptedResponse = crypto.publicEncrypt(key, aesKey);
        vsshd.write(encryptedResponse);
        vsshd.once("data", chunk => {
            try {
                const dataIn = crypt.decrypt(chunk, aesKey);
                if (JSON.parse(dataIn) == "OK") {
                    vsshd.write(crypt.encrypt(upw, aesKey));
                    letsTalk(vsshd, aesKey);
                }
                else {
                    console.error("Key exchange failed.");
                    vsshd.end(); vsshd.destroy(); 
                    process.exit(1);
                }
            } catch (err) {
                console.error(`Key exchange failed due to: ${err}`);
                vsshd.end(); vsshd.destroy(); 
                process.exit(1);
            }
        });
    });
    vsshd.once("timeout", _=> {if (noReply) {console.log("Couldn't connect."); process.exit(1);}});
    vsshd.once("error", err => {console.error(`Error: ${err}\nClosing connection.`); vsshd.end(); vsshd.destroy();});
}

function letsTalk(vsshd, aesKey) {
    vsshd.on("data", data => io.readData(vsshd, data, aesKey, data=>process.stdout.write(_addScreenEscapes(data))));
    vsshd.on("error", err => {console.error(`Error: ${err}\nClosing connection.`); vsshd.end(); vsshd.destroy();});
    vsshd.on("close", _=>process.exit(0));
    process.stdin.on("data", data => io.writeData(vsshd, _removeDosLineEndingsForWindows(data), aesKey));
    process.on("SIGINT", _=>{vsshd.end(); process.exit(1)});   // close connection
}

function _removeDosLineEndingsForWindows(data) {
    if (process.platform != "win32") return data;

    if (!Buffer.isBuffer(data)) data = Buffer.from(data);

    const chkPos = data.length-2;
    if (data[chkPos] == 13) data = Buffer.concat([data.slice(0, chkPos),data.slice(chkPos+1)]);
    return data;
}

function _addScreenEscapes(data) {
    if (!Buffer.isBuffer(data)) data = Buffer.from(data);
    const CLRSCR = Buffer.from('\033[2J\033[0f');
    for (const [i,byte] of data.entries()) 
        if (byte == 12) data = Buffer.concat([data.slice(0, i),CLRSCR,data.slice(i+1)]);
        
    return data;
}