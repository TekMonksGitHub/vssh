/** 
 * Socket I/O functions.
 * (C) 2020 TekMonks. All rights reserved.
 * See enclosed LICENSE file.
 */
const crypt = require(`${__dirname}/crypt`);

function writeData(socket, data, key) {
    const encrypted = Buffer.from(crypt.encrypt(data, key));
    const header = new Buffer.alloc(8); header.writeBigInt64LE(BigInt(encrypted.length));
    const dataOut = Buffer.concat([header, encrypted]);
    socket.write(dataOut);
}

function readData(socket, data, key, opFunc) {
    if (!socket.__vssh_waiting_read) {
        const header = data.slice(0, 8); data = data.slice(8);
        const bytesToRead = parseInt(header.readBigInt64LE());
        if (data.length < bytesToRead) {
            socket.__vssh_waiting_read = true;
            socket.__vssh_bytes_to_read = bytesToRead;
            socket.__vssh_bytes_read = data.length;
            socket.__vssh_data = data;
        } else if (data.length > bytesToRead) {
            const dataSlice = data.slice(0, bytesToRead);
            const dataNext = Buffer.from(data.slice(bytesToRead));
            opFunc(crypt.decrypt(dataSlice, key));
            readData(socket, dataNext, key, opFunc);
        } else opFunc(crypt.decrypt(data, key));
    } else {
        if (socket.__vssh_bytes_read + data.length == socket.__vssh_bytes_to_read) {
            socket.__vssh_data = Buffer.concat([socket.__vssh_data, data]);
            socket.__vssh_waiting_read = false;
            opFunc(crypt.decrypt(new Buffer(socket.__vssh_data), key));
            delete socket.__vssh_data;
        } else if (socket.__vssh_bytes_read + data.length > socket.__vssh_bytes_to_read) {
            const dataSlice = Buffer.concat([socket.__vssh_data, data.slice(0, socket.__vssh_bytes_to_read - socket.__vssh_bytes_read)]);
            const dataNext = data.slice(socket.__vssh_bytes_to_read - socket.__vssh_bytes_read);
            socket.__vssh_waiting_read = false;
            opFunc(crypt.decrypt(dataSlice, key));
            delete socket.__vssh_data;
            readData(socket, dataNext, key, opFunc);
        } else if (socket.__vssh_bytes_read + data.length < socket.__vssh_bytes_to_read) {
            socket.__vssh_bytes_read += data.length;
            socket.__vssh_data = Buffer.concat([socket.__vssh_data, data]);
        }
    }
}

module.exports = {readData, writeData}