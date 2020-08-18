/** 
 * Socket I/O functions. AES encrypted TCP SOCKET layer.
 * OSI Model Layer 4.
 * (C) 2020 TekMonks. All rights reserved.
 * See enclosed LICENSE file.
 */
const crypt = require(`${__dirname}/crypt`); 

const _log = (message, socket) => socket?`[TCP] [VSSH IO Subsystem] [${socket.remoteAddress}:${socket.remotePort}] ${message}`:`[TCP] [VSSH IO Subsystem] ${message}`;

function getWritableData(data, key) {
    const encrypted = Buffer.from(crypt.encrypt(data, key)); 
    const header = new Buffer.alloc(8); header.writeBigInt64LE(BigInt(encrypted.length));
    const dataOut = Buffer.concat([header, encrypted]);
    LOG.debug(_log(`Sending data length: ${dataOut.length}`));
    return dataOut;
}

function readData(socket, data, key, opFunc) {
    const log = msg => LOG.debug(_log(msg, socket));
    
    const cleanSocketAndSendData = dataToDecrypt => {
        delete socket.__vssh_waiting_read; delete socket.__vssh_data;
        delete socket.__vssh_bytes_to_read; socket.__vssh_bytes_read;
        opFunc(crypt.decrypt(dataToDecrypt, key));
    }

    if (!socket.__vssh_waiting_read) {
        const header = data.slice(0, 8); data = data.slice(8);
        if (socket.__vssh_next_data) {  // we got another data packet, while previous one is pending to be read, do it now
            log(`Got new VSSH IO packet, but unprocessed left over data was found, concatenating it`);
            data = Buffer.concat([socket.__vssh_next_data, data]); 
            delete socket.__vssh_next_data;
        }
        
        const bytesToRead = parseInt(header.readBigInt64LE());
        log(`Got new VSSH IO packet, bytes to read = ${bytesToRead}`);

        if (data.length < bytesToRead) {
            log(`Got less data than needed, on new packet, got: ${data.length}, wanted to read: ${bytesToRead}`);
            socket.__vssh_waiting_read = true;
            socket.__vssh_bytes_to_read = bytesToRead;
            socket.__vssh_bytes_read = data.length;
            socket.__vssh_data = data;
        } else if (data.length > bytesToRead) {
            log(`Got more data than needed, on new packet, got: ${data.length}, wanted to read: ${bytesToRead}`);
            const dataSlice = data.slice(0, bytesToRead);
            const dataNext = Buffer.from(data.slice(bytesToRead)); 
            socket.__vssh_next_data = dataNext; // save data in case event loop sends another read first
            cleanSocketAndSendData(dataSlice);  // will cause async events to be processed
            if (socket.__vssh_next_data) {      // this may already have been processed if we were sent another read before next line of code
                delete socket.__vssh_next_data;     // clean up the socket, removed saved data, if needed
                readData(socket, dataNext, key, opFunc);    // may have received more data before this is called
            }
        } else {
            log(`Got correct amount of data, on new packet, got: ${data.length}, wanted to read: ${bytesToRead}`);
            cleanSocketAndSendData(data);
        }
    } else {
        if (socket.__vssh_bytes_read + data.length == socket.__vssh_bytes_to_read) {
            log(`Got correct amount of data, on waiting packet, got: ${data.length}, previous read was ${socket.__vssh_bytes_read}, total to read: ${socket.__vssh_bytes_to_read}`); 
            cleanSocketAndSendData(Buffer.concat([socket.__vssh_data, data]));
        } else if (socket.__vssh_bytes_read + data.length > socket.__vssh_bytes_to_read) {
            log(`Got more data than needed, on waiting packet, got: ${data.length}, previous read was ${socket.__vssh_bytes_read}, total to read: ${socket.__vssh_bytes_to_read}`);
            const dataSlice = Buffer.concat([socket.__vssh_data, data.slice(0, socket.__vssh_bytes_to_read - socket.__vssh_bytes_read)]);
            const dataNext = Buffer.from(data.slice(socket.__vssh_bytes_to_read - socket.__vssh_bytes_read));
            socket.__vssh_next_data = dataNext; // save data in case event loop sends another read first
            cleanSocketAndSendData(dataSlice);  // will cause async events to be processed
            if (socket.__vssh_next_data) {      // this may already have been processed if we were sent another read before next line of code
                delete socket.__vssh_next_data;     // clean up the socket, removed saved data, if needed
                readData(socket, dataNext, key, opFunc);    // may have received more data before this is called
            }
        } else if (socket.__vssh_bytes_read + data.length < socket.__vssh_bytes_to_read) {
            log(`Got less data than needed, on waiting packet, got: ${data.length}, previous read was ${socket.__vssh_bytes_read}, total to read: ${socket.__vssh_bytes_to_read}`);
            socket.__vssh_bytes_read += data.length;
            socket.__vssh_data = Buffer.concat([socket.__vssh_data, data]);
        }
    }
}

module.exports = {readData, getWritableData}