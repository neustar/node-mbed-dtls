'use strict';

var EventEmitter = require('events').EventEmitter;

var mbed = require('./build/Release/node_mbed_dtls');

class DtlsSocket extends EventEmitter {
	constructor(server, address, port) {
		super();
		this.dgramSocket = server.dgramSocket;
		this.address = address;
		this.port = port;
		const key = `${address}:${port}`;

		this.mbedSocket = new mbed.DtlsSocket(server.mbedServer, key,
			this._sendEncrypted.bind(this),
			this._handshakeComplete.bind(this),
			this._error.bind(this));
	}

	send(msg) {
		//console.log('send', msg);
		if (!Buffer.isBuffer(msg)) {
			msg = new Buffer(msg);
		}
		return this.mbedSocket.send(msg);
	}

	_sendEncrypted(msg) {
		//console.log('send encrypted', msg.toString('hex', 0, 16));
		this.dgramSocket.send(msg, 0, msg.length, this.port, this.address);
	}

	_handshakeComplete() {
		//console.log('handshake complete');
		this.emit('secureConnect');
	}

	_error(code, msg) {
		this.emit('error', code, msg);
		this.removeAllListeners();
	}

	receive(msg) {
		const data = this.mbedSocket.receiveData(msg);
		if (data) {
			this.emit('message', data);
		}
	}
}

module.exports = DtlsSocket;
