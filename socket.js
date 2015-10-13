'use strict';

var EventEmitter = require('events').EventEmitter;

var mbed = require('./build/Release/node_mbed_dtls');

const MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY = -0x7880;

class DtlsSocket extends EventEmitter {
	constructor(server, address, port) {
		super();
		this.dgramSocket = server.dgramSocket;
		this.address = address;
		this.port = port;
		const key = `${address}:${port}`;

		this.dgramSocket.once('close', () => {
			this.dgramSocket = null;
		});

		this.mbedSocket = new mbed.DtlsSocket(server.mbedServer, key,
			this._sendEncrypted.bind(this),
			this._handshakeComplete.bind(this),
			this._error.bind(this));
	}

	send(msg) {
		if (!this.mbedSocket) {
			return;
		}

		if (!Buffer.isBuffer(msg)) {
			msg = new Buffer(msg);
		}
		this.mbedSocket.send(msg);
	}

	_sendEncrypted(msg) {
		// make absolutely sure the socket will let us send
		if (!this.dgramSocket || !this.dgramSocket._handle) {
			return;
		}
		this.dgramSocket.send(msg, 0, msg.length, this.port, this.address);
	}

	_handshakeComplete() {
		this.connected = true;
		this.emit('secureConnect');
	}

	_error(code, msg) {
		if (code === MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
			this.close();
			return;
		}

		this.emit('error', code, msg);
		this.removeAllListeners();
	}

	receive(msg) {
		if (!this.mbedSocket) {
			return;
		}

		const data = this.mbedSocket.receiveData(msg);
		if (data) {
			this.emit('message', data);
		}
	}

	close() {
		this.mbedSocket.close();
		this.mbedSocket = null;
		this.dgramSocket = null;
		this.emit('close');
		this.removeAllListeners();
	}
}

module.exports = DtlsSocket;
