'use strict';

const stream = require('stream');

const mbed = require('./build/Release/node_mbed_dtls');

const MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY = -0x7880;
const MBEDTLS_ERR_SSL_CLIENT_RECONNECT = -0x6780;

class DtlsSocket extends stream.Duplex {
	constructor(server, address, port) {
		super({ allowHalfOpen: false });
		this.server = server;
		this.dgramSocket = server.dgramSocket;
		this.remoteAddress = address;
		this.remotePort = port;
		this._hadError = false;
		const key = `${address}:${port}`;

		this.mbedSocket = new mbed.DtlsSocket(server.mbedServer, key,
			this._sendEncrypted.bind(this),
			this._handshakeComplete.bind(this),
			this._error.bind(this),
			this._resumeSession.bind(this),
			this._newSession.bind(this));
	}

	get publicKey() {
		return this.mbedSocket.publicKey;
	}
	get publicKeyPEM() {
		return this.mbedSocket.publicKeyPEM;
	}

	_read() {
		// TODO implement way to stop/start reading?
		// do nothing since chunk pushing is async
	}

	_write(chunk, encoding, callback) {
		if (!this.mbedSocket) {
			return callback(new Error('no mbed socket'));
		}

		this._sendCallback = callback;
		this.mbedSocket.send(chunk);
	}

	_sendEncrypted(msg) {
		// store the callback here because '_write' might be called
		// again before the underlying socket finishes sending
		const sendCb = this._sendCallback;
		this._sendCallback = null;
		const sendFinished = (err) => {
			if (sendCb) {
				sendCb(err);
			}
			if (this._clientEnd) {
				this._finishEnd();
			}
		};

		// make absolutely sure the socket will let us send
		if (!this.dgramSocket || !this.dgramSocket._handle) {
			process.nextTick(() => {
				sendFinished(new Error('no underlying socket'));
			});
			return;
		}

		this.dgramSocket.send(msg, 0, msg.length, this.remotePort, this.remoteAddress, sendFinished);
	}

	_handshakeComplete() {
		this.connected = true;
		this.emit('secureConnect');
	}

	_error(code, msg) {
		if (code === MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
			this._end();
			return;
		}

		if (code === MBEDTLS_ERR_SSL_CLIENT_RECONNECT) {
			this.emit('reconnect', this);
			process.nextTick(() => {
				this.receive();
			});
			return;
		}

		this._hadError = true;
		if (this._sendCallback) {
			this._sendCallback(code);
			this._sendCallback = null;
		} else {
			this.emit('error', code, msg);
		}
		this._end();
	}

	_resumeSession(sessionId) {
		const done = this._resumeSessionCallback.bind(this);
		if (!this.server.emit('resumeSession', sessionId.toString('hex'), done)) {
			process.nextTick(done);
		}
	}

	_resumeSessionCallback(err, data) {
		if (err) {
			this._end();
			return;
		}
		this.mbedSocket.resumeSession(data || undefined);
	}

	_newSession(session) {
		session.remoteAddress = this.remoteAddress;
		session.remotePort = this.remotePort;

		const done = this._newSessionCallback.bind(this);
		if (!this.server.emit('newSession', session.id.toString('hex'), session, done)) {
			process.nextTick(done);
		}
	}

	_newSessionCallback(err) {
		if (err) {
			this._end();
			return;
		}
		this.mbedSocket.newSession();
	}

	receive(msg) {
		if (!this.mbedSocket) {
			return;
		}

		const data = this.mbedSocket.receiveData(msg);
		if (data) {
			this.push(data);
		}
	}

	end() {
		this._clientEnd = true;
		this._end();
	}

	reset() {
		this.emit('close', false);
		this.removeAllListeners();
	}

	_end() {
		if (this._ending) {
			return;
		}
		this._ending = true;

		super.end();
		this.push(null);
		const noSend = this.mbedSocket.close();
		this.mbedSocket = null;
		if (noSend || !this._clientEnd) {
			this._finishEnd();
		}
	}

	_finishEnd() {
		this.dgramSocket = null;
		this.server = null;
		this.emit('close', this._hadError);
		this.removeAllListeners();
	}
}

module.exports = DtlsSocket;
