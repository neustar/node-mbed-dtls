'use strict';

var dgram = require('dgram');
var fs = require('fs');
var EventEmitter = require('events').EventEmitter;

var DtlsSocket = require('./socket');
var mbed = require('./build/Release/node_mbed_dtls');

class DtlsServer extends EventEmitter {
	constructor(options) {
		super();
		this.options = options = Object.assign({
			sendClose: true
		}, options);

		this.sockets = {};
		this.dgramSocket = dgram.createSocket('udp4');
		this._onMessage = this._onMessage.bind(this);
		this.listening = false;

		this.dgramSocket.on('message', this._onMessage);
		this.dgramSocket.once('listening', () => {
			this.listening = true;
			this.emit('listening');
		});
		this.dgramSocket.once('error', err => {
			this.emit('error', err);
			this._closeSocket();
		});
		this.dgramSocket.once('close', () => {
			this._socketClosed();
		});

		let key = Buffer.isBuffer(options.key) ? options.key : fs.readFileSync(options.key);
		// likely a PEM encoded key, add null terminating byte
		// 0x2d = '-'
		if (key[0] === 0x2d && key[key.length - 1] !== 0) {
			key = Buffer.concat([key, new Buffer([0])]);
		}

		this.mbedServer = new mbed.DtlsServer(key, options.debug);
		if (options.handshakeTimeoutMin) {
			this.mbedServer.handshakeTimeoutMin = options.handshakeTimeoutMin;
		}
	}

	listen(port, hostname, callback) {
		this.dgramSocket.bind(port, hostname, callback);
	}

	close(callback) {
		if (callback) {
			this.once('close', callback);
		}
		this._closing = true;
		this._endSockets();
	}

	address() {
		return this.dgramSocket.address();
	}

	getConnections(callback) {
		var numConnections = Object.keys(this.sockets).filter(skey => {
			return this.sockets[skey] && this.sockets[skey].connected;
		}).length;
		process.nextTick(callback, null, numConnections);
	}

	resumeSocket(rinfo, session) {
		const key = `${rinfo.address}:${rinfo.port}`;
		let client = this.sockets[key];
		if (client) {
			return false;
		}

		this.sockets[key] = client = this._createSocket(rinfo, key);
		if (client.resumeSession(session)) {
			this.emit('secureConnection', client, session);
			return true;
		}
		return false;
	}

	_onMessage(msg, rinfo) {
		const key = `${rinfo.address}:${rinfo.port}`;

		let client = this.sockets[key];
		if (!client) {
			this.sockets[key] = client = this._createSocket(rinfo, key);

			// if ApplicationData (23)
			if (msg.length > 0 && msg[0] === 23) {
				const called = this.emit('resumeSession', key, client, (err, session) => {
					if (!err && session) {
						if (client.resumeSession(session)) {
							client.cork();
							if (client.receive(msg)) {
								this.emit('secureConnection', client, session);
							}
							client.uncork();
							return;
						}
					}
					client.receive(msg);
				});

				// if somebody was listening, session will attempt to be resumed
				// do not process with receive until resume finishes
				if (called) {
					return;
				}
			}
		}

		client.receive(msg);
	}

	_createSocket(rinfo, key) {
		var client = new DtlsSocket(this, rinfo.address, rinfo.port);
		client.sendClose = this.options.sendClose;
		this._attachToSocket(client, key);
		return client;
	}

	_attachToSocket(client, key) {
		client.once('error', (code, err) => {
			delete this.sockets[key];
			if (!client.connected) {
				this.emit('clientError', err, client);
			}
		});
		client.once('close', () => {
			delete this.sockets[key];
			client = null;
			if (this._closing && Object.keys(this.sockets).length === 0) {
				this._closeSocket();
			}
		});
		client.once('reconnect', socket => {
			// treat like a brand new connection
			socket.reset();
			this._attachToSocket(socket, key);
			this.sockets[key] = socket;
		});

		client.once('secureConnect', () => {
			this.emit('secureConnection', client);
		});

		this.emit('connection', client);
	}

	_endSockets() {
		if (this.dgramSocket) {
			this.dgramSocket.removeListener('message', this._onMessage);
		}
		const sockets = Object.keys(this.sockets);
		sockets.forEach(skey => {
			const s = this.sockets[skey];
			if (s) {
				s.end();
			}
		});

		if (sockets.length === 0) {
			this._closeSocket();
		}
	}

	_socketClosed() {
		this.listening = false;
		if (this.dgramSocket) {
			this.dgramSocket.removeListener('message', this._onMessage);
		}
		this.dgramSocket = null;
		this._endSockets();
		this.sockets = {};

		this.emit('close');
		this.removeAllListeners();
	}

	_closeSocket() {
		if (!this.listening) {
			process.nextTick(() => {
				this._socketClosed();
			});
			return;
		}

		if (this.dgramSocket) {
			this.dgramSocket.close();
		}
	}
}

module.exports = DtlsServer;
