'use strict';

var dgram = require('dgram');
var fs = require('fs');
var EventEmitter = require('events').EventEmitter;

var DtlsSocket = require('./socket');
var mbed = require('./build/Release/node_mbed_dtls');

class DtlsServer extends EventEmitter {
	constructor(options) {
		super();
		options = options || {};

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

		const key = Buffer.isBuffer(options.key) ? options.key : fs.readFileSync(options.key);

		this.mbedServer = new mbed.DtlsServer(key, options.debug);
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

	_onMessage(msg, rinfo) {
		const key = `${rinfo.address}:${rinfo.port}`;

		let client = this.sockets[key];
		if (!client) {
			this.sockets[key] = client = this._createSocket(rinfo, key);
		}

		client.receive(msg);
	}

	_createSocket(rinfo, key) {
		var client = new DtlsSocket(this, rinfo.address, rinfo.port);
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

		client.once('secureConnect', () => {
			this.emit('secureConnection', client);
		});
		return client;
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

// TODO newSession and resumeSession events

module.exports = DtlsServer;
