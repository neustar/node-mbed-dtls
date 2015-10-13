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

		this.dgramSocket.on('message', this._onMessage);
		this.dgramSocket.once('listening', () => {
			this.emit('listening');
		});
		this.dgramSocket.once('error', err => {
			this.emit('error', err);
			this.close();
		});
		this.dgramSocket.once('close', () => {
			this._close();
		});

		const cert = Buffer.isBuffer(options.cert) ? options.cert : fs.readFileSync(options.cert);
		const key = Buffer.isBuffer(options.key) ? options.key : fs.readFileSync(options.key);

		this.mbedServer = new mbed.DtlsServer(cert, key, options.debug);
	}

	listen(port, hostname, callback) {
		this.dgramSocket.bind(port, hostname, callback);
	}

	close(callback) {
		if (callback) {
			this.once('close', callback);
		}
		this.dgramSocket.close();
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
		});

		client.once('secureConnect', () => {
			this.emit('secureConnection', client);
		});
		return client;
	}

	_close() {
		this.dgramSocket.removeListener('message', this._onMessage);
		Object.keys(this.sockets).forEach(skey => {
			const s = this.sockets[skey];
			if (s) {
				s.close();
			}
		});
		this.sockets = {};

		this.emit('close');
		this.removeAllListeners();
	}
}

// TODO newSession and resumeSession events

module.exports = DtlsServer;
