'use strict';

var dgram = require('dgram');
var fs = require('fs');
var EventEmitter = require('events').EventEmitter;

var DtlsSocket = require('./socket');
var mbed = require('./build/Release/node_mbed_dtls');

class DtlsServer extends EventEmitter {
	constructor(options) {
		super();
		this.sockets = {};
		this.dgramSocket = dgram.createSocket('udp4');

		this.dgramSocket.on('message', this._onMessage.bind(this));
		this.dgramSocket.on('listening', () => {
			this.emit('listening');
		});
		this.dgramSocket.on('error', err => {
			console.error(err);
		});

		const cert = Buffer.isBuffer(options.cert) ? options.cert : fs.readFileSync(options.cert);
		const key = Buffer.isBuffer(options.key) ? options.key : fs.readFileSync(options.key);

		this.mbedServer = new mbed.DtlsServer(cert, key);
	}

	listen(port, hostname, callback) {
		this.dgramSocket.bind(port, hostname, callback);
	}

	_onMessage(msg, rinfo) {
		const key = `${rinfo.address}:${rinfo.port}`;
		//console.log('message from', key);

		let client = this.sockets[key];
		if (!client) {
			this.sockets[key] = client = new DtlsSocket(this, rinfo.address, rinfo.port);
			client.once('error', (code, err) => {
				console.error(code, err);
				delete this.sockets[key];
			});

			client.on('secureConnect', () => {
				this.emit('secureConnection', client);
			});
		}

		client.receive(msg);
	}
}

module.exports = DtlsServer;
