'use strict';

var dgram = require('dgram');
var fs = require('fs');
var EventEmitter = require('events').EventEmitter;

var mbed = require('./build/Release/node_mbed_dtls');

class DtlsSocket extends EventEmitter {
	constructor(server, address, port) {
		super();
		this.dgramSocket = server.dgramSocket;
		this.address = address;
		this.port = port;

		this.mbedSocket = new mbed.DtlsSocket(server.mbedServer, address, this._sendEncrypted);
	}

	send(msg) {
		this.mbedSocket.send(msg);
	}

	_sendEncrypted(msg) {
		this.dgramSocket.send(msg, 0, msg.length, this.port, this.address);
	}

	_receive(msg) {
		const data = this.mbedSocket.receiveData(msg);
		if (data) {
			this.emit('message', data);
		}
	}
}

class DtlsServer extends EventEmitter {
	constructor(options) {
		super();
		this.sockets = {};
		this.dgramSocket = dgram.createSocket('udp4');

		this.dgramSocket.on('message', this._onMessage);
		//this.dgram.on('error');

		const key = Buffer.isBuffer(options.key) ? options.key : fs.readFileSync(options.key);
		const cert = Buffer.isBuffer(options.cert) ? options.cert : fs.readFileSync(options.cert);

		this.mbedServer = new mbed.DtlsServer(key, cert);
	}

	listen(port, hostname, callback) {
		this.dgramSocket.bind(port, hostname, () => {
			callback();
		});
	}

	_onMessage(msg, rinfo) {
		const key = `${rinfo.address}:${rinfo.port}`;

		let client = this.sockets[key];
		if (!client) {
			this.sockets[key] = client = new DtlsSocket(this, rinfo.address, rinfo.port);
			this.emit('secureConnection', client);
		}

		client.receive(msg);
	}
}



function createServer(options, secureConnectionListener) {
	options = options || {};
	const server = new DtlsServer(options);

	if (secureConnectionListener) {
		server.on('secureConnection', secureConnectionListener);
	}

	return server;
}

var opts = {
	key: 'test/server.key',
	cert: 'test/server-ca.der'
};

createServer(opts, function (socket) {
	console.log(socket);
});
