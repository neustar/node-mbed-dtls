'use strict';

var DtlsServer = require('./server');
const DtlsSocket = require('./socket');

function createServer(options, secureConnectionListener) {
	options = options || {};
	const server = new DtlsServer(options);

	if (secureConnectionListener) {
		server.on('secureConnection', secureConnectionListener);
	}

	return server;
}

function connect(options, callback) {
  const socket = new DtlsSocket(options);
  if (callback) {
    socket.once('secureConnect', callback);
  }

  return socket;
}


module.exports = { createServer, connect };
