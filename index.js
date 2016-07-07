'use strict';

// NOTE: Because this is not automatically derived from the library's compiled-in
//         support, care must be taken to ensure that the desired ciphersuite is
//         *actually* supported, or else you will chase your tail.
//       The idea here is to make an enum that can be chosen from JS and have the
//         choice reflected in the allowed_ciphersuites array in the native code.
const supported_ciphersuites = Object.freeze({
  TLS_PSK_WITH_AES_128_CCM_8:                0xC0A8,
  TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256:     0xC037,
  TLS_PSK_WITH_AES_128_CBC_SHA256:           0xAE
});

var DtlsServer = require('./server');
const DtlsClientSocket = require('./client_socket');

function createServer(options, secureConnectionListener) {
  options = options || {};
  const server = new DtlsServer(options);

  if (secureConnectionListener) {
    server.on('secureConnection', secureConnectionListener);
  }

  return server;
}

function connect(options, callback) {
  const socket = new DtlsClientSocket(options);
  if (callback) {
    socket.once('secureConnect', callback);
  }

  return socket;
}


module.exports = { createServer, connect };
