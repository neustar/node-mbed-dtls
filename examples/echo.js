'use strict';

var path = require('path');
var dtls = require('../index');

const opts = {
  key: path.join(__dirname, '../test/private.der'),
  debug: 4,
  handshakeTimeoutMin: 3000
};

const dtlsserver = dtls.createServer(opts, socket => {
  console.log(`secure connection from ${socket.remoteAddress}:${socket.remotePort}`);
  socket.on('data', msg => {
    //console.log('received:', msg.toString('utf8'));
    socket.write(msg);
    if (msg.toString('utf8').indexOf('close') === 0) {
      console.log('closing');
      dtlsserver.close();
    }
  });
  socket.once('error', (err) => {
    console.error(`socket error on ${socket.remoteAddress}:${socket.remotePort}: ${err}`);
  });
  socket.once('close', () => {
    console.log(`closing socket from ${socket.remoteAddress}:${socket.remotePort}`);
  });
});

dtlsserver.on('clientError', err => {
  console.error(`clientError: ${err}`);
});

dtlsserver.on('error', err => {
  console.error(`server error: ${err}`);
});

dtlsserver.on('listening', () => {
  const addr = dtlsserver.address();
  console.log(`dtls listening on ${addr.address}:${addr.port}`);
});

// TODO: Not yet supported
//dtlsserver.on('newSession', (sessionId, sessionData, callback) => {
//  console.log('*** new session callback ***', sessionId);
//  process.nextTick(() => {
//    callback();
//  });
//});

dtlsserver.on('resumeSession', (sessionId, callback) => {
  console.log('*** resume session callback ***', sessionId);
  process.nextTick(() => {
    callback(null, null);
  });
});


dtlsserver.listen(5684);  // Actually begin listening.
