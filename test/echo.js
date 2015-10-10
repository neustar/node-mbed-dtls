'use strict';

var dtls = require('../index');

const opts = {
	cert: './public.der',
	key: './private.der'
};

const dtlsserver = dtls.createServer(opts, socket => {
	console.log('secure connection from', socket.address, socket.port);
	socket.on('message', msg => {
		console.log('received:', msg.toString('utf8'));
		socket.send(msg);
	});
});
dtlsserver.on('listening', () => {
	console.log('dtls listening');
});
dtlsserver.listen(5683);
