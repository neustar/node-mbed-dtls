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
    this._sendClose = true;
    const key = `${address}:${port}`;

    this.mbedSocket = new mbed.DtlsSocket(server.mbedServer, key,
      this._sendEncrypted.bind(this),
      this._handshakeComplete.bind(this),
      this._error.bind(this),
      this._renegotiate.bind(this));

    this.send = function(msg, offset, length, port, host, callback) {
      this.mbedSocket.send(msg);
    }
  }

  get publicKey() {
    return this.mbedSocket.publicKey || new Buffer(0);
  }
  get publicKeyPEM() {
    return this.mbedSocket.publicKeyPEM || new Buffer(0);
  }
  get outCounter() {
    return this.mbedSocket.outCounter;
  }
  get session() {
    return this.mbedSocket.session;
  }

  get sendClose() {
    return this._sendClose;
  }
  set sendClose(value) {
    this._sendClose = value;
  }

  resumeSession(session) {
    if (!session || !this.mbedSocket) {
      return false;
    }

    const s = new mbed.SessionWrap();
    s.restore(session);

    const success = this.mbedSocket.resumeSession(s);
    if (success) {
      this.connected = true;
      this.resumed = true;
    }
    return success;
  }

  _read() {
    // TODO implement way to stop/start reading?
    // do nothing since chunk pushing is async
  }

  /*
   * For the sake of parity with node datagram API...
   */
//  send(msg, offset, length, port, host, callback) {
//    _sendEncrypted(msg, 0, callback);
//  }

  _write(chunk, encoding, callback) {
    console.log("Srv instance socket send.\n");
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

    this.emit('send', msg.length);
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

  _renegotiate(sessionId) {
    const done = this._renegotiateCallback.bind(this);
    if (!this.server.emit('renegotiate', sessionId.toString('hex'), this, done)) {
      process.nextTick(done);
    }
  }

  _renegotiateCallback(err, data) {
    if (err) {
      this._end();
      return;
    }

    let s;
    if (data) {
      s = new mbed.SessionWrap();
      s.restore(data);
    }
    this.mbedSocket.renegotiate(s || undefined);
    this.resumed = true;
  }

  receive(msg) {
    if (!this.mbedSocket) {
      return false;
    }
    if (msg && msg.length < 4) {
      return false;
    }

    this.emit('receive', (msg && msg.length) || 0);
    const data = this.mbedSocket.receiveData(msg);
    if (data) {
      this.push(data);
      return true;
    }
    return false;
  }

  end() {
    this._clientEnd = true;
    this._end();
  }

  reset() {
    this.emit('close', false);
    this.removeAllListeners();
    this.resumed = false;
    this.connected = false;
  }

  _end() {
    if (this._ending) {
      return;
    }
    this._ending = true;

    super.end();
    this.push(null);
    const noSend = !this._sendClose || this.mbedSocket.close();
    this.emit('closing');
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
