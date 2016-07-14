'use strict';

var dgram = require('dgram');
var fs = require('fs');
var EventEmitter = require('events').EventEmitter;

var DtlsSocket = require('./socket');
var mbed = require('./build/Release/node_mbed_dtls');

const APPLICATION_DATA_CONTENT_TYPE = 23;
const IP_CHANGE_CONTENT_TYPE = 254;

class DtlsServer extends EventEmitter {
  constructor(options) {
    super();

    if(!options) options = {};  // Support no-parameter construction.

    this.options = Object.assign({
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
    process.nextTick(() => callback(numConnections));
  }

  resumeSocket(rinfo, session) {
    const key = `${rinfo.address}:${rinfo.port}`;
    let client = this.sockets[key];
    if (client) {
      return false;
    }

    this.sockets[key] = client = this._createSocket(rinfo, key, true);
    if (client.resumeSession(session)) {
      this.emit('secureConnection', client, session);
      return true;
    }
    return false;
  }

  _debug() {
    if (this.options.debug) {
      console.log(...arguments);
    }
  }

  _handleIpChange(msg, key, rinfo, deviceId) {
    const lookedUp = this.emit('lookupKey', deviceId, (err, oldRinfo) => {
      if (!err && oldRinfo) {
        // if the IP hasn't actually changed, handle normally
        if (rinfo.address === oldRinfo.address &&
            rinfo.port === oldRinfo.port) {
          this._debug(`ignoring ip change because address did not change ip=${key}, deviceID=${deviceId}`);
          this._onMessage(msg, rinfo);
          return;
        }

        this._onMessage(msg, oldRinfo, (client, received) => {
          // if the message went through OK
          if (received) {
            const oldKey = `${oldRinfo.address}:${oldRinfo.port}`;
            this._debug(`message successfully received, changing ip address fromip=${oldKey}, toip=${key}, deviceID=${deviceId}`);
            // change IP
            client.remoteAddress = rinfo.address;
            client.remotePort = rinfo.port;
            // move in lookup table
            this.sockets[key] = client;
            delete this.sockets[oldKey];
            // tell the world
            client.emit('ipChanged', oldRinfo);
          }
        });
      }
    });
    return lookedUp;
  }

  _attemptResume(client, msg, key, cb) {
    const lcb = cb || (() => {});
    const called = this.emit('resumeSession', key, client, (err, session) => {
      if (!err && session) {
        const resumed = client.resumeSession(session);
        if (resumed) {
          client.cork();

          const received = client.receive(msg);
          // callback before secureConnection so
          // IP can be changed
          lcb(client, received);
          if (received) {
            this.emit('secureConnection', client, session);
          }

          client.uncork();
          return;
        }
      }
      client.receive(msg);
      lcb(null, false);
    });

    // if somebody was listening, session will attempt to be resumed
    // do not process with receive until resume finishes
    return called;
  }

  _onMessage(msg, rinfo, cb) {
    const key = `${rinfo.address}:${rinfo.port}`;

    // special IP changed content type
    if (msg.length > 0 && msg[0] === IP_CHANGE_CONTENT_TYPE) {
      const idLen = msg[msg.length - 1];
      const idStartIndex = msg.length - idLen - 1;
      const deviceId = msg.slice(idStartIndex, idStartIndex + idLen).toString('hex').toLowerCase();

      // slice off id and length, return content type to ApplicationData
      msg = msg.slice(0, idStartIndex);
      msg[0] = APPLICATION_DATA_CONTENT_TYPE;

      this._debug(`received ip change ip=${key}, deviceID=${deviceId}`);
      if (this._handleIpChange(msg, key, rinfo, deviceId)) {
        return;
      }
    }

    let client = this.sockets[key];
    if (!client) {
      this.sockets[key] = client = this._createSocket(rinfo, key);

      if (msg.length > 0 && msg[0] === APPLICATION_DATA_CONTENT_TYPE) {
        if (this._attemptResume(client, msg, key, cb)) {
          return;
        }
      }
    }

    if (cb) {
      // we cork because we want the callback to happen
      // before the implications of the message do
      client.cork();
      const received = client.receive(msg);
      cb(client, received);
      client.uncork();
    } else {
      client.receive(msg);
    }
  }

  _createSocket(rinfo, key, selfRestored) {
    var client = new DtlsSocket(this, rinfo.address, rinfo.port);
    client.sendClose = this.options.sendClose;
    client.selfRestored = selfRestored;
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
