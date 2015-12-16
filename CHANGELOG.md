# 2.2.4

* Add options to turn on/off sending `close_notify` alerts

# 2.2.3

* Fix segfault caused by accessing SessionWrap variables directly

# 2.2.2

* Fix invalid access to `msg.length` on `socket.receive`

# 2.2.1

* Do not consider session resumed unless message is understood

# 2.2.0

* Add session resumption and renegotiation support

# 2.1.1

* Emit `connection` event when receiving first message from a source ip/port quartet.

# 2.1.0

* Handle client reconnecting on the same host/port quartet

# 2.0.4

* Add null terminating byte for PEM encoded keys

# 2.0.3

* Fix npm publish

# 2.0.2

* Increase max content to 768 bytes
* Add time information to debug output
* Add setter for `handshakeTimeoutMin`

# 2.0.1

* Fix `debug` argument
* Remove test certs

# 2.0.0

* Remove public key as an argument because it can be derived from the private key

# 1.3.6

* Update mbedtls that queues Finished messages in more states for a server
* Handle socket binding errors
* Remove special state checking code

# 1.3.5

* Update mbedtls that plays nice with GCC

# 1.3.4

* Return `int` from `DtlsSocket::close` that indicates when a close alert will not be sent.
* Use direct form of callbacks from C++

# 1.3.3

* Fix send callback handling to prevent deadlock

# 1.3.2

* Fix `publicKeyPEM` property

# 1.3.1

* Update mbedtls to fix queueing corner cases

# 1.3.0

* Update mbedtls that queues out-of-sequence handshake messages and has better raw public key support.

# 1.2.1

* Allow sockets a chance to send closing alerts on server close

# 1.2.0

* change `DtlsSocket` into a `stream.Duplex`

# 1.1.1

* add `publicKeyPEM` on the socket to retrieve the public key in PEM format.

# 1.1.0

* change `socket.address` and `socket.port` to `socket.remoteAddress` and `socket.remotePort`

# 1.0.0

* Initial release