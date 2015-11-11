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