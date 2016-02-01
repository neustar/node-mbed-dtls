# 2.4.4

* Add some debug loggin

# 2.4.3

* Fix copy-pasta bug

# 2.4.2

* Only handle as an IP change if the IP actually changed.

# 2.4.1

* Remove debug code.

# 2.4.0

* Handle DTLS packets with content type of 254 as IP change packets.

# 2.3.4

* Fix `getConnections` callback.

# 2.3.3

* Set `selfRestored` property on socket instead of passing through events.

# 2.3.2

* Include flag in `secureConnection` event indicating the connection was self restored.

# 2.3.1

* Guard `resumeSession` by checking for `mbedSocket`.

# 2.3.0

* Add `resumeSocket` method to server. This allows socket resumption without needing to receive a message.

# 2.2.9

* Properly unset flags on reset

# 2.2.8

* Allow undefined buffer receive calls

# 2.2.7

* Check for valid receive buffer

# 2.2.6

* Filter obviously invalid packets based on size

# 2.2.5

* Don't send alerts on any invalid MAC

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