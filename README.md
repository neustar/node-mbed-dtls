# node-mbed-dtls
node DTLS (server and client) wrapping [mbedtls](https://github.com/ARMmbed/mbedtls)

###Lineage
This package was forked from [Spark's original server implementation](https://github.com/spark/node-mbed-dtls) and merged with [their client implementation](https://github.com/spark/node-mbed-dtls-client).

###Changes made to the fork:
The wrapped library is now pulled directly from ARMmbed's repo, rather than Spark's. The ciphersuites and API have been extended to allow PSK and CA certificates to be loaded at runtime, and on a per-instance basis.


###Client API
Connection as a client is straight-forward. See examples/client_echo.js for a working example.

