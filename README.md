## node-mbed-dtls
================

node DTLS (server and client) wrapping [mbedtls](https://github.com/ARMmbed/mbedtls).

#### Lineage
This package was forked from [Spark's original server implementation](https://github.com/spark/node-mbed-dtls) and merged with [their client implementation](https://github.com/spark/node-mbed-dtls-client).

#### Changes made to the fork:
The wrapped library is now pulled directly from ARMmbed's repo, rather than Spark's. The ciphersuites and API have been extended to allow PSK and CA certificates to be loaded at runtime, and on a per-instance basis.

--------------

## DTLS Client API:

Here is the scope of possible options, along with their default values.

    const options = {
      host:          'localhost',  // The target address or hostname.
      port:          5684,         // The target UDP port.
      socket:        undefined,    // An already established socket, if you'd rather spin your own.
      key:           undefined,    // DER format in a buffer. Our private key.
      peerPublicKey: undefined,    // DER format in a buffer. The server's public key, if applicable.
      psk:           undefined,    // Buffer. Pre-shared Symmetric Key, if applicable.
      PSKIdent:      undefined,    // Buffer. PSK Identity, if applicable.
      CACert:        undefined,    // DER format in a buffer. CA public key, if applicable.
      debug:         0             // How chatty is the library? Larger values generate more log.
    };

The cryptographic parameters will likely change in the future as options are added for...
  * TODO: Ciphersuite limitation/selection
  * TODO: Uniform key/id interface
  * TODO: Conditional validation
  * TODO: Capability discovery

#### A client connection might emit...

**error** when the connection has a problem.

    // err: Error code.
    // msg: Optional error string.
    client.on('error', (err, msg) => {});


**close** when the socket closes.

    //hadError:  A boolean. Did the socket close because of an error?
    client.on('close', (hadError) => {});


**secureConnect** when we successfully establish a connection. This will only occur once for any given client.

    // socket:  A connection socket, ready for data.
    client.on('secureConnect', (socket) => {});


--------------

## DTLS Server API:
Here is the scope of possible server options, along with their default values.

    const options = {
      key:                 null,   // Our server's private key. DER format in a Buffer.
      handshakeTimeoutMin: 3000,   // How many milliseconds can a handshake subtend before being dropped?
      debug:               0       // How chatty is the library? Larger values generate more log.
    };


#### General server emits....

**error** when the server has a problem.

    // err: Error string/code.
    server.on('error', (err) => {});


**close** when the server stops listening.

    // No arguments to callback.
    server.on('error', (err) => {});


**listening** when the server setup completes without problems.

    // No arguments to callback.
    server.on('listening', () => {});


#### Emits related to client handling...

**lookupKey** TODO: Doc forthcoming.

**resumeSession** TODO: Doc forthcoming.

**secureConnection** when a client successfully establishes a connection. This will only occur once for any unique client.

    // client:   The client socket
    // session:  The session identifier
    server.on('secureConnection', (client, session) => {});


**connection** each time a client connects. This is not the same thing as session-establishment (See: secureConnection).

    // client: The client socket that connected.
    server.on('connection', (client) => {});


**clientError** when a client socket experiences a problem.

    // err:    Error string/code.
    // client: The client socket that had the problem.
    server.on('error', (err, client) => {});

