
#include "DtlsServer.h"
#include "DtlsSocket.h"

NAN_MODULE_INIT(init) {
	DtlsServer::Initialize(target);
	DtlsSocket::Initialize(target);
}

NODE_MODULE(node_mbed_dtls, init);
