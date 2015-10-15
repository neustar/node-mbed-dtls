
#include "DtlsServer.h"
#include "DtlsSocket.h"
#include "SessionWrap.h"

NAN_MODULE_INIT(init) {
	DtlsServer::Initialize(target);
	DtlsSocket::Initialize(target);
	SessionWrap::Initialize(target);
}

NODE_MODULE(node_mbed_dtls, init);
