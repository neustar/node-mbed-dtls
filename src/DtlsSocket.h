#ifndef __DTLS_SOCKET_H__
#define __DTLS_SOCKET_H__

#include <node.h>
#include <nan.h>

#include "mbedtls/ssl.h"
#include "mbedtls/timing.h"

#include "DtlsServer.h"

class DtlsSocket : public Nan::ObjectWrap {
public:
	static Nan::Persistent<v8::FunctionTemplate> constructor;
	static void Initialize(Nan::ADDON_REGISTER_FUNCTION_ARGS_TYPE target);
	static NAN_METHOD(New);
	static NAN_METHOD(ReceiveDataFromNode);
	static NAN_METHOD(Close);
	static NAN_METHOD(Send);
	DtlsSocket(DtlsServer *server, unsigned char *client_ip, size_t client_ip_len, Nan::Callback* callback);
	int send_encrypted(const unsigned char *buf, size_t len);
	int recv(unsigned char *buf, size_t len);
	int send(const unsigned char *buf, size_t len);
	int receive_data(unsigned char *buf, int len);
	void store_data(const unsigned char *buf, size_t len);
	void close();

private:
	~DtlsSocket();
	Nan::Callback* send_cb;
	mbedtls_ssl_context ssl_context;
	mbedtls_timing_delay_context timer;

	mbedtls_ssl_config* ssl_config;
	const unsigned char *recv_buf;
	size_t recv_len;


};

#endif