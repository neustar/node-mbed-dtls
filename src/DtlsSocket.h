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
	static void New(const Nan::FunctionCallbackInfo<v8::Value>& info);
	static void ReceiveDataFromNode(const Nan::FunctionCallbackInfo<v8::Value>& info);
	static void Close(const Nan::FunctionCallbackInfo<v8::Value>& info);
	static void Send(const Nan::FunctionCallbackInfo<v8::Value>& info);
	DtlsSocket(DtlsServer *server,
						 unsigned char *client_ip,
						 size_t client_ip_len,
						 Nan::Callback* send_callback,
						 Nan::Callback* hs_callback,
						 Nan::Callback* error_callback);
	int send_encrypted(const unsigned char *buf, size_t len);
	int recv(unsigned char *buf, size_t len);
	int send(const unsigned char *buf, size_t len);
	int receive_data(unsigned char *buf, int len);
	void store_data(const unsigned char *buf, size_t len);
	void close();
	void error(int ret);
	void reset();

private:
	void throwError(int ret);
	~DtlsSocket();
	Nan::Callback* send_cb;
	Nan::Callback* error_cb;
	Nan::Callback* handshake_cb;
	mbedtls_ssl_context ssl_context;
	mbedtls_timing_delay_context timer;
	mbedtls_ssl_config* ssl_config;
	const unsigned char *recv_buf;
	size_t recv_len;	
	unsigned char *ip;
	size_t ip_len;
};

#endif