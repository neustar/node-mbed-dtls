
#include "DtlsSocket.h"

#include <stdlib.h>

#include "mbedtls/ssl_internal.h"

using namespace node;

Nan::Persistent<v8::FunctionTemplate> DtlsSocket::constructor;

void
DtlsSocket::Initialize(Nan::ADDON_REGISTER_FUNCTION_ARGS_TYPE target) {
	Nan::HandleScope scope;

	// Constructor
	v8::Local<v8::FunctionTemplate> ctor = Nan::New<v8::FunctionTemplate>(DtlsSocket::New);
	constructor.Reset(ctor);
	ctor->InstanceTemplate()->SetInternalFieldCount(1);
	ctor->SetClassName(Nan::New("DtlsSocket").ToLocalChecked());
	
	Nan::SetPrototypeMethod(ctor, "receiveData", ReceiveDataFromNode);
	Nan::SetPrototypeMethod(ctor, "close", Close);
	Nan::SetPrototypeMethod(ctor, "send", Send);

	Nan::Set(target, Nan::New("DtlsSocket").ToLocalChecked(), ctor->GetFunction());
}

void DtlsSocket::New(const Nan::FunctionCallbackInfo<v8::Value>& info) {
	if (info.Length() < 5) {
		return Nan::ThrowTypeError("DtlsSocket requires five arguments");
	}

	// TODO check arguments types

	DtlsServer *server = Nan::ObjectWrap::Unwrap<DtlsServer>(Nan::To<v8::Object>(info[0]).ToLocalChecked());
	Nan::Utf8String client_ip(info[1]);

	Nan::Callback* send_cb = new Nan::Callback(info[2].As<v8::Function>());
	Nan::Callback* hs_cb = new Nan::Callback(info[3].As<v8::Function>());
	Nan::Callback* error_cb = new Nan::Callback(info[4].As<v8::Function>());

	DtlsSocket *socket = new DtlsSocket(server,
																			(unsigned char *)*client_ip,
																			client_ip.length(),
																			send_cb,
																			hs_cb,
																			error_cb);
	socket->Wrap(info.This());
	info.GetReturnValue().Set(info.This());
}

void DtlsSocket::ReceiveDataFromNode(const Nan::FunctionCallbackInfo<v8::Value>& info) {
	DtlsSocket *socket = Nan::ObjectWrap::Unwrap<DtlsSocket>(info.This());
	const unsigned char *recv_data = (const unsigned char *)Buffer::Data(info[0]);
	socket->store_data(recv_data, Buffer::Length(info[0]));

	int len = 1024;
	unsigned char buf[len];	
	len = socket->receive_data(buf, len);

	if (len > 0) {
		info.GetReturnValue().Set(Nan::CopyBuffer((char*)buf, len).ToLocalChecked());
	}
}

void DtlsSocket::Close(const Nan::FunctionCallbackInfo<v8::Value>& info) {
	DtlsSocket *socket = Nan::ObjectWrap::Unwrap<DtlsSocket>(info.This());
	socket->close();
}

void DtlsSocket::Send(const Nan::FunctionCallbackInfo<v8::Value>& info) {
	DtlsSocket *socket = Nan::ObjectWrap::Unwrap<DtlsSocket>(info.This());
	
	const unsigned char *send_data = (const unsigned char *)Buffer::Data(info[0]);
	socket->send(send_data, Buffer::Length(info[0]));
}

int net_send( void *ctx, const unsigned char *buf, size_t len ) {
	DtlsSocket* socket = (DtlsSocket*)ctx;
	return socket->send_encrypted(buf, len);
}

int net_recv( void *ctx, unsigned char *buf, size_t len ) {
	DtlsSocket* socket = (DtlsSocket*)ctx;
	return socket->recv(buf, len);
}

DtlsSocket::DtlsSocket(DtlsServer *server,
											 unsigned char *client_ip,
											 size_t client_ip_len, 
											 Nan::Callback* send_callback,
											 Nan::Callback* hs_callback,
											 Nan::Callback* error_callback)
		: Nan::ObjectWrap(),
		send_cb(send_callback),
		error_cb(error_callback),
		handshake_cb(hs_callback) {
	int ret;

	if((ip = (unsigned char *)calloc(1, client_ip_len)) == NULL) {
		throwError(MBEDTLS_ERR_SSL_ALLOC_FAILED);
		return;
	}
	memcpy(ip, client_ip, client_ip_len);
	ip_len = client_ip_len;
	
	mbedtls_ssl_init(&ssl_context);
	ssl_config = server->config();

	if((ret = mbedtls_ssl_setup(&ssl_context, ssl_config)) != 0)
	{
		throwError(ret);
	}

	mbedtls_ssl_set_timer_cb(&ssl_context,
													 &timer,
													 mbedtls_timing_set_delay,
													 mbedtls_timing_get_delay);
	mbedtls_ssl_set_bio(&ssl_context, this, net_send, net_recv, NULL);
	mbedtls_ssl_session_reset(&ssl_context);

	/* For HelloVerifyRequest cookies */
	if((ret = mbedtls_ssl_set_client_transport_id(&ssl_context, ip, ip_len)) != 0)
	{
		throwError(ret);
		return;
	}
}

void DtlsSocket::reset() {
	int ret;
	mbedtls_ssl_session_reset(&ssl_context);

	/* For HelloVerifyRequest cookies */
	if((ret = mbedtls_ssl_set_client_transport_id(&ssl_context, ip, ip_len)) != 0)
	{
		return error(ret);
	}
}

int DtlsSocket::send_encrypted(const unsigned char *buf, size_t len) {
	v8::Local<v8::Value> argv[] = {
		Nan::CopyBuffer((char *)buf, len).ToLocalChecked()
	};
	send_cb->Call(1, argv);
	return len;
}

int DtlsSocket::recv(unsigned char *buf, size_t len) {
	if (recv_len != 0) {
		len = recv_len;
		memcpy(buf, recv_buf, recv_len);
		recv_buf = NULL;
		recv_len = 0;
		return len;
	}

	return MBEDTLS_ERR_SSL_WANT_READ;
}

int DtlsSocket::send(const unsigned char *buf, size_t len) {
	int ret;
	ret = mbedtls_ssl_write(&ssl_context, buf, len);
	if (ret < 0)
	{
		error(ret);
		return ret;
	}
	len = ret;
	return ret;
}

int DtlsSocket::receive_data(unsigned char *buf, int len) {
	int ret;

	if (ssl_context.state == MBEDTLS_SSL_HANDSHAKE_OVER) {
		// normal reading of unencrypted data	
		memset(buf, 0, len);
		ret = mbedtls_ssl_read(&ssl_context, buf, len);
		if (ret <= 0) {
			error(ret);
			return 0;
		}
		return ret;
	}

	// handshake
	while (ssl_context.state != MBEDTLS_SSL_HANDSHAKE_OVER) {
		ret = mbedtls_ssl_handshake_step(&ssl_context);
		if (ret == 0) {			
			// in these states we are waiting for more input
			if (
				ssl_context.state == MBEDTLS_SSL_SERVER_HELLO_VERIFY_REQUEST_SENT ||
				ssl_context.state == MBEDTLS_SSL_CLIENT_CERTIFICATE ||
				ssl_context.state == MBEDTLS_SSL_CLIENT_KEY_EXCHANGE ||
				ssl_context.state == MBEDTLS_SSL_CERTIFICATE_VERIFY ||
				ssl_context.state == MBEDTLS_SSL_CLIENT_CHANGE_CIPHER_SPEC ||
				ssl_context.state == MBEDTLS_SSL_CLIENT_FINISHED
				) {
				return 0;
			}
			// keep looping to send everything
			continue;
		} else if (ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED) {
			// client will start a new session, so reset things
			reset();
			continue;
		}
		else if (ret != 0) {
			// bad things
			error(ret);			
			return 0;
		}
	}

	// this should only be called once when we first finish the handshake
	handshake_cb->Call(0, NULL);
	return 0;
}

void DtlsSocket::throwError(int ret) {
	char error_buf[100];
	mbedtls_strerror(ret, error_buf, 100);
	Nan::ThrowError(error_buf);
}

void DtlsSocket::error(int ret) {
	char error_buf[100];
	mbedtls_strerror(ret, error_buf, 100);
	v8::Local<v8::Value> argv[] = {
		Nan::New(ret),
		Nan::New(error_buf).ToLocalChecked()
	};
	error_cb->Call(2, argv);
}

void DtlsSocket::store_data(const unsigned char *buf, size_t len) {
	recv_buf = buf;
	recv_len = len;
}

void DtlsSocket::close() {
	mbedtls_ssl_close_notify(&ssl_context);
}

DtlsSocket::~DtlsSocket() {
	send_cb = nullptr;
	error_cb = nullptr;
	handshake_cb = nullptr;
	ssl_config = nullptr;
	free(ip);
	ip = nullptr;
	recv_buf = nullptr;
	mbedtls_ssl_free(&ssl_context);
}
