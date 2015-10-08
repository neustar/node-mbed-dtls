
#include "DtlsSocket.h"

#include <stdio.h>
#include <stdlib.h>

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

NAN_METHOD(DtlsSocket::New) {
	DtlsServer *server = Nan::ObjectWrap::Unwrap<DtlsServer>(Nan::To<v8::Object>(info[0]).ToLocalChecked());
	Nan::Utf8String client_ip(info[1]);

	Nan::Callback* cb = new Nan::Callback(info[2].As<v8::Function>());

	DtlsSocket *socket = new DtlsSocket(server, (unsigned char *)*client_ip, client_ip.length(), cb);
  socket->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(DtlsSocket::ReceiveDataFromNode) {
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

NAN_METHOD(DtlsSocket::Close) {
	DtlsSocket *socket = Nan::ObjectWrap::Unwrap<DtlsSocket>(info.This());
	socket->close();
}

NAN_METHOD(DtlsSocket::Send) {
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

DtlsSocket::DtlsSocket(DtlsServer *server, unsigned char *client_ip, size_t client_ip_len, Nan::Callback* callback): Nan::ObjectWrap() {
	send_cb = callback;
	int ret;
	
	mbedtls_ssl_init(&ssl_context);
	ssl_config = server->config();

	if( ( ret = mbedtls_ssl_setup( &ssl_context, ssl_config ) ) != 0 )
  {
    printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
    goto exit;
  }

  mbedtls_ssl_set_timer_cb( &ssl_context, &timer, mbedtls_timing_set_delay, mbedtls_timing_get_delay );

  mbedtls_ssl_session_reset( &ssl_context );

  /* For HelloVerifyRequest cookies */
  if( ( ret = mbedtls_ssl_set_client_transport_id( &ssl_context,
                  client_ip, client_ip_len ) ) != 0 )
  {
      printf( " failed\n  ! "
              "mbedtls_ssl_set_client_transport_id() returned -0x%x\n\n", -ret );
      goto exit;
  }

  mbedtls_ssl_set_bio( &ssl_context, this,
                       net_send, net_recv, NULL );
exit:
	return;
}

int DtlsSocket::send_encrypted(const unsigned char *buf, size_t len) {
	v8::Local<v8::Value> argv[] = {
		Nan::NewBuffer((char *)buf, len).ToLocalChecked()
	};
	send_cb->Call(1, argv);
	return 0;
}

int DtlsSocket::recv(unsigned char *buf, size_t len) {
	if (len <= recv_len) {
		memcpy(buf, recv_buf, len);
		recv_buf = NULL;
		recv_len = 0;
		return len;
	}

	return MBEDTLS_ERR_SSL_WANT_READ;
}

int DtlsSocket::send(const unsigned char *buf, size_t len) {
	int ret;
	ret = mbedtls_ssl_write( &ssl_context, buf, len );
	if( ret < 0 )
  {
    printf( " failed\n  ! mbedtls_ssl_write returned %d\n\n", ret );
    return ret;
  }
  len = ret;
  printf( " %d bytes written\n\n%s\n\n", (int)len, buf );  
  return ret;
}

int DtlsSocket::receive_data(unsigned char *buf, int len) {
	int ret;

	// handshake
	if (ssl_context.state != MBEDTLS_SSL_HANDSHAKE_OVER) {
		ret = mbedtls_ssl_handshake_step(&ssl_context);		

		if (ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED) {
			printf( " hello verification requested\n" );
	    ret = 0;
	    mbedtls_ssl_session_reset( &ssl_context );
	    // TODO this should really close down everything
		}
		else if (ret != 0) {
			// bad things
			printf( " failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret );
			mbedtls_ssl_session_reset( &ssl_context );
			// TODO this should really close down everything
		}

		return 0;
	}

	// normal reading of unencrypted data	
	memset( buf, 0, len );
	ret = mbedtls_ssl_read( &ssl_context, buf, len );
	if (ret <= 0) {
		printf( " mbedtls_ssl_read returned -0x%x\n\n", -ret );
    goto reset;
	}

reset:
	return ret;
}

void DtlsSocket::store_data(const unsigned char *buf, size_t len) {
	recv_buf = buf;
	recv_len = len;
}

void DtlsSocket::close() {
	mbedtls_ssl_close_notify( &ssl_context );
}

DtlsSocket::~DtlsSocket() {
	mbedtls_ssl_free( &ssl_context );
}
