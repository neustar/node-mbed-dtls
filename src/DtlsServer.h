#ifndef __DTLS_SERVER_H__
#define __DTLS_SERVER_H__

#include <node.h>
#include <nan.h>

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_cookie.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"

#if defined(MBEDTLS_SSL_CACHE_C)
#include "mbedtls/ssl_cache.h"
#endif

class DtlsServer : public Nan::ObjectWrap {
public:
	static Nan::Persistent<v8::FunctionTemplate> constructor;
	static void Initialize(Nan::ADDON_REGISTER_FUNCTION_ARGS_TYPE target);
	static void New(const Nan::FunctionCallbackInfo<v8::Value>& info);
	DtlsServer(const unsigned char *srv_crt,
						 size_t srv_crt_len,
						 const unsigned char *srv_key,
						 size_t srv_key_len,
						 int debug_level = 0);
	inline mbedtls_ssl_config* config() { return &conf; }

private:
	void throwError(int ret);
	~DtlsServer();

	mbedtls_ssl_cookie_ctx cookie_ctx;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ssl_config conf;
	mbedtls_x509_crt srvcert;
	mbedtls_pk_context pkey;
#if defined(MBEDTLS_SSL_CACHE_C)
	mbedtls_ssl_cache_context cache;
#endif

};

#endif