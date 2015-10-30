
#include "DtlsServer.h"

#include <stdio.h>
#define mbedtls_printf     printf
#define mbedtls_fprintf    fprintf

using namespace node;

static void my_debug( void *ctx, int level,
											const char *file, int line,
											const char *str )
{
	((void) level);

	mbedtls_fprintf((FILE *) ctx, "%s:%04d: %s", file, line, str);
	fflush((FILE *) ctx);
}

Nan::Persistent<v8::FunctionTemplate> DtlsServer::constructor;

void
DtlsServer::Initialize(Nan::ADDON_REGISTER_FUNCTION_ARGS_TYPE target) {
	Nan::HandleScope scope;

	// Constructor
	v8::Local<v8::FunctionTemplate> ctor = Nan::New<v8::FunctionTemplate>(DtlsServer::New);
	constructor.Reset(ctor);
	ctor->InstanceTemplate()->SetInternalFieldCount(1);
	ctor->SetClassName(Nan::New("DtlsServer").ToLocalChecked());

	Nan::Set(target, Nan::New("DtlsServer").ToLocalChecked(), ctor->GetFunction());
}

void DtlsServer::New(const Nan::FunctionCallbackInfo<v8::Value>& info) {
	if (info.Length() < 2 ||
			!Buffer::HasInstance(info[0]) ||
			!Buffer::HasInstance(info[1])) {
		return Nan::ThrowTypeError("Expecting cert and key to be buffers");
	}

	size_t cert_len = Buffer::Length(info[0]);
	size_t key_len = Buffer::Length(info[1]);

	const unsigned char *cert = (const unsigned char *)Buffer::Data(info[0]);
	const unsigned char *key = (const unsigned char *)Buffer::Data(info[1]);

	int debug_level = 0;
	if (info.Length() > 2) {
		debug_level = info[2]->Uint32Value();
	}

	DtlsServer *server = new DtlsServer(cert, cert_len, key, key_len, debug_level);
	server->Wrap(info.This());
	info.GetReturnValue().Set(info.This());
}

DtlsServer::DtlsServer(const unsigned char *srv_crt,
											 size_t srv_crt_len,
											 const unsigned char *srv_key,
											 size_t srv_key_len,
											 int debug_level)
		: Nan::ObjectWrap() {
	int ret;
	const char *pers = "dtls_server";
	mbedtls_ssl_config_init(&conf);
	mbedtls_ssl_cookie_init(&cookie_ctx);
#if defined(MBEDTLS_SSL_CACHE_C)
	mbedtls_ssl_cache_init(&cache);
#endif
	mbedtls_x509_crt_init(&srvcert);
	mbedtls_pk_init(&pkey);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);

#if defined(MBEDTLS_DEBUG_C)
	mbedtls_debug_set_threshold(debug_level);
#endif

	ret = mbedtls_pk_parse_public_key(&pkey,
																		(const unsigned char *)srv_crt,
																		srv_crt_len);
	if (ret != 0) goto exit;
	
	ret = mbedtls_pk_parse_key(&pkey,
														 (const unsigned char *)srv_key,
														 srv_key_len,
														 NULL,
														 0);
	if (ret != 0) goto exit;

	// TODO re-use node entropy and randomness
	ret = mbedtls_ctr_drbg_seed(&ctr_drbg,
															mbedtls_entropy_func,
															&entropy,
															(const unsigned char *) pers,
															strlen(pers));
	if (ret != 0) goto exit;

	ret = mbedtls_ssl_config_defaults(&conf,
																		MBEDTLS_SSL_IS_SERVER,
																		MBEDTLS_SSL_TRANSPORT_DATAGRAM,
																		MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret != 0) goto exit;

	mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);

	// TODO use node random number generator?
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
	mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

#if defined(MBEDTLS_SSL_CACHE_C)
	// TODO need to add hooks for session get/set
	mbedtls_ssl_conf_session_cache(&conf,
																 &cache,
																 mbedtls_ssl_cache_get,
																 mbedtls_ssl_cache_set);
#endif

	ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey);
	if (ret != 0) goto exit;

	ret = mbedtls_ssl_cookie_setup(&cookie_ctx,
																 mbedtls_ctr_drbg_random,
																 &ctr_drbg);
	if (ret != 0) goto exit;

	mbedtls_ssl_conf_dtls_cookies(&conf,
																mbedtls_ssl_cookie_write,
																mbedtls_ssl_cookie_check, 
																&cookie_ctx);

	// needed for server to send CertificateRequest
	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);

	static int ssl_cert_types[] = { MBEDTLS_TLS_CERT_TYPE_RAW_PUBLIC_KEY, MBEDTLS_TLS_CERT_TYPE_NONE };
	mbedtls_ssl_conf_client_certificate_types(&conf, ssl_cert_types);
	mbedtls_ssl_conf_server_certificate_types(&conf, ssl_cert_types);

	// turn off server sending Certificate
	mbedtls_ssl_conf_certificate_send(&conf, MBEDTLS_SSL_SEND_CERTIFICATE_DISABLED);

	return;
exit:
	throwError(ret);
	return;
}

void DtlsServer::throwError(int ret) {
	char error_buf[100];
	mbedtls_strerror(ret, error_buf, 100);
	Nan::ThrowError(error_buf);
}

DtlsServer::~DtlsServer() {
	mbedtls_x509_crt_free( &srvcert );
	mbedtls_pk_free( &pkey );
	mbedtls_ssl_config_free( &conf );
	mbedtls_ssl_cookie_free( &cookie_ctx );
#if defined(MBEDTLS_SSL_CACHE_C)
	mbedtls_ssl_cache_free( &cache );
#endif
	mbedtls_ctr_drbg_free( &ctr_drbg );
	mbedtls_entropy_free( &entropy );
}
