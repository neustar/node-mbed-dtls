
#include "DtlsServer.h"

#include <stdio.h>
#include <sys/time.h>
#define mbedtls_printf     printf
#define mbedtls_fprintf    fprintf

using namespace node;

static void my_debug( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
  ((void) level);

  struct timeval tp;
  gettimeofday(&tp, NULL);
  long int ms = tp.tv_sec * 1000 + tp.tv_usec / 1000;

  mbedtls_fprintf((FILE *) ctx, "%013ld:%s:%04d: %s", ms, file, line, str);
  fflush((FILE *) ctx);
}


/*
 * Callback to get PSK given identity. Prevents us from having to hard-code
 *   authorized keys.
 */
int fetchPSKGivenID(void *parameter, mbedtls_ssl_context *ssl, const unsigned char *psk_identity, size_t identity_len) {
  //printf("PSK handler entry.\n");
  // Normally, the code below would be a shunt into an HSM, local key store,
  //   or some other means of storing keys securely.
  // We hard-code for the moment to test.
  if (0 == memcmp((const uint8_t*)psk_identity, (const uint8_t*)"32323232-3232-3232-3232-323232323232", identity_len)) {
    mbedtls_ssl_set_hs_psk(ssl, (const unsigned char*)"AAAAAAAAAAAAAAAA", 16);
    //printf("PSK handler departure with success.\n");
    return 0;
  }
  //printf("PSK handler departure with failure.\n");
  return 1;
}


Nan::Persistent<v8::FunctionTemplate> DtlsServer::constructor;

void DtlsServer::Initialize(Nan::ADDON_REGISTER_FUNCTION_ARGS_TYPE target) {
  Nan::HandleScope scope;

  // Constructor
  v8::Local<v8::FunctionTemplate> ctor = Nan::New<v8::FunctionTemplate>(DtlsServer::New);
  constructor.Reset(ctor);
  v8::Local<v8::ObjectTemplate>  ctorInst = ctor->InstanceTemplate();
  ctorInst->SetInternalFieldCount(1);
  ctor->SetClassName(Nan::New("DtlsServer").ToLocalChecked());

  Nan::SetAccessor(ctorInst, Nan::New("handshakeTimeoutMin").ToLocalChecked(), 0, SetHandshakeTimeoutMin);

  Nan::Set(target, Nan::New("DtlsServer").ToLocalChecked(), ctor->GetFunction());
}

void DtlsServer::New(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  if (info.Length() < 1 ||
      !Buffer::HasInstance(info[0])) {
    return Nan::ThrowTypeError("Expecting key to be a buffer");
  }

  size_t key_len = Buffer::Length(info[0]);

  const unsigned char *key = (const unsigned char *)Buffer::Data(info[0]);

  int debug_level = 0;
  if (info.Length() > 1) {
    debug_level = info[1]->Uint32Value();
  }

  DtlsServer *server = new DtlsServer(key, key_len, debug_level);
  server->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}



DtlsServer::DtlsServer(const unsigned char *srv_key,
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

  mbedtls_ssl_conf_psk_cb(&conf, fetchPSKGivenID, NULL);
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

#if defined(MBEDTLS_DEBUG_C)
  mbedtls_debug_set_threshold(debug_level);
#endif

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

  return;
exit:
  throwError(ret);
  return;
}

NAN_SETTER(DtlsServer::SetHandshakeTimeoutMin) {
  DtlsServer *server = Nan::ObjectWrap::Unwrap<DtlsServer>(info.This());
  mbedtls_ssl_conf_handshake_timeout(server->config(), value->Uint32Value(), server->config()->hs_timeout_max);
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
