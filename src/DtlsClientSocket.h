#ifndef __DTLS_CLI_SOCKET_H__
#define __DTLS_CLI_SOCKET_H__

#include <node.h>
#include <nan.h>

#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/timing.h"
#include "mbedtls/debug.h"

#define MAX_CIPHERSUITE_COUNT  30  // Number is arbitrary. Should be enough.

class DtlsClientSocket : public Nan::ObjectWrap {
public:
  static Nan::Persistent<v8::FunctionTemplate> constructor;
  static void Initialize(Nan::ADDON_REGISTER_FUNCTION_ARGS_TYPE target);
  static void New(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void ReceiveDataFromNode(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void Close(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void Send(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void Connect(const Nan::FunctionCallbackInfo<v8::Value>& info);
  DtlsClientSocket(
             const unsigned char *priv_key,     size_t priv_key_len,
             const unsigned char *peer_pub_key, size_t peer_pub_key_len,
             const unsigned char *ca_pem,       size_t ca_pem_len,
             const unsigned char *psk,          size_t psk_len,
             const unsigned char *ident,        size_t ident_len,
             Nan::Callback* send_callback,
             Nan::Callback* hs_callback,
             Nan::Callback* error_callback,
             int debug_level);
  int recv(unsigned char *buf, size_t len);
  int receive_data(unsigned char *buf, int len);
  int send_encrypted(const unsigned char *buf, size_t len);
  int send(const unsigned char *buf, size_t len);
  int step();
  int close();
  void store_data(const unsigned char *buf, size_t len);
  void error(int ret);

private:
  void throwError(int ret);
  ~DtlsClientSocket();

  int allowed_ciphersuites[MAX_CIPHERSUITE_COUNT];
  Nan::Callback* send_cb;
  Nan::Callback* error_cb;
  Nan::Callback* handshake_cb;
  mbedtls_ssl_context ssl_context;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ssl_config conf;
  mbedtls_x509_crt clicert;
  mbedtls_x509_crt cacert;
  mbedtls_pk_context pkey;
  mbedtls_timing_delay_context timer;
  const unsigned char *recv_buf;
  size_t recv_len;
};

#endif
