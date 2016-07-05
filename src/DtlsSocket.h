#ifndef __DTLS_SOCKET_H__
#define __DTLS_SOCKET_H__

#include <node.h>
#include <nan.h>

#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"
#include "mbedtls/timing.h"

#include "DtlsServer.h"
#include "SessionWrap.h"

class DtlsSocket : public Nan::ObjectWrap {
public:
  static Nan::Persistent<v8::FunctionTemplate> constructor;
  static void Initialize(Nan::ADDON_REGISTER_FUNCTION_ARGS_TYPE target);
  static void New(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void ReceiveDataFromNode(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void Close(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void Send(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void ResumeSession(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void Renegotiate(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static NAN_GETTER(GetPublicKey);
  static NAN_GETTER(GetPublicKeyPEM);
  static NAN_GETTER(GetOutCounter);
  static NAN_GETTER(GetSession);
  DtlsSocket(DtlsServer *server,
             unsigned char *client_ip,
             size_t client_ip_len,
             Nan::Callback* send_callback,
             Nan::Callback* hs_callback,
             Nan::Callback* error_callback,
             Nan::Callback* resume_sess_callback);
  int send_encrypted(const unsigned char *buf, size_t len);
  int recv(unsigned char *buf, size_t len);
  int send(const unsigned char *buf, size_t len);
  int receive_data(unsigned char *buf, int len);
  int step();
  void store_data(const unsigned char *buf, size_t len);
  int close();
  void error(int ret);
  void reset();
  void get_session_cache(mbedtls_ssl_session *session);
  void renegotiate(SessionWrap *sess);
  bool resume(SessionWrap *sess);
  void proceed();

private:
  void throwError(int ret);
  ~DtlsSocket();
  Nan::Callback* send_cb;
  Nan::Callback* error_cb;
  Nan::Callback* handshake_cb;
  Nan::Callback* resume_sess_cb;
  mbedtls_ssl_context ssl_context;
  mbedtls_timing_delay_context timer;
  mbedtls_ssl_config* ssl_config;
  const unsigned char *recv_buf;
  size_t recv_len;
  unsigned char *ip;
  size_t ip_len;

  bool session_wait;
  uint8_t random[64];
};

#endif
