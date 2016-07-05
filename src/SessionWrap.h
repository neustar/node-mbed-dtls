#ifndef __SESSION_WRAP_H__
#define __SESSION_WRAP_H__

#include <node.h>
#include <nan.h>

#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"

class SessionWrap : public Nan::ObjectWrap {
public:
  static void Initialize(Nan::ADDON_REGISTER_FUNCTION_ARGS_TYPE target);
  static v8::Local<v8::Object> CreateFromContext(mbedtls_ssl_context *ssl, uint8_t *random);
  static void Restore(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static NAN_GETTER(GetCiphersuite);
  static NAN_GETTER(GetRandomBytes);
  static NAN_GETTER(GetId);
  static NAN_GETTER(GetMaster);
  static NAN_GETTER(GetInEpoch);
  static NAN_GETTER(GetOutCounter);

  static NAN_SETTER(SetCiphersuite);
  static NAN_SETTER(SetRandomBytes);
  static NAN_SETTER(SetId);
  static NAN_SETTER(SetMaster);
  static NAN_SETTER(SetInEpoch);
  static NAN_SETTER(SetOutCounter);
  SessionWrap();

  int ciphersuite;
  unsigned char id[32];
  size_t id_len;
  unsigned char master[48];
  uint8_t randbytes[64];
  uint16_t in_epoch;
  unsigned char out_ctr[8];

private:
  ~SessionWrap();

  static void New(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static Nan::Persistent<v8::FunctionTemplate> constructor;

};

#endif
