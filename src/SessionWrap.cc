#include "SessionWrap.h"

#include <stdlib.h>

using namespace node;

Nan::Persistent<v8::FunctionTemplate> SessionWrap::constructor;

void
SessionWrap::Initialize(Nan::ADDON_REGISTER_FUNCTION_ARGS_TYPE target) {
  Nan::HandleScope scope;

  // Constructor
  v8::Local<v8::FunctionTemplate> ctor = Nan::New<v8::FunctionTemplate>(SessionWrap::New);
  constructor.Reset(ctor);
  v8::Local<v8::ObjectTemplate>  ctorInst = ctor->InstanceTemplate();
  ctorInst->SetInternalFieldCount(1);
  ctor->SetClassName(Nan::New("SessionWrap").ToLocalChecked());

  Nan::SetPrototypeMethod(ctor, "restore", Restore);

  Nan::SetAccessor(ctorInst, Nan::New("ciphersuite").ToLocalChecked(), GetCiphersuite, SetCiphersuite);
  Nan::SetAccessor(ctorInst, Nan::New("randbytes").ToLocalChecked(), GetRandomBytes, SetRandomBytes);
  Nan::SetAccessor(ctorInst, Nan::New("id").ToLocalChecked(), GetId, SetId);
  Nan::SetAccessor(ctorInst, Nan::New("master").ToLocalChecked(), GetMaster, SetMaster);
  Nan::SetAccessor(ctorInst, Nan::New("in_epoch").ToLocalChecked(), GetInEpoch, SetInEpoch);
  Nan::SetAccessor(ctorInst, Nan::New("out_ctr").ToLocalChecked(), GetOutCounter, SetOutCounter);

  Nan::Set(target, Nan::New("SessionWrap").ToLocalChecked(), ctor->GetFunction());
}

void SessionWrap::New(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  SessionWrap *session = new SessionWrap();
  session->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

v8::Local<v8::Object> SessionWrap::CreateFromContext(mbedtls_ssl_context *ssl, uint8_t *random) {
  Nan::EscapableHandleScope scope;
  v8::Local<v8::Function> cons = Nan::GetFunction(Nan::New(constructor)).ToLocalChecked();

  const unsigned argc = 0;
  v8::Local<v8::Value> argv[argc] = {};
  v8::Local<v8::Object> instance = Nan::NewInstance(cons, argc, argv).ToLocalChecked();

  SessionWrap *news = Nan::ObjectWrap::Unwrap<SessionWrap>(instance);
  news->ciphersuite = ssl->session->ciphersuite;
  memcpy(news->randbytes, random, 64);
  memcpy(news->id, ssl->session->id, ssl->session->id_len);
  news->id_len = ssl->session->id_len;
  memcpy(news->master, ssl->session->master, 48);
  news->in_epoch = ssl->in_epoch;
  memcpy(news->out_ctr, ssl->out_ctr, 8);

  return scope.Escape(instance);
}

void SessionWrap::Restore(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  SessionWrap *session = Nan::ObjectWrap::Unwrap<SessionWrap>(info.This());

  v8::Local<v8::Object> object = info[0]->ToObject();
  session->ciphersuite = Nan::Get(object, Nan::New("ciphersuite").ToLocalChecked()).ToLocalChecked()->Uint32Value();

  v8::Local<v8::Object> rbv = Nan::Get(object, Nan::New("randbytes").ToLocalChecked()).ToLocalChecked()->ToObject();
  memcpy(session->randbytes, Buffer::Data(rbv), Buffer::Length(rbv));

  v8::Local<v8::Object> idv = Nan::Get(object, Nan::New("id").ToLocalChecked()).ToLocalChecked()->ToObject();
  memcpy(session->id, Buffer::Data(idv), Buffer::Length(idv));
  session->id_len = Buffer::Length(idv);

  v8::Local<v8::Object> masterv = Nan::Get(object, Nan::New("master").ToLocalChecked()).ToLocalChecked()->ToObject();
  memcpy(session->master, Buffer::Data(masterv), Buffer::Length(masterv));

  session->in_epoch = Nan::Get(object, Nan::New("in_epoch").ToLocalChecked()).ToLocalChecked()->Uint32Value();
  
  v8::Local<v8::Object> out_ctrv = Nan::Get(object, Nan::New("out_ctr").ToLocalChecked()).ToLocalChecked()->ToObject();
  memcpy(session->out_ctr, Buffer::Data(out_ctrv), Buffer::Length(out_ctrv));
}

NAN_GETTER(SessionWrap::GetCiphersuite) {
  SessionWrap *session = Nan::ObjectWrap::Unwrap<SessionWrap>(info.This());
  info.GetReturnValue().Set(Nan::New(session->ciphersuite));
}

NAN_SETTER(SessionWrap::SetCiphersuite) {
  SessionWrap *session = Nan::ObjectWrap::Unwrap<SessionWrap>(info.This());
  session->ciphersuite = value->Uint32Value();
}


NAN_GETTER(SessionWrap::GetRandomBytes) {
  SessionWrap *session = Nan::ObjectWrap::Unwrap<SessionWrap>(info.This());
  info.GetReturnValue().Set(Nan::CopyBuffer((char *)session->randbytes, 64).ToLocalChecked());
}

NAN_SETTER(SessionWrap::SetRandomBytes) {
  SessionWrap *session = Nan::ObjectWrap::Unwrap<SessionWrap>(info.This());
  memcpy(session->randbytes, Buffer::Data(value), Buffer::Length(value));
}


NAN_GETTER(SessionWrap::GetId) {
  SessionWrap *session = Nan::ObjectWrap::Unwrap<SessionWrap>(info.This());
  info.GetReturnValue().Set(Nan::CopyBuffer((char *)session->id, session->id_len).ToLocalChecked());
}

NAN_SETTER(SessionWrap::SetId) {
  SessionWrap *session = Nan::ObjectWrap::Unwrap<SessionWrap>(info.This());
  memcpy(session->id, Buffer::Data(value), Buffer::Length(value));
  session->id_len = Buffer::Length(value);
}


NAN_GETTER(SessionWrap::GetMaster) {
  SessionWrap *session = Nan::ObjectWrap::Unwrap<SessionWrap>(info.This());
  info.GetReturnValue().Set(Nan::CopyBuffer((char *)session->master, 48).ToLocalChecked());
}

NAN_SETTER(SessionWrap::SetMaster) {
  SessionWrap *session = Nan::ObjectWrap::Unwrap<SessionWrap>(info.This());
  memcpy(session->master, Buffer::Data(value), Buffer::Length(value));
}


NAN_GETTER(SessionWrap::GetInEpoch) {
  SessionWrap *session = Nan::ObjectWrap::Unwrap<SessionWrap>(info.This());
  info.GetReturnValue().Set(Nan::New(session->in_epoch));
}

NAN_SETTER(SessionWrap::SetInEpoch) {
  SessionWrap *session = Nan::ObjectWrap::Unwrap<SessionWrap>(info.This());
  session->in_epoch = value->Uint32Value();
}


NAN_GETTER(SessionWrap::GetOutCounter) {
  SessionWrap *session = Nan::ObjectWrap::Unwrap<SessionWrap>(info.This());
  info.GetReturnValue().Set(Nan::CopyBuffer((char *)session->out_ctr, 8).ToLocalChecked());
}

NAN_SETTER(SessionWrap::SetOutCounter) {
  SessionWrap *session = Nan::ObjectWrap::Unwrap<SessionWrap>(info.This());
  memcpy(session->out_ctr, Buffer::Data(value), Buffer::Length(value));
}

SessionWrap::SessionWrap() {
}

SessionWrap::~SessionWrap() {

}
