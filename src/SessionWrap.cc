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
	v8::Local<v8::ObjectTemplate>	ctorInst = ctor->InstanceTemplate();
	ctorInst->SetInternalFieldCount(1);
	ctor->SetClassName(Nan::New("SessionWrap").ToLocalChecked());

	Nan::SetAccessor(ctorInst, Nan::New("ciphersuite").ToLocalChecked(), GetCiphersuite);
	Nan::SetAccessor(ctorInst, Nan::New("compression").ToLocalChecked(), GetCompression);
	Nan::SetAccessor(ctorInst, Nan::New("id").ToLocalChecked(), GetId);
	Nan::SetAccessor(ctorInst, Nan::New("master").ToLocalChecked(), GetMaster);
	Nan::SetAccessor(ctorInst, Nan::New("verifyResult").ToLocalChecked(), GetVerifyResult);

	Nan::Set(target, Nan::New("SessionWrap").ToLocalChecked(), ctor->GetFunction());
}

void SessionWrap::New(const Nan::FunctionCallbackInfo<v8::Value>& info) {	
	v8::Local<v8::Object> session_data = Nan::To<v8::Object>(info[0]).ToLocalChecked();

	SessionWrap *session = new SessionWrap(session_data);
	session->Wrap(info.This());
	info.GetReturnValue().Set(info.This());
}

v8::Local<v8::Object> SessionWrap::CreateFromSession(mbedtls_ssl_session *session) {
	Nan::EscapableHandleScope scope;
	v8::Local<v8::Function> cons = Nan::GetFunction(Nan::New(constructor)).ToLocalChecked();

	v8::Local<v8::Object> session_data = Nan::New<v8::Object>();
	Nan::Set(session_data, Nan::New("ciphersuite").ToLocalChecked(), Nan::New(session->ciphersuite));
	Nan::Set(session_data, Nan::New("compression").ToLocalChecked(), Nan::New(session->compression));
	Nan::Set(session_data, Nan::New("id").ToLocalChecked(), Nan::CopyBuffer((const char *)session->id, session->id_len).ToLocalChecked());
	Nan::Set(session_data, Nan::New("master").ToLocalChecked(), Nan::CopyBuffer((const char *)session->master, 48).ToLocalChecked());
	Nan::Set(session_data, Nan::New("verifyResult").ToLocalChecked(), Nan::New(session->verify_result));

	const unsigned argc = 1;
	v8::Local<v8::Value> argv[argc] = { session_data };
	v8::Local<v8::Object> instance = Nan::NewInstance(cons, argc, argv).ToLocalChecked();
	return scope.Escape(instance);
}

void SessionWrap::ConvertToMbedSession(mbedtls_ssl_session *session) {
	session->compression = compression;
	session->ciphersuite = ciphersuite;
	session->verify_result = verify_result;

	memcpy(session->master, master, 48);
}

NAN_GETTER(SessionWrap::GetCiphersuite) {
	SessionWrap *session = Nan::ObjectWrap::Unwrap<SessionWrap>(info.This());
	info.GetReturnValue().Set(Nan::New(session->ciphersuite));
}

NAN_GETTER(SessionWrap::GetCompression) {
	SessionWrap *session = Nan::ObjectWrap::Unwrap<SessionWrap>(info.This());
	info.GetReturnValue().Set(Nan::New(session->compression));
}

NAN_GETTER(SessionWrap::GetId) {
	SessionWrap *session = Nan::ObjectWrap::Unwrap<SessionWrap>(info.This());
	info.GetReturnValue().Set(Nan::NewBuffer(session->id, session->id_len).ToLocalChecked());
}

NAN_GETTER(SessionWrap::GetMaster) {
	SessionWrap *session = Nan::ObjectWrap::Unwrap<SessionWrap>(info.This());
	info.GetReturnValue().Set(Nan::NewBuffer(session->master, 48).ToLocalChecked());
}

NAN_GETTER(SessionWrap::GetVerifyResult) {
	SessionWrap *session = Nan::ObjectWrap::Unwrap<SessionWrap>(info.This());
	info.GetReturnValue().Set(Nan::New(session->verify_result));
}

SessionWrap::SessionWrap(v8::Local<v8::Object> data) {
	ciphersuite = Nan::Get(data, Nan::New("ciphersuite").ToLocalChecked()).ToLocalChecked()->Uint32Value();
	compression = Nan::Get(data, Nan::New("compression").ToLocalChecked()).ToLocalChecked()->Uint32Value();
	verify_result = Nan::Get(data, Nan::New("verifyResult").ToLocalChecked()).ToLocalChecked()->Uint32Value();

	v8::Local<v8::Value> id_arg = Nan::Get(data, Nan::New("id").ToLocalChecked()).ToLocalChecked();
	id = (char *)Buffer::Data(id_arg);
	id_len = Buffer::Length(id_arg);

	v8::Local<v8::Value> master_arg = Nan::Get(data, Nan::New("master").ToLocalChecked()).ToLocalChecked();
	master = (char *)Buffer::Data(master_arg);
}

SessionWrap::~SessionWrap() {

}