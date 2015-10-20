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
	SessionWrap *session = new SessionWrap();
	session->Wrap(info.This());
	info.GetReturnValue().Set(info.This());
}

v8::Local<v8::Object> SessionWrap::CreateFromSession(mbedtls_ssl_session *session) {
	Nan::EscapableHandleScope scope;
	v8::Local<v8::Function> cons = Nan::GetFunction(Nan::New(constructor)).ToLocalChecked();

	const unsigned argc = 0;
	v8::Local<v8::Value> argv[argc] = {};
	v8::Local<v8::Object> instance = Nan::NewInstance(cons, argc, argv).ToLocalChecked();

	SessionWrap *news = Nan::ObjectWrap::Unwrap<SessionWrap>(instance);
	news->ciphersuite = session->ciphersuite;
	news->compression = session->compression;
	news->verify_result = session->verify_result;

	if((news->id = (char *)calloc(1, session->id_len)) == NULL) {
		Nan::ThrowError("id malloc");
	}
	memcpy(news->id, session->id, session->id_len);
	news->id_len = session->id_len;

	if((news->master = (char *)calloc(1, 48)) == NULL) {
		Nan::ThrowError("master alloc");
	}
	memcpy(news->master, session->master, 48);

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

SessionWrap::SessionWrap() {
}

SessionWrap::~SessionWrap() {

}