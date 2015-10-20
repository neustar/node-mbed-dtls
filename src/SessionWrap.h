#ifndef __SESSION_WRAP_H__
#define __SESSION_WRAP_H__

#include <node.h>
#include <nan.h>

#include "mbedtls/ssl.h"

class SessionWrap : public Nan::ObjectWrap {
public:
	static void Initialize(Nan::ADDON_REGISTER_FUNCTION_ARGS_TYPE target);	
	static v8::Local<v8::Object> CreateFromSession(mbedtls_ssl_session *session);
	static NAN_GETTER(GetCiphersuite);
	static NAN_GETTER(GetCompression);
	static NAN_GETTER(GetId);
	static NAN_GETTER(GetMaster);
	static NAN_GETTER(GetVerifyResult);
	SessionWrap();
	void ConvertToMbedSession(mbedtls_ssl_session *session);
	
private:
	~SessionWrap();

	static void New(const Nan::FunctionCallbackInfo<v8::Value>& info);
	static Nan::Persistent<v8::FunctionTemplate> constructor;
	int ciphersuite;
	int compression;
	char *id;
	size_t id_len;
	char *master;
	uint32_t verify_result;

	//mbedtls_x509_crt *peer_cert;
};

#endif