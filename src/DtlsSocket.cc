
#include "DtlsSocket.h"
#include "SessionWrap.h"

#include <stdlib.h>

#include "mbedtls/ssl_internal.h"
#include "mbedtls/pk.h"

using namespace node;

Nan::Persistent<v8::FunctionTemplate> DtlsSocket::constructor;

void
DtlsSocket::Initialize(Nan::ADDON_REGISTER_FUNCTION_ARGS_TYPE target) {
  Nan::HandleScope scope;

  // Constructor
  v8::Local<v8::FunctionTemplate> ctor = Nan::New<v8::FunctionTemplate>(DtlsSocket::New);
  constructor.Reset(ctor);
  v8::Local<v8::ObjectTemplate>  ctorInst = ctor->InstanceTemplate();
  ctorInst->SetInternalFieldCount(1);
  ctor->SetClassName(Nan::New("DtlsSocket").ToLocalChecked());

  Nan::SetPrototypeMethod(ctor, "receiveData", ReceiveDataFromNode);
  Nan::SetPrototypeMethod(ctor, "close", Close);
  Nan::SetPrototypeMethod(ctor, "send", Send);
  Nan::SetPrototypeMethod(ctor, "resumeSession", ResumeSession);
  Nan::SetPrototypeMethod(ctor, "renegotiate", Renegotiate);

  Nan::SetAccessor(ctorInst, Nan::New("publicKey").ToLocalChecked(), GetPublicKey);
  Nan::SetAccessor(ctorInst, Nan::New("publicKeyPEM").ToLocalChecked(), GetPublicKeyPEM);
  Nan::SetAccessor(ctorInst, Nan::New("outCounter").ToLocalChecked(), GetOutCounter);
  Nan::SetAccessor(ctorInst, Nan::New("session").ToLocalChecked(), GetSession);

  Nan::Set(target, Nan::New("DtlsSocket").ToLocalChecked(), ctor->GetFunction());
}

void DtlsSocket::New(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  if (info.Length() < 6) {
    return Nan::ThrowTypeError("DtlsSocket requires six arguments");
  }

  // TODO check arguments types

  DtlsServer *server = Nan::ObjectWrap::Unwrap<DtlsServer>(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  Nan::Utf8String client_ip(info[1]);

  Nan::Callback* send_cb = new Nan::Callback(info[2].As<v8::Function>());
  Nan::Callback* hs_cb = new Nan::Callback(info[3].As<v8::Function>());
  Nan::Callback* error_cb = new Nan::Callback(info[4].As<v8::Function>());
  Nan::Callback* resume_cb = new Nan::Callback(info[5].As<v8::Function>());

  DtlsSocket *socket = new DtlsSocket(server,
                                      (unsigned char *)*client_ip,
                                      client_ip.length(),
                                      send_cb,
                                      hs_cb,
                                      error_cb,
                                      resume_cb);
  socket->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

void DtlsSocket::ReceiveDataFromNode(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  DtlsSocket *socket = Nan::ObjectWrap::Unwrap<DtlsSocket>(info.This());

  if (info.Length() >= 1 && Buffer::HasInstance(info[0])) {
    const unsigned char *recv_data = (const unsigned char *)Buffer::Data(info[0]);
    size_t recv_len = Buffer::Length(info[0]);
    socket->store_data(recv_data, recv_len);
  }

  int len = 1024;
  unsigned char buf[len];
  len = socket->receive_data(buf, len);

  if (len > 0) {
    info.GetReturnValue().Set(Nan::CopyBuffer((char*)buf, len).ToLocalChecked());
  }
}

NAN_GETTER(DtlsSocket::GetPublicKey) {
  DtlsSocket *socket = Nan::ObjectWrap::Unwrap<DtlsSocket>(info.This());

  mbedtls_ssl_session *session = socket->ssl_context.session;
  if (session == NULL) {
    return;
  }
  int ret;
  const size_t buf_len = 256;
  unsigned char buf[buf_len];
  mbedtls_pk_context pk = session->peer_cert->pk;
  ret = mbedtls_pk_write_pubkey_der(&pk, buf, buf_len);
  if (ret < 0) {
    // TODO error?
    return;
  }

  // key is written at the end
  info.GetReturnValue().Set(Nan::CopyBuffer((char *)buf + (buf_len - ret), ret).ToLocalChecked());
}

NAN_GETTER(DtlsSocket::GetPublicKeyPEM) {
  DtlsSocket *socket = Nan::ObjectWrap::Unwrap<DtlsSocket>(info.This());

  mbedtls_ssl_session *session = socket->ssl_context.session;
  if (session == NULL ||
      session->peer_cert == NULL) {
    return;
  }
  int ret;
  const size_t buf_len = 256;
  unsigned char buf[buf_len];
  mbedtls_pk_context pk = session->peer_cert->pk;
  ret = mbedtls_pk_write_pubkey_pem(&pk, buf, buf_len);
  if (ret < 0) {
    // TODO error?
    return;
  }

  info.GetReturnValue().Set(Nan::CopyBuffer((char *)buf, strlen((const char *)buf)).ToLocalChecked());
}

NAN_GETTER(DtlsSocket::GetOutCounter) {
  DtlsSocket *socket = Nan::ObjectWrap::Unwrap<DtlsSocket>(info.This());
  info.GetReturnValue().Set(Nan::CopyBuffer((char *)socket->ssl_context.out_ctr, 8).ToLocalChecked());
}

NAN_GETTER(DtlsSocket::GetSession) {
  DtlsSocket *socket = Nan::ObjectWrap::Unwrap<DtlsSocket>(info.This());
  v8::Local<v8::Object> sess = SessionWrap::CreateFromContext(&socket->ssl_context, socket->random);
  info.GetReturnValue().Set(sess);
}

void DtlsSocket::Close(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  DtlsSocket *socket = Nan::ObjectWrap::Unwrap<DtlsSocket>(info.This());
  int ret = socket->close();
  if (ret < 0) {
    // TODO error?
    return;
  }

  info.GetReturnValue().Set(Nan::New(ret));
}

void DtlsSocket::Send(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  DtlsSocket *socket = Nan::ObjectWrap::Unwrap<DtlsSocket>(info.This());

  const unsigned char *send_data = (const unsigned char *)Buffer::Data(info[0]);
  socket->send(send_data, Buffer::Length(info[0]));
}

void DtlsSocket::ResumeSession(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  DtlsSocket *socket = Nan::ObjectWrap::Unwrap<DtlsSocket>(info.This());

  Nan::MaybeLocal<v8::Object> maybeSess = Nan::To<v8::Object>(info[0]);
  if (maybeSess.IsEmpty()) {
    return;
  }

  SessionWrap *sess = Nan::ObjectWrap::Unwrap<SessionWrap>(maybeSess.ToLocalChecked());
  bool ret = socket->resume(sess);
  info.GetReturnValue().Set(Nan::New(ret));
}

void DtlsSocket::Renegotiate(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  DtlsSocket *socket = Nan::ObjectWrap::Unwrap<DtlsSocket>(info.This());

  if (info[0]->IsUndefined()) {
    socket->proceed();
    return;
  }

  SessionWrap *sess = Nan::ObjectWrap::Unwrap<SessionWrap>(Nan::To<v8::Object>(info[0]).ToLocalChecked());
  socket->renegotiate(sess);
}

int net_send( void *ctx, const unsigned char *buf, size_t len ) {
  DtlsSocket* socket = (DtlsSocket*)ctx;
  return socket->send_encrypted(buf, len);
}

int net_recv( void *ctx, unsigned char *buf, size_t len ) {
  DtlsSocket* socket = (DtlsSocket*)ctx;
  return socket->recv(buf, len);
}

DtlsSocket::DtlsSocket(DtlsServer *server,
                       unsigned char *client_ip,
                       size_t client_ip_len,
                       Nan::Callback* send_callback,
                       Nan::Callback* hs_callback,
                       Nan::Callback* error_callback,
                       Nan::Callback* resume_sess_callback)
    : Nan::ObjectWrap(),
    send_cb(send_callback),
    error_cb(error_callback),
    handshake_cb(hs_callback),
    resume_sess_cb(resume_sess_callback),
    session_wait(false) {
  int ret;

  recv_len = 0;
  recv_buf = NULL;

  if((ip = (unsigned char *)calloc(1, client_ip_len)) == NULL) {
    throwError(MBEDTLS_ERR_SSL_ALLOC_FAILED);
    return;
  }
  memcpy(ip, client_ip, client_ip_len);
  ip_len = client_ip_len;

  mbedtls_ssl_init(&ssl_context);
  ssl_config = server->config();

  if((ret = mbedtls_ssl_setup(&ssl_context, ssl_config)) != 0)
  {
    throwError(ret);
  }

  mbedtls_ssl_set_timer_cb(&ssl_context,
                           &timer,
                           mbedtls_timing_set_delay,
                           mbedtls_timing_get_delay);
  mbedtls_ssl_set_bio(&ssl_context, this, net_send, net_recv, NULL);
  mbedtls_ssl_session_reset(&ssl_context);

  /* For HelloVerifyRequest cookies */
  if((ret = mbedtls_ssl_set_client_transport_id(&ssl_context, ip, ip_len)) != 0)
  {
    throwError(ret);
    return;
  }
}

bool DtlsSocket::resume(SessionWrap *sess) {
  ssl_context.major_ver = MBEDTLS_SSL_MAJOR_VERSION_3;
  ssl_context.minor_ver = MBEDTLS_SSL_MINOR_VERSION_3;

  ssl_context.state = MBEDTLS_SSL_HANDSHAKE_WRAPUP;
  ssl_context.handshake->resume = 1;

  ssl_context.in_epoch = sess->in_epoch;

  memcpy(ssl_context.out_ctr, sess->out_ctr, 8);
  memcpy(ssl_context.handshake->randbytes, sess->randbytes, 64);
  memcpy(ssl_context.session_negotiate->master, sess->master, 48);

  ssl_context.session_negotiate->id_len = sess->id_len;
  memcpy(ssl_context.session_negotiate->id, sess->id, sess->id_len);

  ssl_context.session_negotiate->ciphersuite = sess->ciphersuite;
  ssl_context.transform_negotiate->ciphersuite_info = mbedtls_ssl_ciphersuite_from_id(sess->ciphersuite);

  if (!ssl_context.transform_negotiate->ciphersuite_info)
  {
    error(MBEDTLS_ERR_SSL_NO_USABLE_CIPHERSUITE);
    return false;
  }

  int err = mbedtls_ssl_derive_keys(&ssl_context);
  if (err)
  {
    error(err);
    return false;
  }

  ssl_context.in_msg = ssl_context.in_iv + ssl_context.transform_negotiate->ivlen -
                    ssl_context.transform_negotiate->fixed_ivlen;
  ssl_context.out_msg = ssl_context.out_iv + ssl_context.transform_negotiate->ivlen -
                     ssl_context.transform_negotiate->fixed_ivlen;

  ssl_context.session_in = ssl_context.session_negotiate;
  ssl_context.session_out = ssl_context.session_negotiate;

  ssl_context.transform_in = ssl_context.transform_negotiate;
  ssl_context.transform_out = ssl_context.transform_negotiate;

  mbedtls_ssl_handshake_wrapup(&ssl_context);

  return true;
}

void DtlsSocket::reset() {
  int ret;
  mbedtls_ssl_session_reset(&ssl_context);

  /* For HelloVerifyRequest cookies */
  if((ret = mbedtls_ssl_set_client_transport_id(&ssl_context, ip, ip_len)) != 0)
  {
    return error(ret);
  }
}

int DtlsSocket::send_encrypted(const unsigned char *buf, size_t len) {
  v8::Local<v8::Value> argv[] = {
    Nan::CopyBuffer((char *)buf, len).ToLocalChecked()
  };
  v8::Local<v8::Function> sendCallbackDirect = send_cb->GetFunction();
  sendCallbackDirect->Call(Nan::GetCurrentContext()->Global(), 1, argv);
  return len;
}

int DtlsSocket::recv(unsigned char *buf, size_t len) {
  if (recv_len != 0) {
    len = recv_len;
    memcpy(buf, recv_buf, recv_len);
    recv_buf = NULL;
    recv_len = 0;
    return len;
  }

  return MBEDTLS_ERR_SSL_WANT_READ;
}

int DtlsSocket::send(const unsigned char *buf, size_t len) {
  int ret;
  ret = mbedtls_ssl_write(&ssl_context, buf, len);
  if (ret < 0)
  {
    error(ret);
    return ret;
  }
  len = ret;
  return ret;
}

int DtlsSocket::receive_data(unsigned char *buf, int len) {
  int ret;

  if (ssl_context.state == MBEDTLS_SSL_HANDSHAKE_OVER) {
    // normal reading of unencrypted data
    memset(buf, 0, len);
    ret = mbedtls_ssl_read(&ssl_context, buf, len);
    if (ret <= 0 && ret != MBEDTLS_ERR_SSL_WANT_READ) {
      error(ret);
      return 0;
    }
    return ret;
  }

  return step();
}

void DtlsSocket::get_session_cache(mbedtls_ssl_session *session) {
  Nan::HandleScope scope;
  session_wait = true;

  v8::Local<v8::Object> session_id = Nan::CopyBuffer((const char *)session->id, session->id_len).ToLocalChecked();
  const unsigned argc = 1;
  v8::Local<v8::Value> argv[argc] = { session_id };

  v8::Local<v8::Function> resumeCallbackDirect = resume_sess_cb->GetFunction();
  resumeCallbackDirect->Call(Nan::GetCurrentContext()->Global(), argc, argv);
}

void DtlsSocket::renegotiate(SessionWrap *sess) {
  mbedtls_ssl_session *session = ssl_context.session_negotiate;

  if( session->ciphersuite != sess->ciphersuite ||
      session->id_len != sess->id_len )
      return;

  if( memcmp( session->id, sess->id,
              sess->id_len ) != 0 )
      return;

  memcpy( session->master, sess->master, 48 );

  session->verify_result = 0;
  ssl_context.handshake->resume = 1;

  proceed();
}

void DtlsSocket::proceed() {
  session_wait = false;
  step();
}

int DtlsSocket::step() {
  int ret;
  // handshake
  while (ssl_context.state != MBEDTLS_SSL_HANDSHAKE_OVER) {
    ret = mbedtls_ssl_handshake_step(&ssl_context);
    if (ret == 0) {
      if (session_wait &&
        (ssl_context.state == MBEDTLS_SSL_SERVER_HELLO ||
         ssl_context.state == MBEDTLS_SSL_HANDSHAKE_WRAPUP)) {
        return 0;
      }

      if (ssl_context.state == MBEDTLS_SSL_SERVER_HELLO &&
          ssl_context.handshake->resume == 0 &&
          ssl_context.session_negotiate->id_len != 0) {
        get_session_cache(ssl_context.session_negotiate);

        // copy client random (renegotiation)
        if (ssl_context.handshake->resume == 1) {
          memcpy(random, ssl_context.handshake->randbytes, 32);
        }
        return 0;
      }

      // nasty grabbing of server random in renegotiation case
      if (ssl_context.state == MBEDTLS_SSL_SERVER_CHANGE_CIPHER_SPEC &&
          ssl_context.handshake->resume == 1) {
        memcpy(random + 32, ssl_context.out_msg + 6, 32);
      }

      // normal handshake random grab
      if (ssl_context.state == MBEDTLS_SSL_SERVER_CERTIFICATE)
      {
        memcpy(random, ssl_context.handshake->randbytes, 64);
      }

      // keep looping to send everything
      continue;
    } else if (ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED) {
      // client will start a new session, so reset things
      reset();
      continue;
    } else if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
      // we just need more data, so return
      if (recv_len > 0)
        continue;

      return 0;
    } else if (ret != 0) {
      // bad things
      error(ret);
      return 0;
    }
  }

  // this should only be called once when we first finish the handshake
  v8::Local<v8::Function> hsCallbackDirect = handshake_cb->GetFunction();
  hsCallbackDirect->Call(Nan::GetCurrentContext()->Global(), 0, NULL);
  return 0;
}

void DtlsSocket::throwError(int ret) {
  char error_buf[100];
  mbedtls_strerror(ret, error_buf, 100);
  Nan::ThrowError(error_buf);
}

void DtlsSocket::error(int ret) {
  char error_buf[100];
  mbedtls_strerror(ret, error_buf, 100);
  v8::Local<v8::Value> argv[] = {
    Nan::New(ret),
    Nan::New(error_buf).ToLocalChecked()
  };

  v8::Local<v8::Function> errorCallbackDirect = error_cb->GetFunction();
  errorCallbackDirect->Call(Nan::GetCurrentContext()->Global(), 2, argv);
}

void DtlsSocket::store_data(const unsigned char *buf, size_t len) {
  recv_buf = buf;
  recv_len = len;
}

int DtlsSocket::close() {
  if(ssl_context.state != MBEDTLS_SSL_HANDSHAKE_OVER) {
    return 1;
  }
  return mbedtls_ssl_close_notify(&ssl_context);
}

DtlsSocket::~DtlsSocket() {
  delete send_cb;
  send_cb = nullptr;
  delete error_cb;
  error_cb = nullptr;
  delete handshake_cb;
  handshake_cb = nullptr;
  delete resume_sess_cb;
  resume_sess_cb = nullptr;
  ssl_config = nullptr;
  if (ip != nullptr) {
    free(ip);
    ip = nullptr;
  }
  recv_buf = nullptr;
  mbedtls_ssl_free(&ssl_context);
}
