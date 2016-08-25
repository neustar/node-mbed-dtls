#include "DtlsClientSocket.h"

#include <stdlib.h>

#include "mbedtls/error.h"

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

int net_send_cli( void *ctx, const unsigned char *buf, size_t len ) {
  DtlsClientSocket* socket = (DtlsClientSocket*)ctx;
  if (NULL == buf) {
    printf("Tried to send from a NULL buffer!\n");
    return 0;
  }
  return socket->send_encrypted(buf, len);
}

int net_recv_cli( void *ctx, unsigned char *buf, size_t len ) {
  DtlsClientSocket* socket = (DtlsClientSocket*)ctx;
  if (NULL == buf) {
    printf("Tried to recv into a NULL buffer!\n");
    return 0;
  }
  return socket->recv(buf, len);
}


Nan::Persistent<v8::FunctionTemplate> DtlsClientSocket::constructor;

void DtlsClientSocket::Initialize(Nan::ADDON_REGISTER_FUNCTION_ARGS_TYPE target) {
  Nan::HandleScope scope;

  // Constructor
  v8::Local<v8::FunctionTemplate> ctor = Nan::New<v8::FunctionTemplate>(DtlsClientSocket::New);
  constructor.Reset(ctor);
  v8::Local<v8::ObjectTemplate>  ctorInst = ctor->InstanceTemplate();
  ctorInst->SetInternalFieldCount(1);
  ctor->SetClassName(Nan::New("DtlsClientSocket").ToLocalChecked());

  Nan::SetPrototypeMethod(ctor, "receiveData", ReceiveDataFromNode);
  Nan::SetPrototypeMethod(ctor, "close", Close);
  Nan::SetPrototypeMethod(ctor, "send", Send);
  Nan::SetPrototypeMethod(ctor, "connect", Connect);

  Nan::Set(target, Nan::New("DtlsClientSocket").ToLocalChecked(), ctor->GetFunction());
}

/*
 * Node wrapper to the client socket constructor.
 */
void DtlsClientSocket::New(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  size_t priv_key_len     = (info[0]->BooleanValue()) ? Buffer::Length(info[0]) : 0;
  size_t peer_pub_key_len = (info[1]->BooleanValue()) ? Buffer::Length(info[1]) : 0;
  size_t ca_len           = (info[2]->BooleanValue()) ? Buffer::Length(info[2]) : 0;
  size_t psk_len          = (info[3]->BooleanValue()) ? Buffer::Length(info[3]) : 0;
  size_t ident_len        = (info[4]->BooleanValue()) ? Buffer::Length(info[4]) : 0;

  const unsigned char* priv_key     = (priv_key_len)     ? (const unsigned char *) Buffer::Data(info[0]) : NULL;
  const unsigned char* peer_pub_key = (peer_pub_key_len) ? (const unsigned char *) Buffer::Data(info[1]) : NULL;
  const unsigned char* _ca_pem      = (ca_len)           ? (const unsigned char *) Buffer::Data(info[2]) : NULL;
  const unsigned char* _psk         = (psk_len)          ? (const unsigned char *) Buffer::Data(info[3]) : NULL;
  const unsigned char* _ident       = (ident_len)        ? (const unsigned char *) Buffer::Data(info[4]) : NULL;

  Nan::Callback* send_cb  = new Nan::Callback(info[5].As<v8::Function>());
  Nan::Callback* hs_cb    = new Nan::Callback(info[6].As<v8::Function>());
  Nan::Callback* error_cb = new Nan::Callback(info[7].As<v8::Function>());

  int debug_level = 0;
  if (info.Length() > 8) {
    debug_level = info[8]->Uint32Value();
  }

  DtlsClientSocket *socket = new DtlsClientSocket(
    priv_key, priv_key_len,
    peer_pub_key, peer_pub_key_len,
    _ca_pem, ca_len,
    _psk,    psk_len,
    _ident,  ident_len,
    send_cb, hs_cb, error_cb,
    debug_level);
  socket->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}


void DtlsClientSocket::ReceiveDataFromNode(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  DtlsClientSocket *socket = Nan::ObjectWrap::Unwrap<DtlsClientSocket>(info.This());
  const unsigned char *recv_data = (const unsigned char *)Buffer::Data(info[0]);
  socket->store_data(recv_data, Buffer::Length(info[0]));

  int len = 1284;
  unsigned char buf[len];
  len = socket->receive_data(buf, len);

  if (len > 0) {
    info.GetReturnValue().Set(Nan::CopyBuffer((char*)buf, len).ToLocalChecked());
  }
}


void DtlsClientSocket::Close(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  DtlsClientSocket *socket = Nan::ObjectWrap::Unwrap<DtlsClientSocket>(info.This());
  int ret = socket->close();
  if (ret < 0) {
    mbedtls_printf("Unexpected return value from socket->close(): %d.\n", ret);
    return;
  }

  info.GetReturnValue().Set(Nan::New(ret));
}


void DtlsClientSocket::Send(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  DtlsClientSocket *socket = Nan::ObjectWrap::Unwrap<DtlsClientSocket>(info.This());
  const unsigned char *send_data = (const unsigned char *)Buffer::Data(info[0]);
  socket->send(send_data, Buffer::Length(info[0]));
}


void DtlsClientSocket::Connect(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  DtlsClientSocket *socket = Nan::ObjectWrap::Unwrap<DtlsClientSocket>(info.This());
  mbedtls_ssl_set_bio(&socket->ssl_context, socket, net_send_cli, net_recv_cli, NULL);
  socket->step();
}


DtlsClientSocket::DtlsClientSocket(
                       const unsigned char *priv_key,     size_t priv_key_len,
                       const unsigned char *peer_pub_key, size_t peer_pub_key_len,
                       const unsigned char *ca_pem,       size_t ca_pem_len,
                       const unsigned char *psk,          size_t psk_len,
                       const unsigned char *ident,        size_t ident_len,
                       Nan::Callback* send_callback,
                       Nan::Callback* hs_callback,
                       Nan::Callback* error_callback,
                       int debug_level)
    : Nan::ObjectWrap(),
    send_cb(send_callback),
    error_cb(error_callback),
    handshake_cb(hs_callback) {
  int ret;
  const char *pers = "dtls_client";

  recv_len = 0;
  recv_buf = NULL;

  #if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(debug_level);
  #endif

  // mbedTLS will expect this array to be null-terminated. Zero it all...
  for (int x = 0; x < MAX_CIPHERSUITE_COUNT; x++) allowed_ciphersuites[x] = 0;

  /*
  * This is essential for limiting the size of handshake packets. Many IoT
  *   devices will only support a single ciphersuite, which may not be in this list.
  * Therefore....
  * TODO: Might-could automatically scope this down based on the provded credentials.
  */
  allowed_ciphersuites[0] = MBEDTLS_TLS_PSK_WITH_AES_128_CCM_8;   // IoTivity
  allowed_ciphersuites[1] = MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA256;
  allowed_ciphersuites[2] = MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256;
  allowed_ciphersuites[3] = MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
  allowed_ciphersuites[4] = MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8;

  mbedtls_ssl_init(&ssl_context);
  mbedtls_x509_crt_init(&clicert);
  mbedtls_x509_crt_init(&cacert);
  mbedtls_pk_init(&pkey);
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  ret = mbedtls_ctr_drbg_seed(&ctr_drbg,
                              mbedtls_entropy_func,
                              &entropy,
                              (const unsigned char *) pers,
                              strlen(pers));
  if (ret != 0) goto exit;

  mbedtls_ssl_config_init(&conf);
  ret = mbedtls_ssl_config_defaults(&conf,
                                    MBEDTLS_SSL_IS_CLIENT,
                                    MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT);
  if (ret != 0) goto exit;
  mbedtls_ssl_conf_ciphersuites(&conf, allowed_ciphersuites);

  mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
  mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
  mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

  if ((NULL != ca_pem) && (ca_pem_len > 0)) {
    ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *) ca_pem, ca_pem_len);
    if (ret != 0) goto exit;
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
  }

  if ((NULL != priv_key) && (priv_key_len > 0)) {
    ret = mbedtls_ssl_conf_own_cert(&conf, &clicert, &pkey);
    if (ret != 0) goto exit;
  }

  if ((NULL != ident) && (NULL != psk)) {
    ret = mbedtls_ssl_conf_psk(&conf, (const unsigned char*)psk, psk_len, (const unsigned char*) ident, ident_len);
    if (ret != 0) goto exit;
  }

  mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);

  if((ret = mbedtls_ssl_setup(&ssl_context, &conf)) != 0) goto exit;

  mbedtls_ssl_set_timer_cb(&ssl_context,
                           &timer,
                           mbedtls_timing_set_delay,
                           mbedtls_timing_get_delay);

  // TODO: Below needs audit and (at minimum) a case-off.
  if( ( ret = mbedtls_ssl_set_hostname(&ssl_context, "localhost" ) ) != 0 ) {
    mbedtls_printf(" failed\n  ! mbedtls_ssl_set_hostname returned 0x%04x\n\n", ret);
    goto exit;
  }

  return;
exit:
  throwError(ret);
  return;
}

int DtlsClientSocket::send_encrypted(const unsigned char *buf, size_t len) {
  v8::Local<v8::Value> argv[] = {
    Nan::CopyBuffer((char *)buf, len).ToLocalChecked()
  };
  v8::Local<v8::Function> sendCallbackDirect = send_cb->GetFunction();
  sendCallbackDirect->Call(Nan::GetCurrentContext()->Global(), 1, argv);
  return len;
}

int DtlsClientSocket::recv(unsigned char *buf, size_t len) {
  if (recv_len != 0) {
    len = recv_len;
    memcpy(buf, recv_buf, recv_len);
    recv_buf = NULL;
    recv_len = 0;
    return len;
  }

  return MBEDTLS_ERR_SSL_WANT_READ;
}

int DtlsClientSocket::send(const unsigned char *buf, size_t len) {
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

int DtlsClientSocket::receive_data(unsigned char *buf, int len) {
  int ret;

  if (ssl_context.state == MBEDTLS_SSL_HANDSHAKE_OVER) {
    // normal reading of unencrypted data
    memset(buf, 0, len);
    ret = mbedtls_ssl_read(&ssl_context, buf, len);
    if (ret <= 0) {
      error(ret);
      return 0;
    }
    return ret;
  }
  return step();
}


const char* _mbedtls_state_to_string(int x) {
  switch (x) {
    case MBEDTLS_SSL_HELLO_REQUEST:                     return "HELLO_REQUEST";
    case MBEDTLS_SSL_CLIENT_HELLO:                      return "CLIENT_HELLO";
    case MBEDTLS_SSL_SERVER_HELLO:                      return "SERVER_HELLO";
    case MBEDTLS_SSL_SERVER_CERTIFICATE:                return "SERVER_CERTIFICATE";
    case MBEDTLS_SSL_SERVER_KEY_EXCHANGE:               return "SERVER_KEY_EXCHANGE";
    case MBEDTLS_SSL_CERTIFICATE_REQUEST:               return "CERTIFICATE_REQUEST";
    case MBEDTLS_SSL_SERVER_HELLO_DONE:                 return "SERVER_HELLO_DONE";
    case MBEDTLS_SSL_CLIENT_CERTIFICATE:                return "CLIENT_CERTIFICATE";
    case MBEDTLS_SSL_CLIENT_KEY_EXCHANGE:               return "CLIENT_KEY_EXCHANGE";
    case MBEDTLS_SSL_CERTIFICATE_VERIFY:                return "CERTIFICATE_VERIFY";
    case MBEDTLS_SSL_CLIENT_CHANGE_CIPHER_SPEC:         return "CLIENT_CHANGE_CIPHER_SPEC";
    case MBEDTLS_SSL_CLIENT_FINISHED:                   return "CLIENT_FINISHED";
    case MBEDTLS_SSL_SERVER_CHANGE_CIPHER_SPEC:         return "SERVER_CHANGE_CIPHER_SPEC";
    case MBEDTLS_SSL_SERVER_FINISHED:                   return "SERVER_FINISHED";
    case MBEDTLS_SSL_FLUSH_BUFFERS:                     return "FLUSH_BUFFERS";
    case MBEDTLS_SSL_HANDSHAKE_WRAPUP:                  return "HANDSHAKE_WRAPUP";
    case MBEDTLS_SSL_HANDSHAKE_OVER:                    return "HANDSHAKE_OVER";
    case MBEDTLS_SSL_SERVER_NEW_SESSION_TICKET:         return "SERVER_NEW_SESSION_TICKET";
    case MBEDTLS_SSL_SERVER_HELLO_VERIFY_REQUEST_SENT:  return "SERVER_HELLO_VERIFY_REQUEST_SENT";
  }
  return "UNKNOWN HANDSHAKE STATE";
}



int DtlsClientSocket::step() {
  mbedtls_printf("step() beginning\n");
  int stacked_state = ssl_context.state;
  if (stacked_state != MBEDTLS_SSL_HANDSHAKE_OVER) {
    int ret = mbedtls_ssl_handshake(&ssl_context);
    switch (ret) {
      case MBEDTLS_ERR_SSL_WANT_READ:
      case MBEDTLS_ERR_SSL_WANT_WRITE:
        // The library is still waiting on the net stack. Do nothing.
        return ret;
      case 0:
        // The nominal outcome.
        break;
      default:
        // Something went sideways during the handshake.
        error(ret);
        return 0;
    }
  }

  if (stacked_state != ssl_context.state) {
    mbedtls_printf("step() state %s --> %s.\n", _mbedtls_state_to_string(stacked_state), _mbedtls_state_to_string(ssl_context.state));
  }

  if (ssl_context.state == MBEDTLS_SSL_HANDSHAKE_OVER) {
    // this should only be called once when we first finish the handshake
    v8::Local<v8::Function> handshakeCallbackDirect = handshake_cb->GetFunction();
    handshakeCallbackDirect->Call(Nan::GetCurrentContext()->Global(), 0, NULL);
  }
  return 0;
}



void DtlsClientSocket::throwError(int ret) {
  char error_buf[100];
  mbedtls_strerror(ret, error_buf, 100);
  Nan::ThrowError(error_buf);
}

void DtlsClientSocket::error(int ret) {
  char error_buf[100];
  mbedtls_strerror(ret, error_buf, 100);
  v8::Local<v8::Value> argv[] = {
    Nan::New(ret),
    Nan::New(error_buf).ToLocalChecked()
  };
  v8::Local<v8::Function> errorCallbackDirect = error_cb->GetFunction();
  errorCallbackDirect->Call(Nan::GetCurrentContext()->Global(), 2, argv);
}

void DtlsClientSocket::store_data(const unsigned char *buf, size_t len) {
  recv_buf = buf;
  recv_len = len;
}

int DtlsClientSocket::close() {
  if(ssl_context.state != MBEDTLS_SSL_HANDSHAKE_OVER) {
    return 1;
  }
  return mbedtls_ssl_close_notify(&ssl_context);
}

DtlsClientSocket::~DtlsClientSocket() {
  delete send_cb;
  send_cb = nullptr;
  delete error_cb;
  error_cb = nullptr;
  delete handshake_cb;
  handshake_cb = nullptr;
  recv_buf = nullptr;
  mbedtls_x509_crt_free(&clicert);
  mbedtls_x509_crt_free(&cacert);
  mbedtls_pk_free(&pkey);
  mbedtls_ssl_config_free(&conf);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  mbedtls_ssl_free(&ssl_context);
}
