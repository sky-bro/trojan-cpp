#include "sslsession.h"
using namespace std;

list<SSL_SESSION *> SSLSession::sessions;

int SSLSession::new_session_cb(SSL *, SSL_SESSION *session) {
  sessions.push_front(session);
  return 0;
}

void SSLSession::remove_session_cb(SSL_CTX *, SSL_SESSION *session) {
  sessions.remove(session);
}

SSL_SESSION *SSLSession::get_session() {
  if (sessions.empty()) {
    return nullptr;
  }
  return sessions.front();
}

void SSLSession::set_callback(SSL_CTX *context) {
  SSL_CTX_sess_set_new_cb(context, new_session_cb);
  SSL_CTX_sess_set_remove_cb(context, remove_session_cb);
}
