#ifndef INCLUDED_SSLSESSION_H
#define INCLUDED_SSLSESSION_H

#include <list>
#include <openssl/ssl.h>

class SSLSession {
private:
  static std::list<SSL_SESSION *> sessions;
  static int new_session_cb(SSL *, SSL_SESSION *session);
  static void remove_session_cb(SSL_CTX *, SSL_SESSION *session);

public:
  static SSL_SESSION *get_session();
  static void set_callback(SSL_CTX *context);
};

#endif /* INCLUDED_SSLSESSION_H */
