#include "service.h"
#include <boost/asio/socket_base.hpp>
#include <boost/asio/strand.hpp>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <stdexcept>
#ifdef _WIN32
#include <tchar.h>
#include <wincrypt.h>
#endif // _WIN32
#ifdef __APPLE__
#include < Security / Security.h>
#endif // __APPLE__
#include "session/clientsession.h"
#include "session/serversession.h"
#include "ssl/ssldefaults.h"
#include "ssl/sslsession.h"
#include <openssl/opensslv.h>

namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = boost::asio::ip::tcp;
using udp = boost::asio::ip::udp;

#ifdef ENABLE_REUSE_PORT
typedef net::detail::socket_option::boolean<SOL_SOCKET, SO_REUSEPORT>
    reuse_port;
#endif // ENABLE_REUSE_PORT

FILE *Service::keylog(nullptr);

Service::Service(Config &config, bool test)
    : config(config), socket_acceptor(ioc), ctx(ssl::context::sslv23),
      udp_socket(ioc) {
  if (!test) {
    tcp::resolver resolver(ioc);
    tcp::endpoint listen_endpoint =
        *resolver.resolve(config.local_addr, std::to_string(config.local_port))
             .begin();
    socket_acceptor.open(listen_endpoint.protocol());
    socket_acceptor.set_option(net::socket_base::reuse_address(true));

    if (config.tcp.reuse_port) {
#ifdef ENABLE_REUSE_PORT
      socket_acceptor.set_option(reuse_port(true));
#else  // ENABLE_REUSE_PORT
      Log::log_with_date_time("SO_REUSEPORT is not supported", Log::WARN);
#endif // ENABLE_REUSE_PORT
    }

    socket_acceptor.bind(listen_endpoint);
    socket_acceptor.listen();
  }
  Log::level = config.log_level;
  auto native_context = ctx.native_handle();
  ctx.set_options(ssl::context::default_workarounds | ssl::context::no_sslv2 |
                  ssl::context::no_sslv3 | ssl::context::single_dh_use);
  if (!config.ssl.curves.empty()) {
    SSL_CTX_set1_curves_list(native_context, config.ssl.curves.c_str());
  }
  if (config.run_type == Config::SERVER) {
    ctx.use_certificate_chain_file(config.ssl.cert);
    ctx.set_password_callback(
        [this](size_t, ssl::context_base::password_purpose) {
          return this->config.ssl.key_password;
        });
    ctx.use_private_key_file(config.ssl.key, ssl::context::pem);
    if (config.ssl.prefer_server_cipher) {
      SSL_CTX_set_options(native_context, SSL_OP_CIPHER_SERVER_PREFERENCE);
    }
    if (!config.ssl.alpn.empty()) {
      SSL_CTX_set_alpn_select_cb(
          native_context,
          [](SSL *, const unsigned char **out, unsigned char *outlen,
             const unsigned char *in, unsigned int inlen, void *config) -> int {
            if (SSL_select_next_proto(
                    (unsigned char **)out, outlen,
                    (unsigned char *)(((Config *)config)->ssl.alpn.c_str()),
                    ((Config *)config)->ssl.alpn.length(), in,
                    inlen) != OPENSSL_NPN_NEGOTIATED) {
              return SSL_TLSEXT_ERR_NOACK;
            }
            return SSL_TLSEXT_ERR_OK;
          },
          &config);
    }
    if (config.ssl.reuse_session) {
      SSL_CTX_set_timeout(native_context, config.ssl.session_timeout);
      if (!config.ssl.session_ticket) {
        SSL_CTX_set_options(native_context, SSL_OP_NO_TICKET);
      }
    } else {
      SSL_CTX_set_session_cache_mode(native_context, SSL_SESS_CACHE_OFF);
      SSL_CTX_set_options(native_context, SSL_OP_NO_TICKET);
    }
    if (!config.ssl.plain_http_response.empty()) {
      std::ifstream ifs(config.ssl.plain_http_response, std::ios::binary);
      if (!ifs.is_open()) {
        throw std::runtime_error(config.ssl.plain_http_response + ": " +
                                 strerror(errno));
      }
      plain_http_response = std::string(std::istreambuf_iterator<char>(ifs),
                                        std::istreambuf_iterator<char>());
    }
    if (config.ssl.dhparam.empty()) {
      ctx.use_tmp_dh(boost::asio::const_buffer(SSLDefaults::g_dh2048_sz,
                                               SSLDefaults::g_dh2048_sz_size));
    } else {
      ctx.use_tmp_dh_file(config.ssl.dhparam);
    }
  } else {
    if (config.ssl.sni.empty()) {
      config.ssl.sni = config.remote_addr;
    }
    if (config.ssl.verify) {
      ctx.set_verify_mode(ssl::verify_peer);
      if (config.ssl.cert.empty()) {
        ctx.set_default_verify_paths();
#ifdef _WIN32
        HCERTSTORE h_store = CertOpenSystemStore(0, _T("ROOT"));
        if (h_store) {
          X509_STORE *store = SSL_CTX_get_cert_store(native_context);
          PCCERT_CONTEXT p_context = NULL;
          while (
              (p_context = CertEnumCertificatesInStore(h_store, p_context))) {
            const unsigned char *encoded_cert = p_context->pbCertEncoded;
            X509 *x509 =
                d2i_X509(NULL, &encoded_cert, p_context->cbCertEncoded);
            if (x509) {
              X509_STORE_add_cert(store, x509);
              X509_free(x509);
            }
          }
          CertCloseStore(h_store, 0);
        }
#endif // _WIN32
#ifdef __APPLE__
        SecKeychainSearchRef pSecKeychainSearch = NULL;
        SecKeychainRef pSecKeychain;
        OSStatus status = noErr;
        X509 *cert = NULL;

        // Leopard and above store location
        status = SecKeychainOpen(
            "/System/Library/Keychains/SystemRootCertificates.keychain",
            &pSecKeychain);
        if (status == noErr) {
          X509_STORE *store = SSL_CTX_get_cert_store(native_context);
          status = SecKeychainSearchCreateFromAttributes(
              pSecKeychain, kSecCertificateItemClass, NULL,
              &pSecKeychainSearch);
          for (;;) {
            SecKeychainItemRef pSecKeychainItem = nil;

            status = SecKeychainSearchCopyNext(pSecKeychainSearch,
                                               &pSecKeychainItem);
            if (status == errSecItemNotFound) {
              break;
            }

            if (status == noErr) {
              void *_pCertData;
              UInt32 _pCertLength;
              status = SecKeychainItemCopyAttributesAndData(
                  pSecKeychainItem, NULL, NULL, NULL, &_pCertLength,
                  &_pCertData);

              if (status == noErr && _pCertData != NULL) {
                unsigned char *ptr;

                ptr = (unsigned char *)_pCertData; /*required because d2i_X509
                                                      is modifying pointer */
                cert =
                    d2i_X509(NULL, (const unsigned char **)&ptr, _pCertLength);
                if (cert == NULL) {
                  continue;
                }

                if (!X509_STORE_add_cert(store, cert)) {
                  X509_free(cert);
                  continue;
                }
                X509_free(cert);

                status = SecKeychainItemFreeAttributesAndData(NULL, _pCertData);
              }
            }
            if (pSecKeychainItem != NULL) {
              CFRelease(pSecKeychainItem);
            }
          }
          CFRelease(pSecKeychainSearch);
          CFRelease(pSecKeychain);
        }
#endif // __APPLE__
      } else {
        ctx.load_verify_file(config.ssl.cert);
      }
      if (config.ssl.verify_hostname) {
#if BOOST_VERSION >= 107300
        ctx.set_verify_callback(ssl::host_name_verification(config.ssl.sni));
#else
        ctx.set_verify_callback(ssl::rfc2818_verification(config.ssl.sni));
#endif
      }
      X509_VERIFY_PARAM *param = X509_VERIFY_PARAM_new();
      X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_PARTIAL_CHAIN);
      SSL_CTX_set1_param(native_context, param);
      X509_VERIFY_PARAM_free(param);
    } else {
      ctx.set_verify_mode(ssl::verify_none);
    }
    if (!config.ssl.alpn.empty()) {
      SSL_CTX_set_alpn_protos(native_context,
                              (unsigned char *)(config.ssl.alpn.c_str()),
                              config.ssl.alpn.length());
    }
    if (config.ssl.reuse_session) {
      SSL_CTX_set_session_cache_mode(native_context, SSL_SESS_CACHE_CLIENT);
      SSLSession::set_callback(native_context);
      if (!config.ssl.session_ticket) {
        SSL_CTX_set_options(native_context, SSL_OP_NO_TICKET);
      }
    } else {
      SSL_CTX_set_options(native_context, SSL_OP_NO_TICKET);
    }
  }
  if (!config.ssl.cipher.empty()) {
    SSL_CTX_set_cipher_list(native_context, config.ssl.cipher.c_str());
  }
  if (!config.ssl.cipher_tls13.empty()) {
#ifdef ENABLE_TLS13_CIPHERSUITES
    SSL_CTX_set_ciphersuites(native_context, config.ssl.cipher_tls13.c_str());
#else  // ENABLE_TLS13_CIPHERSUITES
    Log::log_with_date_time("TLS1.3 ciphersuites are not supported", Log::WARN);
#endif // ENABLE_TLS13_CIPHERSUITES
  }

  if (!test) {
    if (config.tcp.no_delay) {
      socket_acceptor.set_option(tcp::no_delay(true));
    }
    if (config.tcp.keep_alive) {
      socket_acceptor.set_option(boost::asio::socket_base::keep_alive(true));
    }
    if (config.tcp.fast_open) {
#ifdef TCP_FASTOPEN
      using fastopen =
          boost::asio::detail::socket_option::integer<IPPROTO_TCP,
                                                      TCP_FASTOPEN>;
      boost::system::error_code ec;
      socket_acceptor.set_option(fastopen(config.tcp.fast_open_qlen), ec);
#else  // TCP_FASTOPEN
      Log::log_with_date_time("TCP_FASTOPEN is not supported", Log::WARN);
#endif // TCP_FASTOPEN
#ifndef TCP_FASTOPEN_CONNECT
      Log::log_with_date_time("TCP_FASTOPEN_CONNECT is not supported",
                              Log::WARN);
#endif // TCP_FASTOPEN_CONNECT
    }
  }
  if (!config.ssl.keylog_path.empty()) {
#ifdef ENABLE_SSL_KEYLOG
    if (keylog) {
      fclose(keylog);
      keylog = nullptr;
    }
    keylog = fopen(config.ssl.keylog_path.c_str(), "a");
    if (keylog == nullptr) {
      throw std::runtime_error(config.ssl.keylog_path + ": " + strerror(errno));
    }
    SSL_CTX_set_keylog_callback(native_context,
                                [](const SSL *, const char *line) {
                                  fprintf(Service::keylog, "%s\n", line);
                                  fflush(Service::keylog);
                                });
#else  // ENABLE_SSL_KEYLOG
    Log::log_with_date_time("SSL KeyLog is not supported", Log::WARN);
#endif // ENABLE_SSL_KEYLOG
  }
}

void Service::run() {
  async_accept();
  tcp::endpoint local_endpoint = socket_acceptor.local_endpoint();
  std::string rt = "client";
  if (config.run_type == Config::SERVER) {
    rt = "server";
  }
  Log::log_with_date_time(std::string("trojan service (") + rt +
                              ") started at " +
                              local_endpoint.address().to_string() + ':' +
                              std::to_string(local_endpoint.port()),
                          Log::WARN);
  ioc.run();
  Log::log_with_date_time("trojan service stopped", Log::WARN);
}

void Service::stop() {
  boost::system::error_code ec;
  socket_acceptor.cancel(ec);
  if (udp_socket.is_open()) {
    udp_socket.cancel(ec);
    udp_socket.close(ec);
  }
  ioc.stop();
}

void Service::async_accept() {
  socket_acceptor.async_accept(ioc, [this](const boost::system::error_code ec,
                                           tcp::socket socket) {
    if (ec == boost::asio::error::operation_aborted) {
      // got cancel signal, stop calling myself
      return;
    }
    if (!ec) {
      boost::system::error_code ec;
      auto endpoint = socket.remote_endpoint(ec);
      if (!ec) {
        Log::log_with_endpoint(endpoint, "incoming connection");
        switch (config.run_type) {
        case Config::SERVER:
          std::make_shared<ServerSession>(std::move(socket), config, ioc, ctx)
              ->run();
          break;
        default:
          std::make_shared<ClientSession>(std::move(socket), config, ioc, ctx)
              ->run();
          break;
        }
      }
    }
    async_accept();
  });
}

boost::asio::io_context &Service::service() { return ioc; }

void Service::reload_cert() {
  if (config.run_type == Config::SERVER) {
    Log::log_with_date_time("reloading certificate and private key. . . ",
                            Log::WARN);
    ctx.use_certificate_chain_file(config.ssl.cert);
    ctx.use_private_key_file(config.ssl.key, ssl::context::pem);
    boost::system::error_code ec;
    socket_acceptor.cancel(ec);
    async_accept();
    Log::log_with_date_time("certificate and private key reloaded", Log::WARN);
  } else {
    Log::log_with_date_time(
        "cannot reload certificate and private key: wrong run_type",
        Log::ERROR);
  }
}

Service::~Service() {
  if (keylog) {
    fclose(keylog);
    keylog = nullptr;
  }
}
