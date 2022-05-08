#ifndef INCLUDED_SERVICE_H
#define INCLUDED_SERVICE_H

#include "core/config.h"
#include "core/log.h"
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ssl.hpp>

class Service {
private:
  enum { MAX_LENGTH = 8192 };
  const Config &config;
  boost::asio::io_context ioc;
  boost::asio::ip::tcp::acceptor socket_acceptor;
  boost::asio::ssl::context ctx;
  static FILE *keylog;
  std::string plain_http_response;
  boost::asio::ip::udp::socket udp_socket;
  uint8_t udp_read_buf[MAX_LENGTH]{};
  boost::asio::ip::udp::endpoint udp_recv_endpoint;
  void async_accept();

public:
  explicit Service(Config &config, bool test = false);
  void run();
  void stop();
  boost::asio::io_context &service();
  void reload_cert();
  ~Service();
};

#endif /* INCLUDED_SERVICE_H */
