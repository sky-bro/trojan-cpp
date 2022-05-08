#ifndef INCLUDED_SERVERSESSION_H
#define INCLUDED_SERVERSESSION_H

#include "session.h"
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/http/parser.hpp>
#include <boost/beast/http/string_body.hpp>
#include <boost/beast/ssl/ssl_stream.hpp>
#include <boost/beast/websocket/stream.hpp>

class ServerSession : public Session {
private:
  enum Status { HANDSHAKE, FORWARD, UDP_FORWARD, DESTROY } status;
  enum READY_FLAG {
    NONE_READY = 0,
    IN_READY = 1,
    OUT_READY = 2,
    BOTH_READY = 3
  };
  int ready_flag = 0;
  boost::beast::websocket::stream<
      boost::beast::ssl_stream<boost::beast::tcp_stream>>
      in_socket; // wss
  boost::beast::http::request_parser<boost::beast::http::string_body>
      req_parser;
  boost::asio::ip::tcp::socket out_socket;
  boost::asio::ip::udp::resolver udp_resolver;
  std::string auth_password;
  void try_forward(READY_FLAG);
  void destroy();
  void in_async_read();
  void in_async_write(const std::string &data);
  void handle_http_request(const std::string &data);
  bool handle_trojan_request(const std::string &data);
  void in_recv(const std::string &data);
  void in_sent();
  void out_async_read();
  void out_async_write(const std::string &data);
  void out_recv(const std::string &data);
  void out_sent();
  void udp_async_read();
  void udp_async_write(const std::string &data,
                       const boost::asio::ip::udp::endpoint &endpoint);
  void udp_recv(const std::string &data,
                const boost::asio::ip::udp::endpoint &endpoint);
  void udp_sent();
  boost::asio::ip::tcp::socket &in_tcp_socket();

public:
  ServerSession(boost::asio::ip::tcp::socket &&socket, const Config &config,
                boost::asio::io_context &ioc, boost::asio::ssl::context &ctx);
  // boost::asio::ip::tcp::socket &accept_socket() override;
  void run() override;
};

#endif /* INCLUDED_SERVERSESSION_H */
