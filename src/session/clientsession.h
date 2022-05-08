#ifndef INCLUDED_CLIENTSESSION_H
#define INCLUDED_CLIENTSESSION_H

#include "session.h"
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/ssl/ssl_stream.hpp>
#include <boost/beast/websocket/stream.hpp>

class ClientSession : public Session {
private:
  enum Status {
    HANDSHAKE,
    REQUEST,
    CONNECT,
    FORWARD,
    UDP_FORWARD,
    INVALID,
    DESTROY
  } status;
  bool is_udp{};
  bool first_packet_recv;
  boost::asio::ip::tcp::socket in_socket;
  // boost::asio::ssl::stream<boost::asio::ip::tcp::socket> out_socket;
  boost::beast::websocket::stream<
      boost::beast::ssl_stream<boost::beast::tcp_stream>>
      out_socket; // wss
  void destroy();
  void in_async_read();
  void handle_tunnel_established();
  void in_async_write(const std::string &data);
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
  boost::asio::ip::tcp::socket &out_tcp_socket();

public:
  ClientSession(boost::asio::ip::tcp::socket &&socket, const Config &config,
                boost::asio::io_context &ioc, boost::asio::ssl::context &ctx);
  // boost::asio::ip::tcp::socket &accept_socket() override;
  void run() override;
};

#endif /* INCLUDED_CLIENTSESSION_H */
