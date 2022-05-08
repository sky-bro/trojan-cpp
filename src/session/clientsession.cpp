#include "clientsession.h"
#include "proto/trojanrequest.h"
#include "proto/udppacket.h"
#include "ssl/sslsession.h"
#include <boost/beast/core/error.hpp>
#include <boost/beast/core/stream_traits.hpp>
#include <boost/beast/websocket/rfc6455.hpp>
#include <openssl/ssl.h>
#include <string>

using namespace std;
namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace net = boost::asio;
namespace ssl = net::ssl;
using tcp = boost::asio::ip::tcp;
using udp = boost::asio::ip::udp;

ClientSession::ClientSession(tcp::socket &&socket, const Config &config,
                             net::io_context &ioc, ssl::context &ctx)
    : Session(config, ioc), status(HANDSHAKE), first_packet_recv(false),
      in_socket(move(socket)), out_socket(ioc, ctx) {
  out_socket.binary(true);
}

// tcp::socket &ClientSession::accept_socket() { return in_socket; }

tcp::socket &ClientSession::out_tcp_socket() {
  return out_socket.next_layer().next_layer().socket();
}

void ClientSession::run() {
  boost::system::error_code ec;
  start_time = time(nullptr);
  in_endpoint = in_socket.remote_endpoint(ec);
  if (ec) {
    destroy();
    return;
  }
  auto ssl = out_socket.next_layer().native_handle();
  // static unsigned char protos[] = {8, 'h', 't', 't', 'p', '/', '1', '.',
  // '1'}; SSL_set_alpn_protos(ssl, protos, sizeof(protos));
  if (!config.ssl.sni.empty()) {
    SSL_set_tlsext_host_name(ssl, config.ssl.sni.c_str());
  }
  if (config.ssl.reuse_session) {
    SSL_SESSION *session = SSLSession::get_session();
    if (session) {
      SSL_set_session(ssl, session);
    }
  }
  in_async_read();
}

void ClientSession::in_async_read() {
  auto self = shared_from_this();
  in_socket.async_read_some(
      boost::asio::buffer(in_read_buf, MAX_LENGTH),
      [this, self](const boost::system::error_code ec, size_t length) {
        if (ec == boost::asio::error::operation_aborted) {
          return;
        }
        if (ec) {
          // Log::log("in async read error: " + ec.message(), Log::ERROR);
          destroy();
          return;
        }
        in_recv(string((const char *)in_read_buf, length));
      });
}

void ClientSession::in_async_write(const string &data) {
  auto self = shared_from_this();
  auto data_copy = make_shared<string>(data);
  boost::asio::async_write(
      in_socket, boost::asio::buffer(*data_copy),
      [this, self, data_copy](const boost::system::error_code ec, size_t) {
        if (ec) {
          // Log::log("in async write error:" + ec.message(), Log::ERROR);
          destroy();
          return;
        }
        in_sent();
      });
}

void ClientSession::out_async_read() {
  auto self = shared_from_this();
  auto handle_received = [this, self](beast::error_code ec, size_t length) {
    if (ec) {
      // Log::log("out async read error: " + ec.message(), Log::ERROR);
      destroy();
      return;
    }
    out_recv(std::string((const char *)in_read_buf, length));
  };
  if (use_websocket) { /* websocket stream */
    out_socket.async_read_some(boost::asio::buffer(in_read_buf, MAX_LENGTH),
                               handle_received);
  } else { /* ssl stream */
    out_socket.next_layer().async_read_some(
        boost::asio::buffer(in_read_buf, MAX_LENGTH), handle_received);
  }
}

void ClientSession::out_async_write(const string &data) {
  auto self = shared_from_this();
  auto data_copy = make_shared<string>(data);
  auto handle_sent = [this, self, data_copy](beast::error_code ec, size_t) {
    if (ec) {
      // Log::log("out async write error:" + ec.message(), Log::ERROR);
      destroy();
      return;
    }
    out_sent();
  };
  if (use_websocket) {
    out_socket.async_write(boost::asio::buffer(*data_copy), handle_sent);
  } else {
    net::async_write(out_socket.next_layer(), boost::asio::buffer(*data_copy),
                     handle_sent);
  }
}

void ClientSession::udp_async_read() {
  auto self = shared_from_this();
  udp_socket.async_receive_from(
      boost::asio::buffer(udp_read_buf, MAX_LENGTH), udp_recv_endpoint,
      [this, self](const boost::system::error_code ec, size_t length) {
        if (ec == boost::asio::error::operation_aborted) {
          return;
        }
        if (ec) {
          // Log::log("udp async read error:" + ec.message(), Log::ERROR);
          destroy();
          return;
        }
        udp_recv(string((const char *)udp_read_buf, length), udp_recv_endpoint);
      });
}

void ClientSession::udp_async_write(const string &data,
                                    const udp::endpoint &endpoint) {
  auto self = shared_from_this();
  auto data_copy = make_shared<string>(data);
  udp_socket.async_send_to(
      boost::asio::buffer(*data_copy), endpoint,
      [this, self, data_copy](const boost::system::error_code ec, size_t) {
        if (ec) {
          // Log::log("udp async write error:" + ec.message(), Log::ERROR);
          destroy();
          return;
        }
        udp_sent();
      });
}

void ClientSession::in_recv(const string &data) {
  switch (status) {
  case HANDSHAKE: { /* socks5 verify */
    if (data.length() < 2 || data[0] != 5 ||
        data.length() != (unsigned int)(unsigned char)data[1] + 2) {
      Log::log_with_endpoint(in_endpoint, "unknown protocol", Log::ERROR);
      destroy();
      return;
    }
    bool has_method = false;
    for (int i = 2; i < data[1] + 2; ++i) {
      if (data[i] == 0) {
        has_method = true;
        break;
      }
    }
    if (!has_method) {
      Log::log_with_endpoint(in_endpoint, "unsupported auth method",
                             Log::ERROR);
      in_async_write(string("\x05\xff", 2));
      status = INVALID;
      return;
    }
    in_async_write(string("\x05\x00", 2));
    break;
  }
  case REQUEST: { /* socks5 request: CONNECT or UDP ASSOCIATE */
    if (data.length() < 7 || data[0] != 5 || data[2] != 0) {
      Log::log_with_endpoint(in_endpoint, "bad request", Log::ERROR);
      destroy();
      return;
    }
    // if we use websocket, just send the trojan header with websocket handshake
    /*
      56 + 2 + 1 + 253 + 2 = 314 ()
      hash[password] + "\r\n" + CMD(CONNECT|UDP_ASSOCIATE) + ADDRESS + "\r\n"
     */
    out_write_buf = config.password.cbegin()->first + "\r\n" + data[1] +
                    data.substr(3) + "\r\n";
    if (config.websocket.enabled) {
      string hdr = string(trojan_hdr, beast::detail::base64::encode(
                                          trojan_hdr, out_write_buf.c_str(),
                                          out_write_buf.size()));
      out_socket.set_option(websocket::stream_base::decorator(
          [hdr, this](websocket::request_type &req) {
            req.set(config.websocket.custom_header, hdr);
          }));
    }
    TrojanRequest req;
    if (req.parse(out_write_buf) == -1) {
      Log::log_with_endpoint(in_endpoint, "unsupported command", Log::ERROR);
      in_async_write(string("\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00", 10));
      status = INVALID;
      return;
    }
    if (config.websocket.enabled) {
      /* trojan header will be sent with websocket handshake (instead of after
       * establishing the websocket tunnel) */
      out_write_buf = "";
    }
    is_udp = req.command == TrojanRequest::UDP_ASSOCIATE;
    if (is_udp) {
      udp::endpoint bindpoint(in_socket.local_endpoint().address(), 0);
      boost::system::error_code ec;
      udp_socket.open(bindpoint.protocol(), ec);
      if (ec) {
        destroy();
        return;
      }
      udp_socket.bind(bindpoint);
      Log::log_with_endpoint(
          in_endpoint,
          "requested UDP associate to " + req.address.address + ':' +
              to_string(req.address.port) + ", open UDP socket " +
              udp_socket.local_endpoint().address().to_string() + ':' +
              to_string(udp_socket.local_endpoint().port()) + " for relay",
          Log::INFO);
      in_async_write(string("\x05\x00\x00", 3) +
                     SOCKS5Address::generate(udp_socket.local_endpoint()));
    } else {
      Log::log_with_endpoint(in_endpoint,
                             "requested connection to " + req.address.address +
                                 ':' + to_string(req.address.port),
                             Log::INFO);
      in_async_write(string("\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00", 10));
    }
    break;
  }
  case CONNECT: {
    sent_len += data.length();
    first_packet_recv = true;
    out_write_buf += data;
    break;
  }
  case FORWARD: {
    sent_len += data.length();
    out_async_write(data);
    break;
  }
  case UDP_FORWARD: {
    Log::log_with_endpoint(in_endpoint, "unexpected data from TCP port",
                           Log::ERROR);
    destroy();
    break;
  }
  default:
    break;
  }
}
void ClientSession::handle_tunnel_established() {
  Log::log_with_endpoint(in_endpoint, (use_websocket ? "websocket" : "ssl") +
                                          string(" tunnel established"));
  boost::system::error_code ec;
  if (is_udp) {
    if (!first_packet_recv) {
      udp_socket.cancel(ec);
    }
    status = UDP_FORWARD;
  } else {
    if (!first_packet_recv) {
      in_socket.cancel(ec);
    }
    status = FORWARD;
  }
  out_async_read();
  out_async_write(out_write_buf);
};

void ClientSession::in_sent() {
  switch (status) {
  case HANDSHAKE: {
    status = REQUEST;
    in_async_read();
    break;
  }
  case REQUEST: {
    status = CONNECT;
    // begin to receive first data packet from in_socket
    in_async_read();
    if (is_udp) {
      udp_async_read();
    }
    // at the same time, connect to remote server
    auto self = shared_from_this();
    resolver.async_resolve(
        config.remote_addr, to_string(config.remote_port),
        [this, self](const boost::system::error_code error,
                     const tcp::resolver::results_type &results) {
          if (error || results.empty()) {
            Log::log_with_endpoint(in_endpoint,
                                   "cannot resolve remote server hostname " +
                                       config.remote_addr + ": " +
                                       error.message(),
                                   Log::ERROR);
            destroy();
            return;
          }
          auto iterator = results.begin();
          Log::log_with_endpoint(in_endpoint,
                                 config.remote_addr + " is resolved to " +
                                     iterator->endpoint().address().to_string(),
                                 Log::ALL);
          boost::system::error_code ec;
          out_tcp_socket().open(iterator->endpoint().protocol(), ec);
          if (ec) {
            destroy();
            return;
          }
          if (config.tcp.no_delay) {
            out_tcp_socket().set_option(tcp::no_delay(true));
          }
          if (config.tcp.keep_alive) {
            out_tcp_socket().set_option(
                boost::asio::socket_base::keep_alive(true));
          }
#ifdef TCP_FASTOPEN_CONNECT
          if (config.tcp.fast_open) {
            using fastopen_connect =
                boost::asio::detail::socket_option::boolean<
                    IPPROTO_TCP, TCP_FASTOPEN_CONNECT>;
            boost::system::error_code ec;
            out_tcp_socket().set_option(fastopen_connect(true), ec);
          }
#endif // TCP_FASTOPEN_CONNECT
       // Set a timeout on the operation
          beast::get_lowest_layer(out_socket)
              .expires_after(std::chrono::seconds(30));

          // TCP handshake
          out_tcp_socket().async_connect(
              *iterator, [this, self](const boost::system::error_code error) {
                if (error) {
                  Log::log_with_endpoint(
                      in_endpoint,
                      "cannot establish connection to remote server " +
                          config.remote_addr + ':' +
                          to_string(config.remote_port) + ": " +
                          error.message(),
                      Log::ERROR);
                  destroy();
                  return;
                }
                // SSL handshake
                beast::get_lowest_layer(out_socket)
                    .expires_after(std::chrono::seconds(30));
                out_socket.next_layer().async_handshake(
                    ssl::stream_base::client,
                    [this, self](const boost::system::error_code error) {
                      if (error) {
                        Log::log_with_endpoint(
                            in_endpoint,
                            "SSL handshake failed with " + config.remote_addr +
                                ':' + to_string(config.remote_port) + ": " +
                                error.message(),
                            Log::ERROR);
                        destroy();
                        return;
                      }

                      if (config.ssl.reuse_session) {
                        auto ssl = out_socket.next_layer().native_handle();
                        if (!SSL_session_reused(ssl)) {
                          Log::log_with_endpoint(in_endpoint,
                                                 "SSL session not reused");
                        } else {
                          Log::log_with_endpoint(in_endpoint,
                                                 "SSL session reused");
                        }
                      }

                      if (config.websocket.enabled) {
                        beast::get_lowest_layer(out_socket).expires_never();
                        // Set suggested timeout settings for the websocket
                        out_socket.set_option(
                            websocket::stream_base::timeout::suggested(
                                beast::role_type::client));

                        // Perform the websocket handshake
                        // set Host: to sni:remote_port or
                        // remote_addr:remote_port
                        string host_port = config.ssl.sni.empty()
                                               ? config.remote_addr
                                               : config.ssl.sni;
                        host_port += ":" + to_string(config.remote_port);
                        out_socket.async_handshake(
                            host_port, config.websocket.path,
                            [this, self, host_port](beast::error_code error) {
                              if (error) {
                                Log::log_with_endpoint(
                                    in_endpoint,
                                    "websocket handshake failed with " +
                                        host_port + ": " + error.message(),
                                    Log::ERROR);
                                destroy();
                                return;
                              }
                              use_websocket = true;
                              handle_tunnel_established();
                            });
                      } else {
                        handle_tunnel_established();
                      }
                    });
              });
        });
    break;
  }
  case FORWARD: {
    out_async_read();
    break;
  }
  case INVALID: {
    destroy();
    break;
  }
  default:
    break;
  }
}

void ClientSession::out_recv(const string &data) {
  if (status == FORWARD) {
    recv_len += data.length();
    in_async_write(data);
  } else if (status == UDP_FORWARD) {
    udp_data_buf += data;
    udp_sent();
  }
}

void ClientSession::out_sent() {
  if (status == FORWARD) {
    in_async_read();
  } else if (status == UDP_FORWARD) {
    udp_async_read();
  }
}

void ClientSession::udp_recv(const string &data, const udp::endpoint &) {
  if (data.length() == 0) {
    return;
  }
  if (data.length() < 3 || data[0] || data[1] || data[2]) {
    Log::log_with_endpoint(in_endpoint, "bad UDP packet", Log::ERROR);
    destroy();
    return;
  }
  SOCKS5Address address;
  size_t address_len;
  bool is_addr_valid = address.parse(data.substr(3), address_len);
  if (!is_addr_valid) {
    Log::log_with_endpoint(in_endpoint, "bad UDP packet", Log::ERROR);
    destroy();
    return;
  }
  size_t length = data.length() - 3 - address_len;
  Log::log_with_endpoint(in_endpoint, "sent a UDP packet of length " +
                                          to_string(length) + " bytes to " +
                                          address.address + ':' +
                                          to_string(address.port));
  string packet = data.substr(3, address_len) + char(uint8_t(length >> 8)) +
                  char(uint8_t(length & 0xFF)) + "\r\n" +
                  data.substr(address_len + 3);
  sent_len += length;
  if (status == CONNECT) {
    first_packet_recv = true;
    out_write_buf += packet;
  } else if (status == UDP_FORWARD) {
    out_async_write(packet);
  }
}

void ClientSession::udp_sent() {
  if (status == UDP_FORWARD) {
    UDPPacket packet;
    size_t packet_len;
    bool is_packet_valid = packet.parse(udp_data_buf, packet_len);
    if (!is_packet_valid) {
      if (udp_data_buf.length() > MAX_LENGTH) {
        Log::log_with_endpoint(in_endpoint, "UDP packet too long", Log::ERROR);
        destroy();
        return;
      }
      out_async_read();
      return;
    }
    Log::log_with_endpoint(in_endpoint, "received a UDP packet of length " +
                                            to_string(packet.length) +
                                            " bytes from " +
                                            packet.address.address + ':' +
                                            to_string(packet.address.port));
    SOCKS5Address address;
    size_t address_len;
    bool is_addr_valid = address.parse(udp_data_buf, address_len);
    if (!is_addr_valid) {
      Log::log_with_endpoint(
          in_endpoint, "udp_sent: invalid UDP packet address", Log::ERROR);
      destroy();
      return;
    }
    string reply = string("\x00\x00\x00", 3) +
                   udp_data_buf.substr(0, address_len) + packet.payload;
    udp_data_buf = udp_data_buf.substr(packet_len);
    recv_len += packet.length;
    udp_async_write(reply, udp_recv_endpoint);
  }
}

void ClientSession::destroy() {
  if (status == DESTROY) {
    return;
  }
  status = DESTROY;
  Log::log_with_endpoint(in_endpoint,
                         "disconnected, " + to_string(recv_len) +
                             " bytes received, " + to_string(sent_len) +
                             " bytes sent, lasted for " +
                             to_string(time(nullptr) - start_time) + " seconds",
                         Log::INFO);
  boost::system::error_code ec;
  resolver.cancel();
  if (in_socket.is_open()) {
    in_socket.cancel(ec);
    in_socket.shutdown(tcp::socket::shutdown_both, ec);
    in_socket.close(ec);
  }
  if (udp_socket.is_open()) {
    udp_socket.cancel(ec);
    udp_socket.close(ec);
  }
  if (out_tcp_socket().is_open()) {
    auto self = shared_from_this();
    auto ssl_shutdown_cb = [this, self](const boost::system::error_code error) {
      if (error == boost::asio::error::operation_aborted) {
        return;
      }
      boost::system::error_code ec;
      ssl_shutdown_timer.cancel();
      out_tcp_socket().cancel(ec);
      out_tcp_socket().shutdown(tcp::socket::shutdown_both, ec);
      out_tcp_socket().close(ec);
    };

    if (use_websocket) {
      // websocket close will close underlying stream for us
      out_socket.async_close(websocket::close_code::normal,
                             [self](beast::error_code ec) {
                               if (ec) {
                                 // Log::log("close websocket error: " +
                                 // ec.message(), Log::ERROR);
                               }
                             });
    } else {
      out_tcp_socket().cancel(ec);
      out_socket.next_layer().async_shutdown(ssl_shutdown_cb);
      ssl_shutdown_timer.expires_after(chrono::seconds(SSL_SHUTDOWN_TIMEOUT));
      ssl_shutdown_timer.async_wait(ssl_shutdown_cb);
    }
  }
}
