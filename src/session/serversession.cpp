#include "serversession.h"
#include "core/log.h"
#include "proto/trojanrequest.h"
#include "proto/udppacket.h"
#include <boost/asio/buffer.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/beast/core/detail/base64.hpp>
#include <boost/beast/core/error.hpp>
#include <boost/beast/core/stream_traits.hpp>
#include <boost/beast/http/message.hpp>
#include <boost/beast/http/parser.hpp>
#include <boost/beast/http/read.hpp>
#include <boost/beast/http/string_body.hpp>
#include <boost/beast/websocket/rfc6455.hpp>
#include <openssl/x509v3.h>
#include <string>

using namespace std;
namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace net = boost::asio;
namespace ssl = net::ssl;
using tcp = boost::asio::ip::tcp;
using udp = boost::asio::ip::udp;

ServerSession::ServerSession(tcp::socket &&socket, const Config &config,
                             net::io_context &ioc, ssl::context &ctx)
    : Session(config, ioc), status(HANDSHAKE),
      in_socket(std::move(socket), ctx), out_socket(ioc), udp_resolver(ioc) {
  in_socket.binary(true);
}

// tcp::socket &ServerSession::accept_socket() {
//   return (tcp::socket &)boost::beast::get_lowest_layer(in_socket);
// }

tcp::socket &ServerSession::in_tcp_socket() {
  return in_socket.next_layer().next_layer().socket();
}

void ServerSession::try_forward(READY_FLAG new_ready_flag) {
  if (ready_flag == BOTH_READY)
    return;
  ready_flag |= new_ready_flag;
  if (ready_flag == BOTH_READY) {
    if (!out_write_buf.empty()) {
      out_async_write(out_write_buf);
    } else if (!udp_data_buf.empty()) {
      udp_sent();
    } else {
      in_async_read();
    }
    if (status == FORWARD)
      out_async_read();
    // else if (status == UDP_FORWARD)
    //   udp_async_read();
  }
}

void ServerSession::run() {
  boost::system::error_code ec;
  start_time = time(nullptr);
  in_endpoint = in_tcp_socket().remote_endpoint(ec);
  if (ec) {
    destroy();
    return;
  }
  // SSL handshake
  auto self = shared_from_this();
  beast::get_lowest_layer(in_socket).expires_after(std::chrono::seconds(30));
  in_socket.next_layer().async_handshake(
      ssl::stream_base::server, [this, self](beast::error_code ec) {
        if (ec) {
          Log::log_with_endpoint(
              in_endpoint, "SSL handshake failed: " + ec.message(), Log::ERROR);
          destroy();
          return;
        }

        // read tls payload, expecting (http, websocket upgrade, old trojan)
        in_socket.next_layer().async_read_some(
            net::buffer(in_read_buf, MAX_LENGTH),
            [this, self](const boost::system::error_code error, size_t length) {
              if (error) {
                destroy();
                return;
              }
              handle_http_request(string((const char *)in_read_buf, length));
            });
      });
}

void ServerSession::in_async_read() {
  // read: tls stream or wss stream
  auto self = shared_from_this();
  auto handle_received = [this, self](beast::error_code ec, size_t length) {
    if (ec) {
      // Log::log("in async read error: " + ec.message(), Log::ERROR);
      destroy();
      return;
    }
    in_recv(std::string((const char *)in_read_buf, length));
  };
  if (use_websocket) { /* websocket stream */
    in_socket.async_read_some(boost::asio::buffer(in_read_buf, MAX_LENGTH),
                              handle_received);
  } else { /* ssl stream */
    in_socket.next_layer().async_read_some(
        boost::asio::buffer(in_read_buf, MAX_LENGTH), handle_received);
  }
}

void ServerSession::in_async_write(const std::string &data) {
  auto self = shared_from_this();
  auto data_copy = std::make_shared<std::string>(data);
  auto handle_sent = [this, self, data_copy](beast::error_code ec, size_t) {
    if (ec) {
      // Log::log("in async write error:" + ec.message(), Log::ERROR);
      destroy();
      return;
    }
    in_sent();
  };
  if (use_websocket) {
    in_socket.async_write(boost::asio::buffer(*data_copy), handle_sent);
  } else {
    net::async_write(in_socket.next_layer(), boost::asio::buffer(*data_copy),
                     handle_sent);
  }
}

void ServerSession::out_async_read() {
  auto self = shared_from_this();
  out_socket.async_read_some(
      boost::asio::buffer(out_read_buf, MAX_LENGTH),
      [this, self](const boost::system::error_code ec, size_t length) {
        if (ec) {
          // Log::log("out async read error:" + ec.message(), Log::ERROR);
          destroy();
          return;
        }
        out_recv(std::string((const char *)out_read_buf, length));
      });
}

void ServerSession::out_async_write(const std::string &data) {
  auto self = shared_from_this();
  auto data_copy = std::make_shared<std::string>(data);
  boost::asio::async_write(
      out_socket, boost::asio::buffer(*data_copy),
      [this, self, data_copy](const boost::system::error_code ec, size_t) {
        if (ec) {
          // Log::log("out async write error:" + ec.message(), Log::ERROR);
          destroy();
          return;
        }
        out_sent();
      });
}

void ServerSession::udp_async_read() {
  auto self = shared_from_this();
  udp_socket.async_receive_from(
      boost::asio::buffer(udp_read_buf, MAX_LENGTH), udp_recv_endpoint,
      [this, self](const boost::system::error_code ec, size_t length) {
        if (ec) {
          // Log::log("udp async read error:" + ec.message(), Log::ERROR);
          destroy();
          return;
        }
        udp_recv(std::string((const char *)udp_read_buf, length),
                 udp_recv_endpoint);
      });
}

void ServerSession::udp_async_write(const string &data,
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

void ServerSession::handle_http_request(const string &data) {
  beast::error_code ec;
  req_parser.put(net::buffer(data), ec);
  /* trojan over websocket */
  if (!ec && websocket::is_upgrade(req_parser.get()) &&     /* websocket */
      req_parser.get().target() == config.websocket.path && /* right path */
      req_parser.get().find(config.websocket.custom_header) !=
          req_parser.get().end()) { /* right custom_header */
    auto custom_header = req_parser.get().find(config.websocket.custom_header);
    if (custom_header != req_parser.get().end()) {
      use_websocket = true;
      string trojan_req =
          string(trojan_hdr,
                 beast::detail::base64::decode(
                     trojan_hdr, custom_header->value().to_string().c_str(),
                     custom_header->value().size())
                     .first);
      if (handle_trojan_request(trojan_req)) {
        beast::get_lowest_layer(in_socket).expires_never();
        // Set suggested timeout settings for the websocket
        in_socket.set_option(websocket::stream_base::timeout::suggested(
            beast::role_type::server));
        // Accept the websocket handshake
        auto self = shared_from_this();
        auto req = req_parser.get();
        in_socket.async_accept(req, [this, self](beast::error_code ec) {
          if (ec) {
            Log::log_with_endpoint(
                in_endpoint, "websocket handshake failed: " + ec.message(),
                Log::ERROR);
            destroy();
            return;
          }
          try_forward(IN_READY);
        });
      };
    } else {
      // treat as normal http
      ready_flag |= IN_READY;
      in_recv(data);
      return;
    }
  } else { /* normal http or traditional trojan */
    ready_flag |= IN_READY;
    in_recv(data);
  }
}

bool ServerSession::handle_trojan_request(const std::string &data) {
  TrojanRequest req;
  bool valid = req.parse(data) != -1;
  if (valid) {
    auto password_iterator = config.password.find(req.password);
    if (password_iterator == config.password.end()) {
      valid = false;
    } else {
      Log::log_with_endpoint(in_endpoint,
                             "authenticated as " + password_iterator->second,
                             Log::INFO);
    }
    if (!valid) {
      Log::log_with_endpoint(
          in_endpoint,
          "valid trojan request structure but possibly incorrect password (" +
              req.password + ')',
          Log::WARN);
    }
  }
  std::string query_addr = valid ? req.address.address : config.remote_addr;
  std::string query_port = to_string([&]() {
    if (valid) {
      return req.address.port;
    }
    const unsigned char *alpn_out;
    unsigned int alpn_len;
    SSL_get0_alpn_selected(in_socket.next_layer().native_handle(), &alpn_out,
                           &alpn_len);
    if (alpn_out == nullptr) {
      return config.remote_port;
    }
    auto it = config.ssl.alpn_port_override.find(
        std::string(alpn_out, alpn_out + alpn_len));
    return it == config.ssl.alpn_port_override.end() ? config.remote_port
                                                     : it->second;
  }());
  if (valid) {
    out_write_buf = req.payload; // should be empty for websocket trojan
    if (req.command == TrojanRequest::UDP_ASSOCIATE) {
      Log::log_with_endpoint(in_endpoint,
                             "requested UDP associate to " +
                                 req.address.address + ':' +
                                 to_string(req.address.port),
                             Log::INFO);
      status = UDP_FORWARD;
      udp_data_buf = out_write_buf;
      out_write_buf = "";
      try_forward(OUT_READY);
      return true;
    } else {
      Log::log_with_endpoint(in_endpoint,
                             "requested connection to " + req.address.address +
                                 ':' + to_string(req.address.port),
                             Log::INFO);
    }
  } else {
    Log::log_with_endpoint(in_endpoint,
                           "not trojan request, connecting to " + query_addr +
                               ':' + query_port,
                           Log::WARN);
    out_write_buf = data;
  }
  /* relay: real server or my fake server */
  sent_len += out_write_buf.length();
  auto self = shared_from_this();
  resolver.async_resolve(
      query_addr, query_port,
      [this, self, query_addr,
       query_port](const boost::system::error_code error,
                   const tcp::resolver::results_type &results) {
        if (error || results.empty()) {
          Log::log_with_endpoint(in_endpoint,
                                 "cannot resolve remote server hostname " +
                                     query_addr + ": " + error.message(),
                                 Log::ERROR);
          destroy();
          return;
        }
        auto iterator = results.begin();
        if (config.tcp.prefer_ipv4) {
          for (auto it = results.begin(); it != results.end(); ++it) {
            const auto &addr = it->endpoint().address();
            if (addr.is_v4()) {
              iterator = it;
              break;
            }
          }
        }
        Log::log_with_endpoint(in_endpoint,
                               query_addr + " is resolved to " +
                                   iterator->endpoint().address().to_string(),
                               Log::ALL);
        boost::system::error_code ec;
        out_socket.open(iterator->endpoint().protocol(), ec);
        if (ec) {
          destroy();
          return;
        }
        if (config.tcp.no_delay) {
          out_socket.set_option(tcp::no_delay(true));
        }
        if (config.tcp.keep_alive) {
          out_socket.set_option(boost::asio::socket_base::keep_alive(true));
        }
#ifdef TCP_FASTOPEN_CONNECT
        if (config.tcp.fast_open) {
          using fastopen_connect =
              boost::asio::detail::socket_option::boolean<IPPROTO_TCP,
                                                          TCP_FASTOPEN_CONNECT>;
          boost::system::error_code ec;
          out_socket.set_option(fastopen_connect(true), ec);
        }
#endif // TCP_FASTOPEN_CONNECT
        out_socket.async_connect(
            *iterator, [this, self, query_addr,
                        query_port](const boost::system::error_code error) {
              if (error) {
                Log::log_with_endpoint(
                    in_endpoint,
                    "cannot establish connection to remote server " +
                        query_addr + ':' + query_port + ": " + error.message(),
                    Log::ERROR);
                destroy();
                return;
              }
              Log::log_with_endpoint(in_endpoint,
                                     (use_websocket ? "websocket" : "ssl") +
                                         string(" tunnel established"));
              status = FORWARD;
              try_forward(OUT_READY);
              // what if no packet to send, and in_socket not ready?
              // if (!out_write_buf.empty()) {
              //   out_async_write(out_write_buf);
              // } else if (!use_websocket) {
              //   // if use websocket, call read after handshake done
              //   in_async_read();
              // }
            });
      });
  return valid;
}

void ServerSession::in_recv(const std::string &data) {
  if (status == HANDSHAKE) {
    handle_trojan_request(data);
  } else if (status == FORWARD) {
    sent_len += data.length();
    out_async_write(data);
  } else if (status == UDP_FORWARD) {
    udp_data_buf += data;
    udp_sent();
  }
}

void ServerSession::in_sent() {
  if (status == FORWARD) {
    out_async_read();
  } else if (status == UDP_FORWARD) {
    udp_async_read();
  }
}

void ServerSession::out_recv(const std::string &data) {
  if (status == FORWARD) {
    recv_len += data.length();
    in_async_write(data);
  }
}

void ServerSession::out_sent() {
  if (status == FORWARD) {
    in_async_read();
  }
}

void ServerSession::udp_recv(const std::string &data,
                             const udp::endpoint &endpoint) {
  if (status == UDP_FORWARD) {
    size_t length = data.length();
    Log::log_with_endpoint(in_endpoint, "received a UDP packet of length " +
                                            to_string(length) + " bytes from " +
                                            endpoint.address().to_string() +
                                            ':' + to_string(endpoint.port()));
    recv_len += length;
    in_async_write(UDPPacket::generate(endpoint, data));
  }
}

void ServerSession::udp_sent() {
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
      in_async_read();
      return;
    }
    Log::log_with_endpoint(
        in_endpoint, "sent a UDP packet of length " + to_string(packet.length) +
                         " bytes to " + packet.address.address + ':' +
                         to_string(packet.address.port));
    udp_data_buf = udp_data_buf.substr(packet_len);
    std::string query_addr = packet.address.address;
    auto self = shared_from_this();
    udp_resolver.async_resolve(
        query_addr, to_string(packet.address.port),
        [this, self, packet,
         query_addr](const boost::system::error_code error,
                     const udp::resolver::results_type &results) {
          if (error || results.empty()) {
            Log::log_with_endpoint(in_endpoint,
                                   "cannot resolve remote server hostname " +
                                       query_addr + ": " + error.message(),
                                   Log::ERROR);
            destroy();
            return;
          }
          auto iterator = results.begin();
          if (config.tcp.prefer_ipv4) {
            for (auto it = results.begin(); it != results.end(); ++it) {
              const auto &addr = it->endpoint().address();
              if (addr.is_v4()) {
                iterator = it;
                break;
              }
            }
          }
          Log::log_with_endpoint(in_endpoint,
                                 query_addr + " is resolved to " +
                                     iterator->endpoint().address().to_string(),
                                 Log::ALL);
          if (!udp_socket.is_open()) {
            auto protocol = iterator->endpoint().protocol();
            boost::system::error_code ec;
            udp_socket.open(protocol, ec);
            if (ec) {
              destroy();
              return;
            }
            udp_socket.bind(udp::endpoint(protocol, 0));
            udp_async_read();
          }
          sent_len += packet.length;
          udp_async_write(packet.payload, *iterator);
        });
  }
}

void ServerSession::destroy() {
  if (status == DESTROY) {
    return;
  }
  status = DESTROY;
  Log::log_with_endpoint(
      in_endpoint,
      "disconnected, " + std::to_string(recv_len) + " bytes received, " +
          std::to_string(sent_len) + " bytes sent, lasted for " +
          std::to_string(time(nullptr) - start_time) + " seconds",
      Log::INFO);
  beast::error_code ec;
  resolver.cancel();
  udp_resolver.cancel();
  if (out_socket.is_open()) {
    out_socket.cancel(ec);
    out_socket.shutdown(tcp::socket::shutdown_both, ec);
    out_socket.close(ec);
  }
  if (udp_socket.is_open()) {
    udp_socket.cancel(ec);
    udp_socket.close(ec);
  }
  if (in_tcp_socket().is_open()) {
    auto self = shared_from_this();
    auto ssl_shutdown_cb = [this, self](beast::error_code ec) {
      if (ec == boost::asio::error::operation_aborted) {
        return;
      }
      ssl_shutdown_timer.cancel();
      in_tcp_socket().cancel(ec);
      in_tcp_socket().shutdown(tcp::socket::shutdown_both, ec);
      in_tcp_socket().close(ec);
    };
    if (use_websocket) {
      // websocket close will close underlying stream for us
      // https://www.boost.org/doc/libs/1_69_0/libs/beast/doc/html/beast/using_websocket/teardown.html
      in_socket.async_close(websocket::close_code::normal,
                            [self](beast::error_code ec) {
                              if (ec) {
                                // Log::log("close websocket error: " +
                                // ec.message(), Log::ERROR);
                              }
                            });
    } else {
      in_tcp_socket().cancel(ec);
      in_socket.next_layer().async_shutdown(ssl_shutdown_cb);
      ssl_shutdown_timer.expires_after(chrono::seconds(SSL_SHUTDOWN_TIMEOUT));
      ssl_shutdown_timer.async_wait(ssl_shutdown_cb);
    }
  }
}
