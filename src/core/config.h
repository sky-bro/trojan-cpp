#ifndef INCLUDED_CONFIG_H
#define INCLUDED_CONFIG_H

#include "log.h"
#include <boost/property_tree/ptree.hpp>
#include <cstdint>
#include <map>

class Config {
public:
  enum RunType { SERVER, CLIENT } run_type;
  std::string local_addr;
  uint16_t local_port;
  std::string remote_addr;
  uint16_t remote_port;
  std::string target_addr;
  uint16_t target_port;
  std::map<std::string, std::string> password;
  int udp_timeout;
  Log::Level log_level;
  class SSLConfig {
  public:
    bool verify;
    bool verify_hostname;
    std::string cert;
    std::string key;
    std::string key_password;
    std::string keylog_path;
    std::string cipher;
    std::string cipher_tls13;
    bool prefer_server_cipher;
    std::string sni;
    std::string alpn;
    std::map<std::string, uint16_t> alpn_port_override;
    bool reuse_session;
    bool session_ticket;
    long session_timeout;
    std::string plain_http_response;
    std::string curves;
    std::string dhparam;
  } ssl;
  class TCPConfig {
  public:
    bool prefer_ipv4;
    bool no_delay;
    bool keep_alive;
    bool reuse_port;
    bool fast_open;
    int fast_open_qlen;
  } tcp;
  class WebSocketConfig {
  public:
    bool enabled;
    std::string path;
    std::string custom_header;
  } websocket;
  void load(const std::string &filename);
  void populate(const std::string &JSON);
  static std::string SHA224(const std::string &message);

private:
  void populate(const boost::property_tree::ptree &tree);
};

#endif /* INCLUDED_CONFIG_H */
