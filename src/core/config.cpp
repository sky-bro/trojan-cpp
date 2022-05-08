#include "config.h"
#include <boost/property_tree/json_parser.hpp>
#include <cstdlib>
#include <openssl/evp.h>
#include <sstream>
#include <stdexcept>
#include <string>
using namespace std;
using namespace boost::property_tree;

void Config::load(const string &filename) {
  ptree tree;
  read_json(filename, tree);
  populate(tree);
}

void Config::populate(const string &JSON) {
  istringstream s(JSON);
  ptree tree;
  read_json(s, tree);
  populate(tree);
}

string Config::SHA224(const string &message) {
  uint8_t digest[EVP_MAX_MD_SIZE];
  char mdString[(EVP_MAX_MD_SIZE << 1) + 1];
  unsigned int digest_len;
  EVP_MD_CTX *ctx;
  if ((ctx = EVP_MD_CTX_new()) == nullptr) {
    throw runtime_error("could not create hash context");
  }
  if (!EVP_DigestInit_ex(ctx, EVP_sha224(), nullptr)) {
    EVP_MD_CTX_free(ctx);
    throw runtime_error("could not initialize hash context");
  }
  if (!EVP_DigestUpdate(ctx, message.c_str(), message.length())) {
    EVP_MD_CTX_free(ctx);
    throw runtime_error("could not update hash");
  }
  if (!EVP_DigestFinal_ex(ctx, digest, &digest_len)) {
    EVP_MD_CTX_free(ctx);
    throw runtime_error("could not output hash");
  }

  for (unsigned int i = 0; i < digest_len; ++i) {
    sprintf(mdString + (i << 1), "%02x", (unsigned int)digest[i]);
  }
  mdString[digest_len << 1] = '\0';
  EVP_MD_CTX_free(ctx);
  return string(mdString);
}

void Config::populate(const ptree &tree) {
  string rt = tree.get("run_type", string("client"));
  if (rt == "server") {
    run_type = SERVER;
  } else if (rt == "client") {
    run_type = CLIENT;
  } else {
    throw runtime_error("wrong run_type in config file");
  }
  local_addr = tree.get("local_addr", string());
  local_port = tree.get("local_port", uint16_t());
  remote_addr = tree.get("remote_addr", string());
  remote_port = tree.get("remote_port", uint16_t());
  target_addr = tree.get("target_addr", string());
  target_port = tree.get("target_port", uint16_t());
  map<string, string>().swap(password);
  if (tree.get_child_optional("password")) {
    for (auto &item : tree.get_child("password")) {
      string p = item.second.get_value<string>();
      password[SHA224(p)] = p;
    }
  }
  udp_timeout = tree.get("udp_timeout", 60);
  log_level = static_cast<Log::Level>(tree.get("log_level", 1));
  ssl.verify = tree.get("ssl.verify", true);
  ssl.verify_hostname = tree.get("ssl.verify_hostname", true);
  ssl.cert = tree.get("ssl.cert", string());
  ssl.key = tree.get("ssl.key", string());
  ssl.key_password = tree.get("ssl.key_password", string());
  ssl.keylog_path = tree.get("ssl.keylog_path", string());
  ssl.cipher = tree.get("ssl.cipher", string());
  ssl.cipher_tls13 = tree.get("ssl.cipher_tls13", string());
  ssl.prefer_server_cipher = tree.get("ssl.prefer_server_cipher", true);
  ssl.sni = tree.get("ssl.sni", string());
  ssl.alpn = "";
  if (tree.get_child_optional("ssl.alpn")) {
    for (auto &item : tree.get_child("ssl.alpn")) {
      string proto = item.second.get_value<string>();
      ssl.alpn += (char)((unsigned char)(proto.length()));
      ssl.alpn += proto;
    }
  }
  map<string, uint16_t>().swap(ssl.alpn_port_override);
  if (tree.get_child_optional("ssl.alpn_port_override")) {
    for (auto &item : tree.get_child("ssl.alpn_port_override")) {
      ssl.alpn_port_override[item.first] = item.second.get_value<uint16_t>();
    }
  }
  ssl.reuse_session = tree.get("ssl.reuse_session", true);
  ssl.session_ticket = tree.get("ssl.session_ticket", false);
  ssl.session_timeout = tree.get("ssl.session_timeout", long(600));
  ssl.plain_http_response = tree.get("ssl.plain_http_response", string());
  ssl.curves = tree.get("ssl.curves", string());
  ssl.dhparam = tree.get("ssl.dhparam", string());
  tcp.prefer_ipv4 = tree.get("tcp.prefer_ipv4", false);
  tcp.no_delay = tree.get("tcp.no_delay", true);
  tcp.keep_alive = tree.get("tcp.keep_alive", true);
  tcp.reuse_port = tree.get("tcp.reuse_port", false);
  tcp.fast_open = tree.get("tcp.fast_open", false);
  tcp.fast_open_qlen = tree.get("tcp.fast_open_qlen", 20);
  websocket.enabled = tree.get("websocket.enabled", false);
  websocket.path = tree.get("websocket.path", "/trojan");
  websocket.custom_header = tree.get("websocket.custom_header", "trojan-hdr");
}
