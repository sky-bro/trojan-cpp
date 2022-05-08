#ifndef INCLUDED_SOCKS5ADDRESS_H
#define INCLUDED_SOCKS5ADDRESS_H

#include <boost/asio/ip/udp.hpp>
#include <cstdint>
#include <string>

class SOCKS5Address {
public:
  enum AddressType { IPv4 = 1, DOMAINNAME = 3, IPv6 = 4 } address_type;
  std::string address;
  uint16_t port;
  bool parse(const std::string &data, size_t &address_len);
  static std::string generate(const boost::asio::ip::udp::endpoint &endpoint);
};

#endif /* INCLUDED_SOCKS5ADDRESS_H */
