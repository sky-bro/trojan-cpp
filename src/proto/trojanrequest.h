#ifndef INCLUDED_TROJANREQUEST_H
#define INCLUDED_TROJANREQUEST_H

#include "socks5address.h"

class TrojanRequest {
public:
  std::string password;
  enum Command { CONNECT = 1, UDP_ASSOCIATE = 3 } command;
  SOCKS5Address address;
  std::string payload;
  int parse(const std::string &data);
  static std::string generate(const std::string &password,
                              const std::string &domainname, uint16_t port,
                              bool tcp);
};

#endif /* INCLUDED_TROJANREQUEST_H */
