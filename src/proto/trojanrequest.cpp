#include "trojanrequest.h"
#include <string>

using namespace std;

int TrojanRequest::parse(const string &data) {
  size_t first = data.find("\r\n");
  if (first == string::npos) {
    return -1;
  }
  password = data.substr(0, first);
  payload = data.substr(first + 2);
  if (payload.length() == 0 ||
      (payload[0] != CONNECT && payload[0] != UDP_ASSOCIATE)) {
    return -1;
  }
  command = static_cast<Command>(payload[0]);
  size_t address_len;
  bool is_addr_valid = address.parse(payload.substr(1), address_len);
  if (!is_addr_valid || payload.length() < address_len + 3 ||
      payload.substr(address_len + 1, 2) != "\r\n") {
    return -1;
  }
  payload = payload.substr(address_len + 3);
  return data.length();
}

string TrojanRequest::generate(const string &password, const string &domainname,
                               uint16_t port, bool tcp) {
  string ret = password + "\r\n";
  if (tcp) {
    ret += '\x01';
  } else {
    ret += '\x03';
  }
  ret += '\x03';
  ret += char(uint8_t(domainname.length()));
  ret += domainname;
  ret += char(uint8_t(port >> 8));
  ret += char(uint8_t(port & 0xFF));
  ret += "\r\n";
  return ret;
}
