#include "session.h"

Session::Session(const Config &config, boost::asio::io_context &ioc)
    : config(config), recv_len(0), sent_len(0), resolver(ioc), udp_socket(ioc),
      ssl_shutdown_timer(ioc) {}

Session::~Session() = default;
