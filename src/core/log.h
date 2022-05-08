#ifndef INCLUDED_LOG_H
#define INCLUDED_LOG_H

#include <boost/asio/ip/tcp.hpp>
#include <cstdio>
#include <string>

#ifdef ERROR // windows.h
#undef ERROR
#endif // ERROR

class Log {
public:
  enum Level { ALL = 0, INFO = 1, WARN = 2, ERROR = 3, FATAL = 4, OFF = 5 };
  typedef std::function<void(const std::string &, Level)> LogCallback;
  static Level level;
  static void log(const std::string &message, Level level = ALL);
  static void log_with_date_time(const std::string &message, Level level = ALL);
  static void log_with_endpoint(const boost::asio::ip::tcp::endpoint &endpoint,
                                const std::string &message, Level level = ALL);
  static void redirect(const std::string &filename);
  static void set_callback(LogCallback cb);
  static void reset();

private:
  static FILE *output_stream;
  static LogCallback log_callback;
};

#endif /* INCLUDED_LOG_H */
