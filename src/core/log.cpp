#include "log.h"
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/date_time/posix_time/posix_time_io.hpp>
#include <cerrno>
#include <cstring>
#include <sstream>
#include <stdexcept>
#ifdef ENABLE_ANDROID_LOG
#include <android/log.h>
#endif // ENABLE_ANDROID_LOG
using namespace std;
using namespace boost::posix_time;
using namespace boost::asio::ip;

Log::Level Log::level(INFO);
FILE *Log::output_stream(stderr);
Log::LogCallback Log::log_callback{};

void Log::log(const string &message, Level level) {
  if (level >= Log::level) {
#ifdef ENABLE_ANDROID_LOG
    __android_log_print(ANDROID_LOG_ERROR, "trojan", "%s\n", message.c_str());
#else
    fprintf(output_stream, "%s\n", message.c_str());
    fflush(output_stream);
#endif // ENABLE_ANDROID_LOG
    if (log_callback) {
      log_callback(message, level);
    }
  }
}

void Log::log_with_date_time(const string &message, Level level) {
  static const char *level_strings[] = {"ALL",   "INFO",  "WARN",
                                        "ERROR", "FATAL", "OFF"};
  auto *facet = new time_facet("[%Y-%m-%d %H:%M:%S] ");
  ostringstream stream;
  stream.imbue(locale(stream.getloc(), facet));
  stream << second_clock::local_time();
  string level_string = '[' + string(level_strings[level]) + "] ";
  log(stream.str() + level_string + message, level);
}

void Log::log_with_endpoint(const tcp::endpoint &endpoint,
                            const string &message, Level level) {
  log_with_date_time(endpoint.address().to_string() + ':' +
                         to_string(endpoint.port()) + ' ' + message,
                     level);
}

void Log::redirect(const string &filename) {
  FILE *fp = fopen(filename.c_str(), "a");
  if (fp == nullptr) {
    throw runtime_error(filename + ": " + strerror(errno));
  }
  if (output_stream != stderr) {
    fclose(output_stream);
  }
  output_stream = fp;
}

void Log::set_callback(LogCallback cb) { log_callback = move(cb); }

void Log::reset() {
  if (output_stream != stderr) {
    fclose(output_stream);
    output_stream = stderr;
  }
}
