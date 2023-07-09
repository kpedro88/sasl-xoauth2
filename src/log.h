/*
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SASL_XOAUTH2_LOG_H
#define SASL_XOAUTH2_LOG_H

#include <memory>
#include <string>
#include <vector>
#include <sys/time.h>
#include <time.h>
#include <stdio.h>
#include <stdexcept>

namespace {

//from https://stackoverflow.com/questions/2342162/stdstring-formatting-like-sprintf
template<typename ... Args>
std::string string_format(const std::string& format, const Args& ... args)
{
    int size_s = std::snprintf( nullptr, 0, format.c_str(), args ... ) + 1; // Extra space for '\0'
    if( size_s <= 0 ){ throw std::runtime_error( "Error during formatting." ); }
    auto size = static_cast<size_t>( size_s );
    std::unique_ptr<char[]> buf( new char[ size ] );
    std::snprintf( buf.get(), size, format.c_str(), args ... );
    return std::string( buf.get(), buf.get() + size - 1 ); // We don't want the '\0' inside
}

std::string Now() {
  time_t t = time(nullptr);
  char time_str[32];
  tm local_time = {};
  localtime_r(&t, &local_time);
  strftime(time_str, sizeof(time_str), "%F %T", &local_time);
  return std::string(time_str);
}

}  // namespace


namespace sasl_xoauth2 {

void EnableLoggingForTesting();

class Log {
 public:
  enum Options {
    OPTIONS_NONE = 0,
    OPTIONS_IMMEDIATE = 1,
    OPTIONS_FULL_TRACE_ON_FAILURE = 2,
    OPTIONS_FLUSH_ON_DESTROY = 4,
  };

  enum Target {
    TARGET_DEFAULT = 0,
    TARGET_NONE = 1,
    TARGET_SYSLOG = 2,
    TARGET_STDERR = 3,
  };

  static std::unique_ptr<Log> Create(Options options = OPTIONS_NONE,
                                     Target target = TARGET_DEFAULT);

  virtual ~Log();

  template<typename ... Args>
  void Write(const std::string& fmt, const Args& ... args) {
    Write(string_format(fmt, args...));
  }

  void Write(const std::string& line) {
    if (options_ & OPTIONS_IMMEDIATE) {
      WriteLine(line);
    } else {
      lines_.push_back(Now() + ": " + line);
    }
  }
  void Flush();
  void SetFlushOnDestroy();

 protected:
  Log(Options options) : options_(options) {}

  virtual void WriteLine(const std::string &line) = 0;

 private:
  Options options_;
  std::string summary_;
  std::vector<std::string> lines_;
};

}  // namespace sasl_xoauth2

#endif  // SASL_XOAUTH2_LOG_H
