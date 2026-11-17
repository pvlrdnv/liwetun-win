#pragma once
#include <flutter/binary_messenger.h>
#include <flutter/encodable_value.h>
#include <flutter/method_channel.h>
#include <windows.h>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>
#include "client.h"

class ServiceChannel {
 public:
  static constexpr UINT kCompletion = WM_APP + 0x541;
  ServiceChannel(flutter::BinaryMessenger* messenger, HWND window);
  ~ServiceChannel();
  void Complete();
 private:
  using Value = flutter::EncodableValue;
  using Result = std::unique_ptr<flutter::MethodResult<Value>>;
  struct Job {
    liwetun::Command command;
    std::string profile;
    Result result;
    ~Job() { if (!profile.empty()) SecureZeroMemory(profile.data(), profile.size()); }
    Job(liwetun::Command c, std::string p, Result r) : command(c), profile(std::move(p)), result(std::move(r)) {}
    Job(Job&&) = default;
    Job& operator=(Job&&) = default;
  };
  struct Completion { Result result; liwetun::Reply reply; liwetun::TrafficReply traffic; bool is_traffic; };
  static Value Encode(const liwetun::Reply& reply);
  static Value EncodeTraffic(const liwetun::TrafficReply& reply);
  void Run();
  HWND window_;
  std::unique_ptr<flutter::MethodChannel<Value>> channel_;
  std::mutex mutex_;
  std::condition_variable wake_;
  std::deque<Job> jobs_;
  std::deque<Completion> completions_;
  bool stopping_ = false;
  std::thread worker_;
};
