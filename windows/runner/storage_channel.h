#pragma once
#include <flutter/binary_messenger.h>
#include <flutter/encodable_value.h>
#include <flutter/method_channel.h>
#include <windows.h>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>
#include "store.h"

class StorageChannel {
 public:
  static constexpr UINT kCompletion = WM_APP + 0x542;
  StorageChannel(flutter::BinaryMessenger* messenger, HWND window);
  ~StorageChannel();
  void Complete();
 private:
  using Value = flutter::EncodableValue;
  using Result = std::unique_ptr<flutter::MethodResult<Value>>;
  enum class Command { Load, Save, Clear };
  struct Job {
    Command command;
    std::string payload, revision;
    Result result;
    Job(Command c, std::string p, std::string v, Result r)
        : command(c), payload(std::move(p)), revision(std::move(v)), result(std::move(r)) {}
    Job(Job&&) = default;
    ~Job() { if (!payload.empty()) SecureZeroMemory(payload.data(), payload.size()); }
  };
  struct Completion { Result result; liwetun::storage::Snapshot snapshot; };
  static Value Encode(const liwetun::storage::Snapshot& snapshot, bool load);
  void Run();
  HWND window_;
  std::unique_ptr<flutter::MethodChannel<Value>> channel_;
  std::mutex mutex_;
  std::condition_variable wake_;
  std::deque<Job> jobs_;
  std::deque<std::pair<Completion, bool>> completions_;
  bool stopping_ = false;
  std::thread worker_;
};
