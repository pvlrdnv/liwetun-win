#pragma once
#include "protocol.h"
#include "security.h"
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>

struct trusttunnel_s;
namespace liwetun {
class Backend {
 public:
  explicit Backend(const Image& service);
  ~Backend();
  Code Start(std::string uri);
  void Stop();
  void Shutdown();
  bool Busy() const { return busy_.load(); }
  void Snapshot(Reply& reply) const;
  HANDLE Done() const { return done_.get(); }
 private:
  using StateCallback = void (*)(void*, int);
  using InfoCallback = void (*)(void*, void*);
  using CoreStart = trusttunnel_s* (*)(const char*, bool, StateCallback, void*, InfoCallback, void*);
  using CoreStop = void (*)(trusttunnel_s*);
  using Decode = char* (*)(const char*);
  using Free = void (*)(char*);
  bool Load(const Image& service);
  void Run();
  static void OnState(void* context, int state);
  std::atomic<State> state_{State::Disconnected};
  std::atomic<uint32_t> core_state_{UINT32_MAX};
  std::atomic<bool> ready_{false}, busy_{false}, intent_{false};
  std::mutex mutex_;
  std::condition_variable wake_;
  std::string pending_;
  bool stop_ = false, shutdown_ = false, failed_stop_ = false;
  HMODULE module_ = nullptr;
  Image sdk_, wintun_;
  CoreStart start_ = nullptr;
  CoreStop stop_fn_ = nullptr;
  Decode decode_ = nullptr;
  Free free_ = nullptr;
  Handle done_;
  std::thread worker_;
};
}
