#include "service_channel.h"
#include <flutter/standard_method_codec.h>

ServiceChannel::Value ServiceChannel::Encode(const liwetun::Reply& reply) {
  constexpr const char* codes[]{"ok", "malformed", "denied", "busy", "runtimeUnavailable", "profileRejected",
      "coreFailure", "serviceUnavailable", "timeout", "untrustedInstallation"};
  constexpr const char* states[]{"disconnected", "connecting", "tunnelReady", "recovering", "error"};
  const auto code = static_cast<uint32_t>(reply.code);
  const auto state = static_cast<uint32_t>(reply.state);
  return Value(flutter::EncodableMap{
      {Value("code"), Value(code < 10 ? codes[code] : "malformed")},
      {Value("state"), Value(state < 5 ? states[state] : "error")},
      {Value("runtimeReady"), Value(reply.runtime_ready == 1)},
      {Value("coreState"), reply.core_state <= 5 ? Value(static_cast<int32_t>(reply.core_state)) : Value()},
  });
}
ServiceChannel::ServiceChannel(flutter::BinaryMessenger* messenger, HWND window) : window_(window) {
  channel_ = std::make_unique<flutter::MethodChannel<Value>>(
      messenger, "top.likeweb.liwetun/service", &flutter::StandardMethodCodec::GetInstance());
  channel_->SetMethodCallHandler([this](const auto& call, auto result) {
    if (call.method_name() == "environment") {
      if (call.arguments() && !std::holds_alternative<std::monostate>(*call.arguments())) {
        result->Error("invalid_arguments", "Invalid environment request"); return;
      }
      // Diagnostic observation only. The manifest declares Windows 10/11;
      // compatibility modes can affect this API. Never use it as a feature gate.
      OSVERSIONINFOW version{};
      version.dwOSVersionInfoSize = sizeof(version);
#pragma warning(push)
#pragma warning(disable: 4996)
      const bool known = GetVersionExW(&version) != FALSE;
#pragma warning(pop)
      result->Success(Value(flutter::EncodableMap{
          {Value("major"), known ? Value(static_cast<int32_t>(version.dwMajorVersion)) : Value()},
          {Value("minor"), known ? Value(static_cast<int32_t>(version.dwMinorVersion)) : Value()},
          {Value("build"), known ? Value(static_cast<int32_t>(version.dwBuildNumber)) : Value()},
          {Value("architecture"), Value("x64")},
      }));
      return;
    }
    liwetun::Command command;
    std::string profile;
    if (call.method_name() == "query") command = liwetun::Command::Query;
    else if (call.method_name() == "stop") command = liwetun::Command::Stop;
    else if (call.method_name() == "start") {
      command = liwetun::Command::Start;
      const auto* args = call.arguments();
      const auto* map = args ? std::get_if<flutter::EncodableMap>(args) : nullptr;
      if (!map || map->size() != 1) { result->Error("invalid_arguments", "Invalid service request"); return; }
      const auto found = map->find(Value("uri"));
      const auto* uri = found == map->end() ? nullptr : std::get_if<std::string>(&found->second);
      if (!uri || uri->size() < 20 || uri->size() > liwetun::kMaxPayload) {
        result->Error("invalid_arguments", "Invalid service request"); return;
      }
      profile = *uri;
    } else { result->NotImplemented(); return; }
    if (command != liwetun::Command::Start && call.arguments() && !std::holds_alternative<std::monostate>(*call.arguments())) {
      result->Error("invalid_arguments", "Invalid service request"); return;
    }
    std::lock_guard lock(mutex_);
    if (stopping_ || jobs_.size() >= 4) {
      if (!profile.empty()) SecureZeroMemory(profile.data(), profile.size());
      liwetun::Reply reply{}; reply.code = liwetun::Code::Busy; reply.core_state = UINT32_MAX;
      result->Success(Encode(reply)); return;
    }
    jobs_.emplace_back(command, std::move(profile), std::move(result));
    wake_.notify_one();
  });
  worker_ = std::thread([this] { Run(); });
}
ServiceChannel::~ServiceChannel() {
  channel_->SetMethodCallHandler(nullptr);
  { std::lock_guard lock(mutex_); stopping_ = true; jobs_.clear(); }
  wake_.notify_one();
  if (worker_.joinable()) worker_.join();
}
void ServiceChannel::Run() {
  for (;;) {
    std::unique_lock lock(mutex_);
    wake_.wait(lock, [this] { return stopping_ || !jobs_.empty(); });
    if (stopping_) return;
    Job job = std::move(jobs_.front()); jobs_.pop_front();
    lock.unlock();
    auto reply = liwetun::ServiceRequest(job.command, job.profile, job.command == liwetun::Command::Start);
    lock.lock();
    if (stopping_) return;
    completions_.push_back({std::move(job.result), reply});
    PostMessageW(window_, kCompletion, 0, 0);
  }
}
void ServiceChannel::Complete() {
  std::deque<Completion> values;
  { std::lock_guard lock(mutex_); values.swap(completions_); }
  for (auto& value : values) value.result->Success(Encode(value.reply));
}
