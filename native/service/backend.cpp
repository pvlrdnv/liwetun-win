#include "backend.h"
#include "liwetun_native.h"
#include <cstring>
#include <stdexcept>

namespace liwetun {
namespace {
void Clear(std::string& value) {
  if (!value.empty()) SecureZeroMemory(value.data(), value.size());
  value.clear();
}
std::string Hex(const Digest& digest) {
  constexpr char alphabet[] = "0123456789abcdef";
  std::string result;
  for (unsigned char b : digest) { result += alphabet[b >> 4]; result += alphabet[b & 15]; }
  return result;
}
}
Backend::Backend(const Image& service) : done_(CreateEventW(nullptr, TRUE, FALSE, nullptr)) {
  if (!done_) throw std::runtime_error("service_initialization_failed");
  ready_ = Load(service);
  worker_ = std::thread([this] { Run(); });
}
Backend::~Backend() {
  Shutdown();
  if (worker_.joinable()) worker_.join();
  if (module_) FreeLibrary(module_);
}
bool Backend::Load(const Image& service) {
  const std::wstring root = Directory(service.path);
  if (!OpenTrustedImage(root + L"\\trusttunnel.dll", sdk_) || !SameSigner(service, sdk_) ||
      !OpenTrustedImage(root + L"\\wintun.dll", wintun_)) return false;
  Digest hash{};
  if (!HashFile(wintun_.handle.get(), hash) || Hex(hash) !=
      "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce") return false;
  module_ = LoadLibraryExW(sdk_.path.c_str(), nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
  if (!module_) return false;
  auto policy = reinterpret_cast<int (*)()>(GetProcAddress(module_, "liwetun_core_policy_version"));
  if (!policy || policy() != 1) return false;
  start_ = reinterpret_cast<CoreStart>(GetProcAddress(module_, "trusttunnel_start_ex"));
  stop_fn_ = reinterpret_cast<CoreStop>(GetProcAddress(module_, "trusttunnel_stop_ex"));
  decode_ = reinterpret_cast<Decode>(GetProcAddress(module_, "trusttunnel_decode_deeplink"));
  free_ = reinterpret_cast<Free>(GetProcAddress(module_, "trusttunnel_free_deeplink_string"));
  return start_ && stop_fn_ && decode_ && free_;
}
Code Backend::Start(std::string uri) {
  LiwetunTtInfo info{};
  if (liwetun_tt_inspect(reinterpret_cast<const uint8_t*>(uri.data()), uri.size(), &info) != 0) {
    Clear(uri); return Code::ProfileRejected;
  }
  if (!ready_) { Clear(uri); return Code::RuntimeUnavailable; }
  std::lock_guard lock(mutex_);
  if (busy_ || stop_ || shutdown_) { Clear(uri); return Code::Busy; }
  pending_ = std::move(uri);
  core_state_ = UINT32_MAX;
  busy_ = true;
  intent_ = true;
  state_ = State::Connecting;
  wake_.notify_one();
  return Code::Ok;
}
void Backend::Stop() {
  std::lock_guard lock(mutex_);
  intent_ = false;
  stop_ = true;
  busy_ = true;
  failed_stop_ = false;
  Clear(pending_);
  wake_.notify_one();
}
void Backend::Shutdown() {
  { std::lock_guard lock(mutex_); shutdown_ = true; }
  Stop();
}
void Backend::Snapshot(Reply& reply) const {
  reply.state = state_;
  reply.core_state = core_state_;
  reply.runtime_ready = ready_ ? 1u : 0u;
  if (reply.state == State::Error) reply.code = Code::CoreFailure;
}
void Backend::OnState(void* context, int state) {
  auto* self = static_cast<Backend*>(context);
  if (state < 0 || state > 5) { self->state_ = State::Error; return; }
  self->core_state_ = static_cast<uint32_t>(state);
  if (!self->intent_ && state != 0) return;
  switch (state) {
    case 0:
      if (self->intent_) {
        std::lock_guard lock(self->mutex_);
        self->failed_stop_ = true;
        self->stop_ = true;
        self->state_ = State::Error;
        self->wake_.notify_one();
      } else { self->state_ = State::Disconnected; }
      break;
    case 1: self->state_ = State::Connecting; break;
    case 2: self->state_ = State::TunnelReady; break;
    default: self->state_ = State::Recovering; break;
  }
}
void Backend::Run() {
  trusttunnel_s* core = nullptr;
  for (;;) {
    std::string uri;
    bool stopping = false, failed = false, exiting = false;
    {
      std::unique_lock lock(mutex_);
      wake_.wait(lock, [this] { return stop_ || shutdown_ || !pending_.empty(); });
      stopping = stop_; failed = failed_stop_; exiting = shutdown_;
      stop_ = false; failed_stop_ = false;
      if (!stopping && !exiting) uri.swap(pending_);
      else Clear(pending_);
    }
    if (stopping || exiting) {
      intent_ = false;
      if (core) { stop_fn_(core); core = nullptr; }
      busy_ = false;
      state_ = failed ? State::Error : State::Disconnected;
      if (exiting) break;
      continue;
    }
    std::string config;
    try {
      char* endpoint = decode_(uri.c_str());
      Clear(uri);
      if (endpoint) {
        const size_t size = strnlen(endpoint, 131072);
        if (size < 131072) {
          // Windows adds multicast routes to virtual adapters independently of
          // included_routes. Keep local discovery/broadcast out of the exit.
          config = "loglevel=\"error\"\nvpn_mode=\"general\"\nkillswitch_enabled=false\n"
              "exclusions=[\"224.0.0.0/4\",\"ff00::/8\",\"255.255.255.255\"]\n";
          config.append(endpoint, size);
          config += "\n[listener.tun]\ndevice_name=\"LiWeTun\"\n";
#ifdef LIWETUN_TEST_NO_GLOBAL_ROUTES
          config += "included_routes=[]\nexcluded_routes=[]\nchange_system_dns=false\n";
#elif defined(LIWETUN_TEST_TUN_NETWORK)
          // Same-host CI only: never capture ambient runner/endpoint egress.
          // The harness adds one high-metric origin host route to this adapter;
          // probe sockets explicitly bind IP_UNICAST_IF to it.
          config += "included_routes=[\"198.18.0.0/15\"]\nexcluded_routes=[]\nchange_system_dns=true\n";
#else
          // The pinned TOML parser leaves omitted route arrays empty. Its
          // documented defaults are not copied into TunListener automatically.
          config += "included_routes=[\"0.0.0.0/0\",\"2000::/3\"]\n"
              "excluded_routes=[\"10.0.0.0/8\",\"169.254.0.0/16\",\"172.16.0.0/12\","
              "\"192.168.0.0/16\",\"224.0.0.0/3\"]\nchange_system_dns=true\n";
#endif
        }
        SecureZeroMemory(endpoint, size);
        free_(endpoint);
      }
      if (!config.empty()) core = start_(config.c_str(), false, OnState, this, nullptr, nullptr);
    } catch (...) { core = nullptr; }
    Clear(uri); Clear(config);
    if (!core) { intent_ = false; busy_ = false; state_ = State::Error; }
  }
  if (done_) SetEvent(done_.get());
}
}
