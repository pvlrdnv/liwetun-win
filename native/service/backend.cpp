#include "backend.h"
#include "adapter_admission.h"
#include "liwetun_native.h"
#include <cstring>
#include <bcrypt.h>
#include <stdexcept>
#ifdef LIWETUN_TEST_ATTACHED_TUN
#include "../health/attached_tun_validate.h"
#endif

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
#ifdef LIWETUN_TEST_OWNED_PROBE
  owned_report_ = Directory(service.path) + L"\\owned-probe-context.json";
#endif
  ready_ = Load(service);
  worker_ = std::thread([this] { Run(); });
}
Backend::~Backend() {
  Shutdown();
  if (worker_.joinable()) worker_.join();
#ifdef LIWETUN_TEST_OWNED_PROBE
  JoinOwnedProbe();
#endif
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
  traffic_read_ = reinterpret_cast<TrafficRead>(GetProcAddress(module_, "liwetun_traffic_snapshot_v1"));
#ifdef LIWETUN_TEST_ATTACHED_TUN
  attachment_read_ = reinterpret_cast<AttachmentRead>(GetProcAddress(module_, "liwetun_attached_tun_v1"));
  if (!attachment_read_) return false;
#endif
#ifdef LIWETUN_TEST_OWNED_PROBE
  owned_arm_ = reinterpret_cast<OwnedArm>(GetProcAddress(module_, "liwetun_probe_arm_socket_v1"));
  owned_read_ = reinterpret_cast<OwnedRead>(GetProcAddress(module_, "liwetun_probe_snapshot_socket_v1"));
  owned_disarm_ = reinterpret_cast<OwnedDisarm>(GetProcAddress(module_, "liwetun_probe_disarm_v1"));
  if (!owned_arm_ || !owned_read_ || !owned_disarm_) return false;
#endif
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
  if (!ReservedAdapterAliasAbsent()) { Clear(uri); return Code::CoreFailure; }
  pending_ = std::move(uri);
  core_state_ = UINT32_MAX;
  busy_ = true;
  intent_ = true;
  state_ = State::Connecting;
  wake_.notify_one();
  return Code::Ok;
}
void Backend::Stop() {
#ifdef LIWETUN_TEST_OWNED_PROBE
  CancelOwnedProbe();
#endif
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
void Backend::SnapshotTraffic(TrafficReply& reply) const {
  if (!traffic_read_) { Snapshot(reply.status); return; }
  reply.sample.flags = traffic::kSupported;
  std::unique_lock lock(core_mutex_, std::try_to_lock);
  if (!lock.owns_lock()) {
    reply.sample.flags |= traffic::kObservationGap;
  } else if (observed_core_) {
    reply.instance = instance_;
    traffic::Snapshot candidate;
    if (traffic_read_(observed_core_, sizeof(candidate), &candidate) == 1 && traffic::Valid(candidate)) {
#ifdef LIWETUN_TEST_ATTACHED_TUN
      // Read through the same borrowed-core lock, including concurrent Stop.
      // Identifiers stay inside this stack frame and never cross IPC/logging.
      if (candidate.flags & traffic::kValid) {
        health::AttachedTun attachment;
        if (!attachment_read_ || attachment_read_(observed_core_, sizeof(attachment), &attachment) != 1 ||
            !health::MatchesReadyCounter(attachment, candidate)) {
          candidate.flags &= ~traffic::kValid;
          candidate.flags |= traffic::kObservationGap;
        }
      }
#endif
#ifdef LIWETUN_TEST_OWNED_PROBE
      if ((candidate.flags & traffic::kValid) && (!owned_qualified_.load() ||
          owned_epoch_.load() != candidate.epoch || owned_instance_.load() != instance_)) {
        candidate.flags &= ~traffic::kValid;
        candidate.flags |= traffic::kObservationGap;
      }
#endif
      reply.sample = candidate;
    } else {
      reply.sample.flags |= traffic::kObservationGap;
    }
  }
  Snapshot(reply.status);
  if (reply.instance == 0 || reply.status.state != State::TunnelReady ||
      reply.status.core_state != reply.sample.state) reply.sample.flags &= ~traffic::kValid;
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
#ifdef LIWETUN_TEST_OWNED_PROBE
      // Keep the borrowed core available for the cancelled worker's matching
      // disarm. No SDK teardown starts until it has joined, and no core lock
      // spans that join. Cancellation already invalidates CI observations.
      JoinOwnedProbe();
#endif
      {
        // Withdraw the pointer before teardown. Readers only borrow it under
        // this short lock; stop itself never holds the lock while joining SDK threads.
        std::lock_guard lock(core_mutex_);
        observed_core_ = nullptr;
        instance_ = 0;
      }
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
#ifdef LIWETUN_TEST_OWNED_MIGRATION
          // Disposable fixed-port experiment: real fake-upstream -> endpoint
          // migration on first payload; no SDK callbacks/flags are injected.
          config += "\nexclusions_tcp_early_ack_enabled=true\nexclusions_scannable_ports=\"38556\"\n";
#endif
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
      // Recheck after decoding, immediately before the SDK can open/create its
      // adapter. This is a second refusal gate, not an atomic ownership claim.
      if (!config.empty() && ReservedAdapterAliasAbsent())
        core = start_(config.c_str(), false, OnState, this, nullptr, nullptr);
    } catch (...) { core = nullptr; }
    Clear(uri); Clear(config);
    {
      uint64_t token = 0;
      if (core && BCryptGenRandom(nullptr, reinterpret_cast<BYTE*>(&token), sizeof(token), BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0) {
        token &= traffic::kMaximum;
      } else { token = 0; }
      std::lock_guard lock(core_mutex_);
      observed_core_ = core;
      instance_ = token;
    }
#ifdef LIWETUN_TEST_OWNED_PROBE
    if (core) StartOwnedProbe();
#endif
    if (!core) { intent_ = false; busy_ = false; state_ = State::Error; }
  }
  if (done_) SetEvent(done_.get());
}
}
