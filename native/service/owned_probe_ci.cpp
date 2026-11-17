// Compiled only in disposable CI. Fixed synthetic receiver, no public probe API.
#include <winsock2.h>
#include <ws2tcpip.h>
#include "backend.h"
#include <algorithm>
#include <array>
#include <bcrypt.h>
#include <cstdio>
#include <string>
#include <utility>

namespace liwetun {
namespace {
struct Socket {
  SOCKET value = INVALID_SOCKET;
  Socket() = default;
  explicit Socket(SOCKET fd) : value(fd) {}
  Socket(const Socket&) = delete;
  Socket& operator=(const Socket&) = delete;
  Socket(Socket&& other) noexcept : value(std::exchange(other.value, INVALID_SOCKET)) {}
  ~Socket() { if (value != INVALID_SOCKET) closesocket(value); }
};
struct Winsock {
  bool ready = false;
  Winsock() { WSADATA data{}; ready = WSAStartup(MAKEWORD(2, 2), &data) == 0; }
  ~Winsock() { if (ready) WSACleanup(); }
};
template <typename F> struct Cleanup {
  F action;
  ~Cleanup() { try { action(); } catch (...) {} }
};
struct Result {
  uint32_t stage = 1;
  bool connected = false, nonexclusive_rejected = false, armed = false;
  bool echoed = false, same_epoch = false, disarmed = false, cancelled = false, qualified = false;
  bool receive_cancelled = false;
  probe::Snapshot sample;
};
enum class IoResult { Complete, Cancelled, Deadline, Failed };
IoResult Wait(SOCKET socket, bool writing, ULONGLONG deadline, const std::atomic<bool>& cancel) {
  for (;;) {
    if (GetTickCount64() >= deadline) return IoResult::Deadline;
    if (cancel.load()) return IoResult::Cancelled;
    fd_set ready, errors;
    FD_ZERO(&ready); FD_ZERO(&errors);
    FD_SET(socket, &ready); FD_SET(socket, &errors);
    timeval timeout{0, 50000};
    const int status = select(0, writing ? nullptr : &ready, writing ? &ready : nullptr, &errors, &timeout);
    if (status == SOCKET_ERROR || FD_ISSET(socket, &errors)) return IoResult::Failed;
    if (status > 0 && FD_ISSET(socket, &ready)) return IoResult::Complete;
  }
}
Socket Connect(uint32_t index, bool exclusive, ULONGLONG deadline, const std::atomic<bool>& cancel) {
  Socket socket(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
  if (socket.value == INVALID_SOCKET) return Socket{};
  const int enabled = exclusive ? 1 : 0;
  const DWORD interface_index = htonl(index);
  u_long nonblocking = 1;
  if (setsockopt(socket.value, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
          reinterpret_cast<const char*>(&enabled), sizeof(enabled)) != 0 ||
      setsockopt(socket.value, IPPROTO_IP, IP_UNICAST_IF,
          reinterpret_cast<const char*>(&interface_index), sizeof(interface_index)) != 0 ||
      ioctlsocket(socket.value, FIONBIO, &nonblocking) != 0) return Socket{};
  sockaddr_in target{};
  target.sin_family = AF_INET;
  target.sin_addr.s_addr = htonl(0xc612000a); // Fixed CI receiver: 198.18.0.10:38556.
  target.sin_port = htons(38556);
  if (connect(socket.value, reinterpret_cast<sockaddr*>(&target), sizeof(target)) != 0) {
    if (WSAGetLastError() != WSAEWOULDBLOCK || Wait(socket.value, true, deadline, cancel) != IoResult::Complete) return Socket{};
    int error = 0, size = sizeof(error);
    if (getsockopt(socket.value, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &size) != 0 || error) return Socket{};
  }
  return socket;
}
IoResult Transfer(SOCKET socket, std::array<char, 24>& bytes, bool writing, ULONGLONG deadline,
              const std::atomic<bool>& cancel) {
  size_t offset = 0;
  while (offset < bytes.size()) {
    if (GetTickCount64() >= deadline) return IoResult::Deadline;
    if (cancel.load()) return IoResult::Cancelled;
    const int left = static_cast<int>(bytes.size() - offset);
    const int count = writing ? send(socket, bytes.data() + offset, left, 0)
                              : recv(socket, bytes.data() + offset, left, 0);
    if (count > 0) offset += static_cast<size_t>(count);
    else {
      if (!count || WSAGetLastError() != WSAEWOULDBLOCK) return IoResult::Failed;
      const auto waited = Wait(socket, writing, deadline, cancel);
      if (waited != IoResult::Complete) return waited;
    }
  }
  return IoResult::Complete;
}
bool ValidSample(const probe::Snapshot& s) {
  if (s.abi != 1 || s.size != sizeof(s) || s.reserved || !(s.flags & probe::kSupported) ||
      (s.flags & ~uint32_t{1023}) || s.token > probe::kMaximum || s.epoch > probe::kMaximum ||
      (s.at_ms != UINT64_MAX && s.at_ms > probe::kMaximum) || s.tx > probe::kMaximum || s.rx > probe::kMaximum) return false;
  if (!(s.flags & probe::kArmed)) return !s.tx && !s.rx && !(s.flags & (probe::kEndpointTx | probe::kEndpointRx));
  return !(s.flags & ~uint32_t{15}) && s.token && s.epoch && s.at_ms <= probe::kMaximum &&
      ((s.tx != 0) == ((s.flags & probe::kEndpointTx) != 0)) && ((s.rx != 0) == ((s.flags & probe::kEndpointRx) != 0));
}
bool WriteResult(const std::wstring& path, const Result& result) {
  const auto boolean = [](bool value) { return value ? "true" : "false"; };
  const bool observed = (result.sample.flags & probe::kArmed) != 0;
  const std::string tx = observed ? std::to_string(result.sample.tx) : "null";
  const std::string rx = observed ? std::to_string(result.sample.rx) : "null";
  char output[1536]{};
  const int length = std::snprintf(output, sizeof(output),
      "{\"schema_version\":1,\"stage\":%u,\"connected\":%s,\"nonexclusive_rejected\":%s,"
      "\"arm_accepted\":%s,\"echo_verified\":%s,\"same_instance_epoch\":%s,\"disarmed\":%s,\"cancelled\":%s,"
      "\"receive_cancelled\":%s,"
      "\"snapshot_flags\":%u,\"tx_bytes\":%s,\"rx_bytes\":%s,\"qualified\":%s,"
      "\"proves_dns\":false,\"proves_https\":false,\"proves_internet\":false,"
      "\"identifiers_exported\":false,\"release_ready\":false}\n",
      result.stage, boolean(result.connected), boolean(result.nonexclusive_rejected), boolean(result.armed),
      boolean(result.echoed), boolean(result.same_epoch), boolean(result.disarmed), boolean(result.cancelled),
      boolean(result.receive_cancelled), result.sample.flags,
      tx.c_str(), rx.c_str(), boolean(result.qualified));
  if (length <= 0 || static_cast<size_t>(length) >= sizeof(output)) return false;
  Handle file(CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_NEW,
      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
  if (!file || file.get() == INVALID_HANDLE_VALUE) return false;
  DWORD written = 0;
  return WriteFile(file.get(), output, static_cast<DWORD>(length), &written, nullptr) && written == static_cast<DWORD>(length);
}
} // namespace

void Backend::CancelOwnedProbe() noexcept {
  try { std::lock_guard lock(owned_publish_mutex_); owned_cancel_ = true; owned_qualified_ = false; }
  catch (...) { owned_cancel_ = true; owned_qualified_ = false; }
}
void Backend::JoinOwnedProbe() noexcept {
  CancelOwnedProbe();
  try { if (owned_worker_.joinable()) owned_worker_.join(); } catch (...) {}
}
void Backend::StartOwnedProbe() noexcept {
  JoinOwnedProbe();
  try {
    { std::lock_guard lock(owned_publish_mutex_); owned_cancel_ = false; owned_qualified_ = false; }
    owned_worker_ = std::thread([this] { RunOwnedProbe(); });
  } catch (...) { owned_cancel_ = true; owned_qualified_ = false; }
}
void Backend::RunOwnedProbe() noexcept {
  Result result;
  uint64_t instance = 0, epoch = 0;
  try {
    Winsock winsock;
    if (!winsock.ready) throw 1;
    health::AttachedTun attachment;
    {
      std::lock_guard lock(core_mutex_);
      if (owned_cancel_ || !observed_core_ || !instance_ || state_ != State::TunnelReady) throw 1;
      traffic::Snapshot counter;
      if (traffic_read_(observed_core_, sizeof(counter), &counter) != 1 || !traffic::Valid(counter) || counter.flags != 3 ||
          attachment_read_(observed_core_, sizeof(attachment), &attachment) != 1 || attachment.flags != 3 ||
          attachment.epoch != counter.epoch) throw 1;
      instance = instance_; epoch = counter.epoch;
    }
    probe::Request request;
    request.epoch = epoch;
    if (BCryptGenRandom(nullptr, reinterpret_cast<BYTE*>(&request.token), sizeof(request.token), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) throw 1;
    request.token &= probe::kMaximum;
    if (!request.token) throw 1;
    const auto deadline = GetTickCount64() + 4000;
    result.stage = 2;
    {
      auto ordinary = Connect(attachment.index, false, deadline, owned_cancel_);
      if (ordinary.value == INVALID_SOCKET) throw 1;
      result.stage = 3;
      std::lock_guard lock(core_mutex_);
      if (owned_cancel_ || !observed_core_ || instance_ != instance) throw 1;
      const auto refusal = owned_arm_(observed_core_, ordinary.value, sizeof(request), &request);
      result.nonexclusive_rejected = refusal == static_cast<uint32_t>(probe::ArmResult::SocketRejected);
      if (!result.nonexclusive_rejected) { owned_disarm_(observed_core_, request.token); throw 1; }
    }
    result.stage = 4;
    auto socket = Connect(attachment.index, true, deadline, owned_cancel_);
    result.connected = socket.value != INVALID_SOCKET;
    if (!result.connected) throw 1;
    Cleanup cleanup{[this, instance, token = request.token, &result] {
      std::lock_guard lock(core_mutex_);
      if (observed_core_ && instance_ == instance) result.disarmed = owned_disarm_(observed_core_, token) == 1;
    }};
    result.stage = 5;
    {
      std::lock_guard lock(core_mutex_);
      if (owned_cancel_ || !observed_core_ || instance_ != instance) throw 1;
      result.armed = owned_arm_(observed_core_, socket.value, sizeof(request), &request) ==
          static_cast<uint32_t>(probe::ArmResult::Armed);
      if (!result.armed) throw 1;
    }
    std::array<char, 24> payload{}, response{}, expected{};
    constexpr char request_prefix[] = "liwetun-path-v1:";
    constexpr char reply_prefix[] = "liwetun-path-ok:";
    std::copy_n(request_prefix, 16, payload.begin());
    std::copy_n(reply_prefix, 16, expected.begin());
    for (unsigned i = 0; i < 8; ++i) payload[16 + i] = expected[16 + i] = static_cast<char>((request.token >> (56 - 8 * i)) & 255);
    result.stage = 6;
    const bool sent = Transfer(socket.value, payload, true, deadline, owned_cancel_) == IoResult::Complete;
    result.stage = 7;
    const auto received = sent ? Transfer(socket.value, response, false, deadline, owned_cancel_) : IoResult::Failed;
    result.receive_cancelled = received == IoResult::Cancelled;
    result.echoed = received == IoResult::Complete && response == expected;
    result.stage = 8;
    {
      std::lock_guard lock(core_mutex_);
      if (observed_core_ && instance_ == instance) {
        probe::Snapshot candidate;
        if (!owned_cancel_ && owned_read_(observed_core_, socket.value, request.token, sizeof(candidate), &candidate) == 1 && ValidSample(candidate)) {
          result.sample = candidate;
          traffic::Snapshot after;
          result.same_epoch = state_ == State::TunnelReady && traffic_read_(observed_core_, sizeof(after), &after) == 1 &&
              traffic::Valid(after) && after.flags == 3 && after.epoch == epoch && result.sample.epoch == epoch &&
              result.sample.token == request.token && result.sample.at_ms <= after.at_ms && after.at_ms - result.sample.at_ms <= 5000;
        } else {
          result.sample = probe::Snapshot{}; result.sample.flags |= probe::kFault;
        }
      }
    }
    result.qualified = result.connected && result.nonexclusive_rejected && result.armed && result.echoed &&
        result.same_epoch && result.sample.flags == 15 && result.sample.tx >= 24 && result.sample.rx >= 24;
    result.stage = 9;
  } catch (...) { result.qualified = false; }
  try {
    result.qualified = result.qualified && result.disarmed;
    result.cancelled = owned_cancel_.load();
    if (result.cancelled) { result.qualified = false; result.sample = probe::Snapshot{}; }
    const bool written = WriteResult(owned_report_, result);
    std::lock_guard lock(owned_publish_mutex_);
    owned_instance_ = instance; owned_epoch_ = epoch;
    owned_qualified_ = written && result.qualified && !owned_cancel_.load();
  } catch (...) { owned_qualified_ = false; }
}
} // namespace liwetun
