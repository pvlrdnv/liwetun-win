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
#ifdef LIWETUN_TEST_OWNED_HTTPS
#include "../health/http_probe.h"
#include "../health/schannel_probe.h"
#endif
#ifdef LIWETUN_TEST_OWNED_BYPASS
#include <iphlpapi.h>
#include <netioapi.h>
#include <vector>
#endif

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
enum class InitializationResult : uint32_t {
  Unknown, WinsockUnavailable, Cancelled, CoreUnavailable, InstanceUnavailable,
  StateNotReady, TrafficUnavailable, TrafficNotReady, AttachmentUnavailable,
  AttachmentNotReady, EpochMismatch, EntropyUnavailable, EmptyToken, Passed
};
struct Result {
  uint32_t stage = 1;
  InitializationResult initialization_result = InitializationResult::Unknown;
  uint32_t socket_failure = 0; // Closed CI stages only; never OS text/address/identifier.
  bool connected = false, nonexclusive_rejected = false, armed = false;
  bool echoed = false, same_epoch = false, disarmed = false, cancelled = false, qualified = false;
  bool receive_cancelled = false;
  bool receive_timed_out = false;
  bool state_epoch_changed = false;
  probe::Snapshot sample;
#ifdef LIWETUN_TEST_OWNED_HTTPS
  std::optional<health::TlsResult> tls; // No invented TLS failure before an attempt.
  std::optional<health::HttpResult> http;
  bool handshake_verified = false, request_sent = false;
  uint64_t wire_tx = 0, wire_rx = 0;
#endif
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
#ifdef LIWETUN_TEST_OWNED_BYPASS
DWORD OwnedIpv4(const health::AttachedTun& attachment, uint32_t& issue) {
  DWORD size = 0;
  issue = 9; // Address table size query.
  if (GetIpAddrTable(nullptr, &size, FALSE) != ERROR_INSUFFICIENT_BUFFER) return 0;
  issue = 10; // Bounded table layout.
  if (size < sizeof(MIB_IPADDRTABLE) || size > 65536) return 0;
  std::vector<unsigned char> buffer(size);
  auto* table = reinterpret_cast<MIB_IPADDRTABLE*>(buffer.data());
  if (GetIpAddrTable(table, &size, FALSE) != NO_ERROR || size > buffer.size() ||
      size < offsetof(MIB_IPADDRTABLE, table) ||
      table->dwNumEntries > (size - offsetof(MIB_IPADDRTABLE, table)) / sizeof(MIB_IPADDRROW)) return 0;
  issue = 11; // No unambiguous preferred address on the held SDK attachment.
  DWORD selected = 0;
  for (DWORD i = 0; i < table->dwNumEntries; ++i) {
    const auto& entry = table->table[i];
    if (entry.dwIndex != attachment.index || !entry.dwAddr || (ntohl(entry.dwAddr) >> 24) >= 224) continue;
    MIB_UNICASTIPADDRESS_ROW row;
    InitializeUnicastIpAddressEntry(&row);
    row.InterfaceIndex = attachment.index; row.InterfaceLuid.Value = attachment.luid;
    row.Address.Ipv4.sin_family = AF_INET; row.Address.Ipv4.sin_addr.s_addr = entry.dwAddr;
    if (GetUnicastIpAddressEntry(&row) != NO_ERROR || row.DadState != IpDadStatePreferred ||
        row.InterfaceIndex != attachment.index || row.InterfaceLuid.Value != attachment.luid) continue;
    if (selected && selected != entry.dwAddr) { issue = 12; return 0; }
    selected = entry.dwAddr;
  }
  return selected;
}
#endif
Socket ConnectOnce(const health::AttachedTun& attachment, bool exclusive, ULONGLONG deadline,
               const std::atomic<bool>& cancel, uint32_t& issue) {
  issue = 1;
  Socket socket(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
  if (socket.value == INVALID_SOCKET) return Socket{};
  const int enabled = exclusive ? 1 : 0;
  issue = 2;
  u_long nonblocking = 1;
  if (setsockopt(socket.value, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
          reinterpret_cast<const char*>(&enabled), sizeof(enabled)) != 0 ||
      ioctlsocket(socket.value, FIONBIO, &nonblocking) != 0) return Socket{};
  sockaddr_in target{};
  target.sin_family = AF_INET;
#ifdef LIWETUN_TEST_OWNED_BYPASS
  sockaddr_in source{};
  source.sin_family = AF_INET; source.sin_addr.s_addr = OwnedIpv4(attachment, issue);
  if (!source.sin_addr.s_addr) return Socket{};
  issue = 4;
  if (bind(socket.value, reinterpret_cast<sockaddr*>(&source), sizeof(source)) != 0) return Socket{};
  // Same-address local delivery: bind and peer both use the verified TUN IP,
  // with no forced outgoing IF and no alias/address supplied by the caller.
  target.sin_addr = source.sin_addr; target.sin_port = htons(38557);
#else
  const DWORD interface_index = htonl(attachment.index);
  issue = 5;
  if (setsockopt(socket.value, IPPROTO_IP, IP_UNICAST_IF,
          reinterpret_cast<const char*>(&interface_index), sizeof(interface_index)) != 0) return Socket{};
  target.sin_addr.s_addr = htonl(0xc612000a); // Fixed CI receiver: 198.18.0.10:38556.
  target.sin_port = htons(38556);
#endif
  issue = 6;
  if (connect(socket.value, reinterpret_cast<sockaddr*>(&target), sizeof(target)) != 0) {
    if (WSAGetLastError() != WSAEWOULDBLOCK) return Socket{};
    issue = 7;
    if (Wait(socket.value, true, deadline, cancel) != IoResult::Complete) return Socket{};
    issue = 8;
    int error = 0, size = sizeof(error);
    if (getsockopt(socket.value, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &size) != 0 || error) return Socket{};
  }
  issue = 0;
  return socket;
}
Socket Connect(const health::AttachedTun& attachment, bool exclusive, ULONGLONG deadline,
               const std::atomic<bool>& cancel, uint32_t& issue) {
#ifdef LIWETUN_TEST_OWNED_BYPASS
  // The fixture can bind its receiver only after this owned address exists.
  // Retry with fresh descriptors before arm; no old tuple/token is registered.
  while (!cancel.load() && GetTickCount64() < deadline) {
    auto socket = ConnectOnce(attachment, exclusive, deadline, cancel, issue);
    if (socket.value != INVALID_SOCKET) return socket;
    Sleep(25);
  }
  return Socket{};
#else
  return ConnectOnce(attachment, exclusive, deadline, cancel, issue);
#endif
}
[[maybe_unused]] IoResult Transfer(SOCKET socket, std::array<char, 24>& bytes, bool writing, ULONGLONG deadline,
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
      "{\"schema_version\":4,\"stage\":%u,\"socket_failure\":%u,\"connected\":%s,\"nonexclusive_rejected\":%s,"
      "\"arm_accepted\":%s,\"echo_verified\":%s,\"same_instance_epoch\":%s,\"disarmed\":%s,\"cancelled\":%s,"
      "\"receive_cancelled\":%s,\"receive_timed_out\":%s,"
      "\"state_epoch_changed\":%s,"
      "\"snapshot_flags\":%u,\"tx_bytes\":%s,\"rx_bytes\":%s,\"qualified\":%s,"
      "\"proves_dns\":false,\"proves_https\":false,\"proves_internet\":false,"
      "\"identifiers_exported\":false,\"release_ready\":false}\n",
      result.stage, result.socket_failure, boolean(result.connected), boolean(result.nonexclusive_rejected), boolean(result.armed),
      boolean(result.echoed), boolean(result.same_epoch), boolean(result.disarmed), boolean(result.cancelled),
      boolean(result.receive_cancelled), boolean(result.receive_timed_out), boolean(result.state_epoch_changed), result.sample.flags,
      tx.c_str(), rx.c_str(), boolean(result.qualified));
  if (length <= 0 || static_cast<size_t>(length) >= sizeof(output)) return false;
  Handle file(CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_NEW,
      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
  if (!file || file.get() == INVALID_HANDLE_VALUE) return false;
  DWORD written = 0;
  return WriteFile(file.get(), output, static_cast<DWORD>(length), &written, nullptr) && written == static_cast<DWORD>(length);
}
#ifdef LIWETUN_TEST_OWNED_HTTPS
IoResult ExchangeHttps(SOCKET socket, uint64_t token, ULONGLONG deadline,
                      const std::atomic<bool>& cancel, Result& result) {
  health::SocketIo io(socket, deadline, cancel);
  Cleanup wire_counts{[&] { result.wire_tx = io.SentBytes(); result.wire_rx = io.ReceivedBytes(); }};
  health::SchannelProbe tls(io);
  result.tls = tls.Handshake(L"health.liwetun.invalid");
  result.handshake_verified = result.tls == health::TlsResult::Ok;
  if (result.handshake_verified) {
    health::Nonce nonce{};
    for (unsigned i = 0; i < nonce.size(); ++i) nonce[i] = static_cast<char>((token >> (56 - 8 * i)) & 255);
    const auto request = health::FixtureHealthRequest(nonce);
    if (!request) return IoResult::Failed;
    result.tls = tls.Send(*request);
    result.request_sent = result.tls == health::TlsResult::Ok;
    if (result.request_sent) {
      health::HttpProbeParser parser(nonce);
      std::vector<char> plain;
      for (unsigned record = 0; record < 256; ++record) {
        result.tls = tls.Receive(plain);
        if (result.tls != health::TlsResult::Ok || parser.Feed(plain) != health::HttpResult::NeedMore) break;
      }
      parser.Finish(); result.http = parser.Result();
      result.echoed = result.tls == health::TlsResult::Ok && result.http == health::HttpResult::Verified;
    }
  }
  if (io.Control() == health::IoState::Cancelled) result.tls = health::TlsResult::Cancelled;
  else if (io.Control() == health::IoState::Deadline) result.tls = health::TlsResult::Deadline;
  if (result.tls != health::TlsResult::Ok) result.echoed = false;
  if (result.tls == health::TlsResult::Cancelled) return IoResult::Cancelled;
  if (result.tls == health::TlsResult::Deadline) return IoResult::Deadline;
  return result.tls == health::TlsResult::Ok ? IoResult::Complete : IoResult::Failed;
}
bool WriteHttpsResult(const std::wstring& base, const Result& result) {
  const auto boolean = [](bool value) { return value ? "true" : "false"; };
  const std::string http = result.http ? std::to_string(static_cast<uint32_t>(*result.http)) : "null";
  const std::string tls = result.tls ? std::to_string(static_cast<uint32_t>(*result.tls)) : "null";
  char output[1024]{};
  const int length = std::snprintf(output, sizeof(output),
      "{\"schema_version\":2,\"initialization_result\":%u,\"tls_result\":%s,\"http_result\":%s,\"handshake_verified\":%s,"
      "\"request_sent\":%s,\"response_verified\":%s,\"wire_tx\":%llu,\"wire_rx\":%llu,"
      "\"qualified\":%s,\"proves_dns\":false,\"proves_internet\":false,\"release_ready\":false}\n",
      static_cast<uint32_t>(result.initialization_result), tls.c_str(), http.c_str(), boolean(result.handshake_verified),
      boolean(result.request_sent), boolean(result.echoed),
      static_cast<unsigned long long>(result.wire_tx), static_cast<unsigned long long>(result.wire_rx), boolean(result.qualified));
  if (length <= 0 || static_cast<size_t>(length) >= sizeof(output)) return false;
  const auto path = base.substr(0, base.find_last_of(L"\\/") + 1) + L"owned-https-context.json";
  Handle file(CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_NEW,
      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
  DWORD written = 0;
  return file && file.get() != INVALID_HANDLE_VALUE &&
      WriteFile(file.get(), output, static_cast<DWORD>(length), &written, nullptr) && written == static_cast<DWORD>(length);
}
#endif
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
    const auto refuse = [&result](InitializationResult issue) { result.initialization_result = issue; throw 1; };
    Winsock winsock;
    if (!winsock.ready) refuse(InitializationResult::WinsockUnavailable);
    health::AttachedTun attachment;
    {
      std::lock_guard lock(core_mutex_);
      if (owned_cancel_) refuse(InitializationResult::Cancelled);
      if (!observed_core_) refuse(InitializationResult::CoreUnavailable);
      if (!instance_) refuse(InitializationResult::InstanceUnavailable);
      if (state_ != State::TunnelReady) refuse(InitializationResult::StateNotReady);
      traffic::Snapshot counter;
      if (traffic_read_(observed_core_, sizeof(counter), &counter) != 1 || !traffic::Valid(counter)) refuse(InitializationResult::TrafficUnavailable);
      if (counter.flags != 3) refuse(InitializationResult::TrafficNotReady);
      if (attachment_read_(observed_core_, sizeof(attachment), &attachment) != 1) refuse(InitializationResult::AttachmentUnavailable);
      if (attachment.flags != 3) refuse(InitializationResult::AttachmentNotReady);
      if (attachment.epoch != counter.epoch) refuse(InitializationResult::EpochMismatch);
      instance = instance_; epoch = counter.epoch;
    }
    probe::Request request;
    request.epoch = epoch;
    if (BCryptGenRandom(nullptr, reinterpret_cast<BYTE*>(&request.token), sizeof(request.token), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) refuse(InitializationResult::EntropyUnavailable);
    request.token &= probe::kMaximum;
    if (!request.token) refuse(InitializationResult::EmptyToken);
    const auto deadline = GetTickCount64() + 4000;
    result.initialization_result = InitializationResult::Passed;
    result.stage = 2;
    {
      auto ordinary = Connect(attachment, false, deadline, owned_cancel_, result.socket_failure);
      if (ordinary.value == INVALID_SOCKET) throw 1;
      result.stage = 3;
      std::lock_guard lock(core_mutex_);
      if (owned_cancel_ || !observed_core_ || instance_ != instance) throw 1;
      const auto refusal = owned_arm_(observed_core_, ordinary.value, sizeof(request), &request);
      result.nonexclusive_rejected = refusal == static_cast<uint32_t>(probe::ArmResult::SocketRejected);
      if (!result.nonexclusive_rejected) { owned_disarm_(observed_core_, request.token); throw 1; }
    }
    result.stage = 4;
    auto socket = Connect(attachment, true, deadline, owned_cancel_, result.socket_failure);
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
#ifdef LIWETUN_TEST_OWNED_HTTPS
    result.stage = 6;
    const auto received = ExchangeHttps(socket.value, request.token, deadline, owned_cancel_, result);
    result.stage = 7;
    result.receive_cancelled = received == IoResult::Cancelled;
    result.receive_timed_out = received == IoResult::Deadline;
#else
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
    result.receive_timed_out = received == IoResult::Deadline;
    result.echoed = received == IoResult::Complete && response == expected;
#endif
    // Observe actual state transitions following a failed receive, without
    // changing SDK state or holding its lifetime lock over the wait. The bound
    // leaves margin inside the existing five-second arm TTL after a 4 s I/O.
    for (unsigned poll = 0; poll < 10 && !owned_cancel_.load(); ++poll) {
      {
        std::lock_guard lock(core_mutex_);
        traffic::Snapshot current;
        if (observed_core_ && instance_ == instance &&
            traffic_read_(observed_core_, sizeof(current), &current) == 1 && traffic::Valid(current) &&
            (current.flags & traffic::kSupported) && current.epoch > 0) {
          result.state_epoch_changed = current.epoch != epoch;
        }
      }
      if (result.state_epoch_changed || received == IoResult::Complete) break;
      Sleep(25);
    }
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
#ifdef LIWETUN_TEST_OWNED_HTTPS
    result.qualified = result.qualified && GetTickCount64() < deadline && result.wire_tx > 0 && result.wire_rx > 0 &&
        result.sample.tx >= result.wire_tx && result.sample.rx >= result.wire_rx;
#endif
    result.stage = 9;
  } catch (...) { result.qualified = false; }
  try {
    result.qualified = result.qualified && result.disarmed;
    if (result.state_epoch_changed) {
      result.qualified = false; result.same_epoch = false;
      if (result.sample.flags & probe::kArmed) result.sample = probe::Snapshot{};
    }
    result.cancelled = owned_cancel_.load();
    if (result.cancelled) { result.qualified = false; result.sample = probe::Snapshot{}; }
    bool written = WriteResult(owned_report_, result);
#ifdef LIWETUN_TEST_OWNED_HTTPS
    written = WriteHttpsResult(owned_report_, result) && written;
#endif
    std::lock_guard lock(owned_publish_mutex_);
    owned_instance_ = instance; owned_epoch_ = epoch;
    owned_qualified_ = written && result.qualified && !owned_cancel_.load();
  } catch (...) { owned_qualified_ = false; }
}
} // namespace liwetun
