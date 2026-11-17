#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <span>

namespace liwetun::health {
enum class IoState : uint32_t { Ok, Cancelled, Deadline, Closed, Failed, Limit };
// Borrows one nonblocking socket. No DNS, route lookup/change, connect, fallback
// or ownership transfer; caller retains the descriptor through SDK proof read.
class SocketIo {
 public:
  static constexpr size_t kWireLimit = 262144;
  SocketIo(SOCKET socket, ULONGLONG deadline, const std::atomic<bool>& cancel)
      : socket_(socket), deadline_(deadline), cancel_(cancel) {}
  size_t SentBytes() const { return sent_; }
  size_t ReceivedBytes() const { return received_; }
  IoState Control() const {
    if (GetTickCount64() >= deadline_) return IoState::Deadline;
    return cancel_.load() ? IoState::Cancelled : IoState::Ok;
  }
  IoState Send(std::span<const char> bytes) {
    if (bytes.size() > kWireLimit - sent_) return IoState::Limit;
    size_t offset = 0;
    while (offset < bytes.size()) {
      if (const auto state = Control(); state != IoState::Ok) return state;
      const int count = send(socket_, bytes.data() + offset,
          static_cast<int>(std::min<size_t>(bytes.size() - offset, 65536)), 0);
      if (count > 0) { offset += static_cast<size_t>(count); sent_ += static_cast<size_t>(count); }
      else if (!count || WSAGetLastError() != WSAEWOULDBLOCK) return IoState::Failed;
      else if (const auto state = Wait(true); state != IoState::Ok) return state;
    }
    return Control();
  }
  IoState Receive(std::span<char> output, size_t& received) {
    received = 0;
    if (output.empty() || received_ == kWireLimit) return IoState::Limit;
    for (;;) {
      if (const auto state = Control(); state != IoState::Ok) return state;
      const auto capacity = std::min({output.size(), kWireLimit - received_, size_t{65536}});
      const int count = recv(socket_, output.data(), static_cast<int>(capacity), 0);
      if (count > 0) {
        received = static_cast<size_t>(count); received_ += received;
        return Control();
      }
      if (!count) return IoState::Closed;
      if (WSAGetLastError() != WSAEWOULDBLOCK) return IoState::Failed;
      if (const auto state = Wait(false); state != IoState::Ok) return state;
    }
  }
 private:
  IoState Wait(bool writing) {
    for (;;) {
      if (const auto state = Control(); state != IoState::Ok) return state;
      fd_set ready, errors;
      FD_ZERO(&ready); FD_ZERO(&errors); FD_SET(socket_, &ready); FD_SET(socket_, &errors);
      timeval timeout{0, 50000};
      const int result = select(0, writing ? nullptr : &ready, writing ? &ready : nullptr, &errors, &timeout);
      if (result == SOCKET_ERROR || FD_ISSET(socket_, &errors)) return IoState::Failed;
      if (result > 0 && FD_ISSET(socket_, &ready)) return Control();
    }
  }
  SOCKET socket_;
  ULONGLONG deadline_;
  const std::atomic<bool>& cancel_;
  size_t sent_ = 0, received_ = 0;
};
} // namespace liwetun::health
