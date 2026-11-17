#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <cstring>
#include "probe_slot.h"

namespace liwetun::probe {
// Read-only, exact address entry lookup. Never enumerate adapters/addresses.
// The caller holds this fresh connected socket through arm/read/disarm and
// starts application I/O only after arm. No handle or tuple is retained here.
template <typename Attachment>
inline bool DeriveOwnedKey(SOCKET socket, const Attachment& attachment, Key& output) noexcept {
  output = Key{};
  if (sizeof(Attachment) != 40 || attachment.abi != 1 || attachment.size != 40 || attachment.flags != 3 ||
      !attachment.index || !attachment.luid || socket == INVALID_SOCKET) return false;
  int kind = 0, exclusive = 0, reuse = 0;
  const auto option = [socket](int name, int& value) {
    int size = sizeof(value);
    return getsockopt(socket, SOL_SOCKET, name, reinterpret_cast<char*>(&value), &size) == 0 && size == static_cast<int>(sizeof(value));
  };
  if (!option(SO_TYPE, kind) || kind != SOCK_STREAM ||
      !option(SO_EXCLUSIVEADDRUSE, exclusive) || !exclusive ||
      !option(SO_REUSEADDR, reuse) || reuse) return false;
  WSAPROTOCOL_INFOW protocol{};
  int protocol_size = sizeof(protocol);
  if (getsockopt(socket, SOL_SOCKET, SO_PROTOCOL_INFOW, reinterpret_cast<char*>(&protocol), &protocol_size) != 0 ||
      protocol_size != static_cast<int>(sizeof(protocol)) || protocol.iProtocol != IPPROTO_TCP) return false;
  sockaddr_storage local{}, peer{};
  int local_size = sizeof(local), peer_size = sizeof(peer);
  if (getsockname(socket, reinterpret_cast<sockaddr*>(&local), &local_size) != 0 ||
      getpeername(socket, reinterpret_cast<sockaddr*>(&peer), &peer_size) != 0 ||
      local.ss_family != peer.ss_family) return false;
  MIB_UNICASTIPADDRESS_ROW row{};
  InitializeUnicastIpAddressEntry(&row);
  row.InterfaceLuid.Value = attachment.luid;
  row.InterfaceIndex = attachment.index;
  Key key;
  if (local.ss_family == AF_INET && local_size >= static_cast<int>(sizeof(sockaddr_in)) && peer_size >= static_cast<int>(sizeof(sockaddr_in))) {
    const auto& source = *reinterpret_cast<const sockaddr_in*>(&local);
    const auto& destination = *reinterpret_cast<const sockaddr_in*>(&peer);
    key.family = 4;
    std::memcpy(key.source.data(), &source.sin_addr, 4);
    std::memcpy(key.destination.data(), &destination.sin_addr, 4);
    key.source_port = ntohs(source.sin_port); key.destination_port = ntohs(destination.sin_port);
    row.Address.Ipv4 = source; row.Address.Ipv4.sin_port = 0;
  } else if (local.ss_family == AF_INET6 && local_size >= static_cast<int>(sizeof(sockaddr_in6)) && peer_size >= static_cast<int>(sizeof(sockaddr_in6))) {
    const auto& source = *reinterpret_cast<const sockaddr_in6*>(&local);
    const auto& destination = *reinterpret_cast<const sockaddr_in6*>(&peer);
    key.family = 6;
    std::memcpy(key.source.data(), &source.sin6_addr, 16);
    std::memcpy(key.destination.data(), &destination.sin6_addr, 16);
    key.source_port = ntohs(source.sin6_port); key.destination_port = ntohs(destination.sin6_port);
    row.Address.Ipv6 = source; row.Address.Ipv6.sin6_port = 0;
  } else return false;
  if (!ValidKey(key) || GetUnicastIpAddressEntry(&row) != NO_ERROR ||
      row.InterfaceLuid.Value != attachment.luid || row.InterfaceIndex != attachment.index ||
      row.DadState != IpDadStatePreferred) return false;
  output = key;
  return true;
}
} // namespace liwetun::probe
