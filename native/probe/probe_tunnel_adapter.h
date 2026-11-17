#pragma once
#include "probe_slot.h"
#include "vpn/internal/vpn_client.h"
#include "vpn/internal/vpn_connection.h"
#include <optional>

namespace ag {
inline std::optional<liwetun::probe::Key> liwetun_owned_probe_key(const VpnConnection* conn) {
  if (!conn || conn->proto != IPPROTO_TCP) return std::nullopt;
  const auto* destination = std::get_if<SocketAddress>(&conn->addr.dst);
  if (!destination) return std::nullopt;
  liwetun::probe::Key key;
  const auto& source = conn->addr.src;
  if (source.is_ipv4() && destination->is_ipv4()) key.family = 4;
  else if (source.is_ipv6() && destination->is_ipv6() &&
      !source.is_ipv4_mapped() && !destination->is_ipv4_mapped()) key.family = 6;
  else return std::nullopt;
  const auto source_bytes = source.addr(), destination_bytes = destination->addr();
  const size_t count = key.family == 4 ? 4 : 16;
  if (source_bytes.size() != count || destination_bytes.size() != count) return std::nullopt;
  std::copy_n(source_bytes.begin(), count, key.source.begin());
  std::copy_n(destination_bytes.begin(), count, key.destination.begin());
  key.source_port = source.port(); key.destination_port = destination->port();
  if (!liwetun::probe::ValidKey(key)) return std::nullopt;
  return key;
}
inline void liwetun_owned_probe_bytes(VpnClient* client, const VpnConnection* conn,
    bool endpoint, uint64_t tx, uint64_t rx) noexcept {
  const auto& slot = client->parameters.liwetun_owned_probe;
  if (!slot || !slot->Active()) return;
  try {
    if (auto key = liwetun_owned_probe_key(conn)) slot->Bytes(*key, endpoint, tx, rx);
  } catch (...) { slot->ObservationFailure(); }
}
inline void liwetun_owned_probe_reject(VpnClient* client, const VpnConnection* conn, uint32_t reason) noexcept {
  const auto& slot = client->parameters.liwetun_owned_probe;
  if (!slot || !slot->Active()) return;
  try {
    if (auto key = liwetun_owned_probe_key(conn)) slot->Reject(*key, reason);
  } catch (...) { slot->ObservationFailure(); }
}
inline void liwetun_owned_probe_selected(VpnClient* client, const VpnConnection* conn, bool endpoint) noexcept {
  if (!endpoint) liwetun_owned_probe_reject(client, conn, liwetun::probe::kOtherPath);
}
} // namespace ag
