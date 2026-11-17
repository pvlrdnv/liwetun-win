// SDK-internal definitions included after trusttunnel_s and attached TUN export.
// Caller serializes against SDK start/stop/destruction; no lock spans network I/O.
extern "C" __declspec(dllexport) uint32_t liwetun_probe_arm_socket_v1(
    trusttunnel_t* vpn, uintptr_t socket, uint32_t size, const liwetun::probe::Request* request) noexcept {
  using namespace liwetun::probe;
  if (!vpn || !vpn->client || !vpn->traffic || !request || size != sizeof(*request) || !ValidRequest(*request))
    return static_cast<uint32_t>(ArmResult::Invalid);
  try {
    const auto before = vpn->traffic->Read();
    if (before.flags != 3 || before.epoch != request->epoch) return static_cast<uint32_t>(ArmResult::NotReady);
    liwetun::health::AttachedTun attachment;
    if (liwetun_attached_tun_v1(vpn, sizeof(attachment), &attachment) != 1 ||
        attachment.flags != 3 || attachment.epoch != before.epoch) return static_cast<uint32_t>(ArmResult::NotReady);
    Key key;
    if (!DeriveOwnedKey(static_cast<SOCKET>(socket), attachment, key)) return static_cast<uint32_t>(ArmResult::SocketRejected);
    const auto result = vpn->client->liwetun_probe_arm(*request, key);
    const auto after = vpn->traffic->Read();
    if (result == ArmResult::Armed && (after.flags != 3 || after.epoch != before.epoch)) {
      vpn->client->liwetun_probe_disarm(request->token);
      return static_cast<uint32_t>(ArmResult::NotReady);
    }
    return static_cast<uint32_t>(result);
  } catch (...) { return static_cast<uint32_t>(ArmResult::NotReady); }
}
extern "C" __declspec(dllexport) uint32_t liwetun_probe_snapshot_socket_v1(
    trusttunnel_t* vpn, uintptr_t socket, uint64_t token, uint32_t size, liwetun::probe::Snapshot* output) noexcept {
  using namespace liwetun::probe;
  if (!vpn || !vpn->client || !vpn->traffic || !output || size != sizeof(*output) || !token || token > kMaximum) return 0;
  *output = Snapshot{};
  try {
    const auto before = vpn->traffic->Read();
    liwetun::health::AttachedTun attachment;
    if (before.flags != 3 || liwetun_attached_tun_v1(vpn, sizeof(attachment), &attachment) != 1 ||
        attachment.flags != 3 || attachment.epoch != before.epoch) {
      vpn->client->liwetun_probe_disarm(token);
      output->flags |= kFault;
      return 1;
    }
    Key key;
    if (!DeriveOwnedKey(static_cast<SOCKET>(socket), attachment, key)) {
      vpn->client->liwetun_probe_disarm(token);
      output->flags |= kSocketChanged;
      return 1;
    }
    *output = vpn->client->liwetun_probe_read(token, before.epoch, key);
    const auto after = vpn->traffic->Read();
    if (after.flags != 3 || after.epoch != before.epoch) {
      vpn->client->liwetun_probe_disarm(token);
      *output = Snapshot{};
      output->flags |= kEpochChanged;
    }
    return 1;
  } catch (...) { *output = Snapshot{}; output->flags |= kFault; return 1; }
}
extern "C" __declspec(dllexport) uint32_t liwetun_probe_disarm_v1(trusttunnel_t* vpn, uint64_t token) noexcept {
  if (!vpn || !vpn->client || !token || token > liwetun::probe::kMaximum) return 0;
  vpn->client->liwetun_probe_disarm(token);
  return 1;
}
