#include "windows_probe_socket.h"
#include "../health/attached_tun_abi.h"
#include <cstdlib>

using namespace liwetun::probe;
void Require(bool value) { if (!value) std::abort(); }
struct Socket {
  SOCKET value = INVALID_SOCKET;
  ~Socket() { if (value != INVALID_SOCKET) closesocket(value); }
};
int main() {
  WSADATA data{};
  Require(WSAStartup(MAKEWORD(2, 2), &data) == 0);
  {
    Socket listener{::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)};
    Require(listener.value != INVALID_SOCKET);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    Require(bind(listener.value, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
    Require(listen(listener.value, 2) == 0);
    int size = sizeof(address);
    Require(getsockname(listener.value, reinterpret_cast<sockaddr*>(&address), &size) == 0);
    DWORD index = 0;
    Require(GetBestInterfaceEx(reinterpret_cast<sockaddr*>(&address), &index) == NO_ERROR && index != 0);
    NET_LUID luid{};
    Require(ConvertInterfaceIndexToLuid(index, &luid) == NO_ERROR);
    liwetun::health::AttachedTun context;
    context.flags = 3; context.index = index; context.luid = luid.Value;
    context.epoch = 3; context.at_ms = 100;
    Socket owned{::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)};
    int exclusive = 1;
    Require(setsockopt(owned.value, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
        reinterpret_cast<const char*>(&exclusive), sizeof(exclusive)) == 0);
    Key key;
    Require(!DeriveOwnedKey(owned.value, context, key)); // Not connected.
    Require(connect(owned.value, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
    Socket peer{accept(listener.value, nullptr, nullptr)};
    Require(peer.value != INVALID_SOCKET);
    Require(DeriveOwnedKey(owned.value, context, key));
    Require(key.family == 4 && key.source[0] == 127 && key.destination[0] == 127 &&
        key.source_port != 0 && key.destination_port == ntohs(address.sin_port));
    auto wrong = context; ++wrong.index;
    Require(!DeriveOwnedKey(owned.value, wrong, key) && key.family == 0);
    wrong = context; wrong.flags = 1;
    Require(!DeriveOwnedKey(owned.value, wrong, key) && key.family == 0);
    Require(!DeriveOwnedKey(INVALID_SOCKET, context, key) && key.family == 0);
    Socket ordinary{::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)};
    Require(connect(ordinary.value, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
    Socket ordinary_peer{accept(listener.value, nullptr, nullptr)};
    Require(ordinary_peer.value != INVALID_SOCKET);
    Require(!DeriveOwnedKey(ordinary.value, context, key)); // No exclusive-port contract.
    Socket udp{::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)};
    Require(!DeriveOwnedKey(udp.value, context, key));
  }
  WSACleanup();
  return 0;
}
