// Disposable CI loopback driver only. Not a service command or owner tool.
#include "http_probe.h"
#include "schannel_probe.h"
#include <charconv>
#include <cstdio>
#include <cstdlib>
#include <optional>
#include <thread>

using namespace liwetun::health;
namespace {
struct Socket { SOCKET value = INVALID_SOCKET; ~Socket() { if (value != INVALID_SOCKET) closesocket(value); } };
struct Winsock { ~Winsock() { WSACleanup(); } };
void Print(TlsResult tls, std::optional<HttpResult> http, bool handshake, bool sent, bool verified) {
  const auto number = http ? std::to_string(static_cast<uint32_t>(*http)) : "null";
  std::printf("{\"tls_result\":%u,\"http_result\":%s,\"handshake_verified\":%s,\"request_sent\":%s,"
      "\"response_verified\":%s,\"synthetic_nonce\":true,\"sdk_path_qualified\":false,\"release_ready\":false}\n",
      static_cast<uint32_t>(tls), number.c_str(), handshake ? "true" : "false", sent ? "true" : "false", verified ? "true" : "false");
}
}
int main(int argc, char** argv) {
  char actions[8]{};
  if (GetEnvironmentVariableA("GITHUB_ACTIONS", actions, sizeof(actions)) != 4 ||
      std::string_view(actions) != "true" || argc < 2 || argc > 3) return 2;
  unsigned port = 0;
  const std::string_view input(argv[1]);
  const auto parsed = std::from_chars(input.data(), input.data() + input.size(), port);
  if (parsed.ec != std::errc{} || parsed.ptr != input.data() + input.size() || !port || port > 65535) return 2;
  const bool cancel_read = argc == 3 && std::string_view(argv[2]) == "cancel-read";
  if (argc == 3 && !cancel_read) return 2;
  try {
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return 2;
    Winsock winsock;
    Socket socket;
    socket.value = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in peer{}; peer.sin_family = AF_INET; peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    peer.sin_port = htons(static_cast<u_short>(port));
    // The fixture is already listening on loopback; no external address/DNS.
    if (socket.value == INVALID_SOCKET || connect(socket.value, reinterpret_cast<sockaddr*>(&peer), sizeof(peer)) != 0) return 2;
    u_long nonblocking = 1;
    if (ioctlsocket(socket.value, FIONBIO, &nonblocking) != 0) return 2;
    std::atomic<bool> cancel{false};
    SocketIo io(socket.value, GetTickCount64() + 4000, cancel);
    SchannelProbe channel(io);
    auto result = channel.Handshake(L"health.liwetun.invalid");
    const bool handshake = result == TlsResult::Ok;
    if (!handshake) { Print(result, std::nullopt, false, false, false); return 0; }
    constexpr Nonce nonce{'c', 'i', '-', 't', 'e', 's', 't', '1'};
    const auto request = FixtureHealthRequest(nonce);
    if (!request) return 2;
    result = channel.Send(*request);
    if (result != TlsResult::Ok) { Print(result, std::nullopt, true, false, false); return 0; }
    std::optional<std::jthread> canceller;
    if (cancel_read) canceller.emplace([&] { Sleep(100); cancel = true; });
    HttpProbeParser response(nonce);
    std::vector<char> plain;
    for (unsigned record = 0; record < 256; ++record) {
      result = channel.Receive(plain);
      if (result != TlsResult::Ok) { response.Finish(); break; }
      if (response.Feed(plain) != HttpResult::NeedMore) break;
    }
    response.Finish();
    if (io.Control() == IoState::Deadline) result = TlsResult::Deadline;
    else if (io.Control() == IoState::Cancelled) result = TlsResult::Cancelled;
    Print(result, response.Result(), true, true, result == TlsResult::Ok && response.Result() == HttpResult::Verified);
  } catch (...) { return 2; }
}
