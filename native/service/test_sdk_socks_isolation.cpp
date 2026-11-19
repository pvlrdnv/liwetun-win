// Disposable CI feasibility probe only. Synthetic fixed settings, no real URI.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>

namespace {
void Check(bool value) { if (!value) throw 1; }
bool NoDriverModule() { return GetModuleHandleW(L"wintun.dll") == nullptr; }
using Start = void* (*)(const char*, bool, void (*)(void*, int), void*, void (*)(void*, void*), void*);
using Stop = void (*)(void*);
struct Core { void* value{}; Stop stop{}; ~Core() { if (value) stop(value); } };
struct Library { HMODULE value{}; ~Library() { if (value) FreeLibrary(value); } };
struct Socket { SOCKET value = INVALID_SOCKET; ~Socket() { if (value != INVALID_SOCKET) closesocket(value); } };
void Transfer(SOCKET socket, unsigned char* bytes, int count, bool writing) {
  for (int position = 0; position < count;) {
    const int result = writing ? send(socket, reinterpret_cast<const char*>(bytes + position), count - position, 0)
                               : recv(socket, reinterpret_cast<char*>(bytes + position), count - position, 0);
    Check(result > 0); position += result;
  }
}
void Handshake(bool offer_auth, bool correct_password) {
  Socket socket{::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)};
  Check(socket.value != INVALID_SOCKET);
  const DWORD timeout = 500;
  Check(setsockopt(socket.value, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout)) == 0);
  Check(setsockopt(socket.value, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout)) == 0);
  sockaddr_in address{}; address.sin_family = AF_INET; address.sin_port = htons(38559);
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  Check(connect(socket.value, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0);
  unsigned char greeting[]{5, 1, static_cast<unsigned char>(offer_auth ? 2 : 0)};
  Transfer(socket.value, greeting, sizeof(greeting), true);
  unsigned char method[2]{}; Transfer(socket.value, method, sizeof(method), false);
  Check(method[0] == 5 && method[1] == (offer_auth ? 2 : 255));
  if (!offer_auth) return;
  const std::string user = "synthetic-local-user";
  const std::string password = correct_password ? "synthetic-local-password" : "synthetic-wrong-password";
  std::vector<unsigned char> auth{1, static_cast<unsigned char>(user.size())};
  auth.insert(auth.end(), user.begin(), user.end()); auth.push_back(static_cast<unsigned char>(password.size()));
  auth.insert(auth.end(), password.begin(), password.end());
  Transfer(socket.value, auth.data(), static_cast<int>(auth.size()), true);
  unsigned char answer[2]{}; Transfer(socket.value, answer, sizeof(answer), false);
  Check(answer[0] == 1 && (correct_password ? answer[1] == 0 : answer[1] != 0));
}
}
int wmain(int argc, wchar_t** argv) {
  unsigned stage = 0;
  try {
    wchar_t actions[8]{};
    Check(GetEnvironmentVariableW(L"GITHUB_ACTIONS", actions, 8) && std::wstring(actions) == L"true" && argc == 2);
    const std::filesystem::path dll = std::filesystem::absolute(argv[1]);
    Check(!std::filesystem::exists(dll.parent_path() / L"wintun.dll") && NoDriverModule());
    WSADATA winsock{}; Check(WSAStartup(MAKEWORD(2,2), &winsock) == 0);
    Library library{LoadLibraryExW(dll.c_str(), nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32)};
    stage = 1; Check(library.value != nullptr && NoDriverModule());
    const auto policy = reinterpret_cast<int (*)()>(GetProcAddress(library.value, "liwetun_core_policy_version"));
    const auto start = reinterpret_cast<Start>(GetProcAddress(library.value, "trusttunnel_start_ex"));
    const auto stop = reinterpret_cast<Stop>(GetProcAddress(library.value, "trusttunnel_stop_ex"));
    Check(policy && policy() == 1 && start && stop);
    const char* config = R"(loglevel="error"
vpn_mode="general"
killswitch_enabled=false
exclusions_preresolve_enabled=false
[endpoint]
hostname="node.example.invalid"
addresses=["127.0.0.1:9"]
username="synthetic-endpoint-user"
password="synthetic-endpoint-password"
skip_verification=false
has_ipv6=false
upstream_protocol="http2"
[listener.socks]
address="127.0.0.1:38559"
username="synthetic-local-user"
password="synthetic-local-password"
)";
    Core core{start(config, true, nullptr, nullptr, nullptr, nullptr), stop};
    stage = 2; Check(core.value != nullptr && NoDriverModule());
    bool ready = false;
    const ULONGLONG deadline = GetTickCount64() + 10000;
    while (!ready && GetTickCount64() < deadline) {
      try { Handshake(true, true); ready = true; } catch (...) { Sleep(50); }
    }
    stage = 3; Check(ready);
    Handshake(false, false); Handshake(true, false);
    Check(NoDriverModule());
    std::cout << "{\"ready\":true,\"authenticated_socks_handshake\":true,\"no_auth_refused\":true,\"wrong_proxy_auth_refused\":true,\"wintun_not_loaded\":true,\"upstream_payload_verified\":false}" << std::endl;
    std::string command; Check(std::getline(std::cin, command) && command == "stop");
    stop(core.value); core.value = nullptr;
    stage = 4; Check(NoDriverModule());
    Check(FreeLibrary(library.value) != FALSE); library.value = nullptr;
    Check(NoDriverModule());
    std::cout << "{\"stopped\":true,\"wintun_not_loaded\":true,\"upstream_payload_verified\":false}" << std::endl;
    return 0;
  } catch (...) {
    std::cout << "{\"probe_failed\":true,\"stage\":" << stage << ",\"upstream_payload_verified\":false}" << std::endl;
    return 2;
  }
}
