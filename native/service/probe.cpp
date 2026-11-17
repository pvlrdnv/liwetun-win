// Disposable-runner CI client. Only synthetic loopback profiles are used.
#include <winsock2.h>
#include <ws2tcpip.h>
#include "client.h"
#include "pipe_io.h"
#include "wfp_probe.h"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <optional>
#include <iphlpapi.h>

using namespace liwetun;
std::optional<bool> AdapterPresent(const wchar_t* alias) {
  MIB_IF_TABLE2* table = nullptr;
  if (GetIfTable2(&table) != NO_ERROR) return std::nullopt;
  bool found = false;
  for (ULONG i = 0; i < table->NumEntries; ++i) if (std::wstring(table->Table[i].Alias) == alias) found = true;
  FreeMibTable(table);
  return found;
}
void PrintTraffic(const TrafficReply& data) {
  const auto& sample = data.sample;
  const bool valid = (sample.flags & traffic::kValid) != 0;
  auto optional = [](uint64_t value, bool known) {
    if (known && value <= traffic::kMaximum) std::cout << value;
    else std::cout << "null";
  };
  std::cout << "{\"code\":" << static_cast<uint32_t>(data.status.code)
      << ",\"flags\":" << sample.flags << ",\"instance\":";
  optional(data.instance, data.instance != 0);
  std::cout << ",\"epoch\":"; optional(sample.epoch, sample.epoch != 0);
  std::cout << ",\"at_ms\":"; optional(sample.at_ms, sample.epoch != 0);
  std::cout << ",\"tx\":"; optional(sample.tx, valid);
  std::cout << ",\"rx\":"; optional(sample.rx, valid);
  std::cout << ",\"last_tx_ms\":"; optional(sample.last_tx_ms, valid);
  std::cout << ",\"last_rx_ms\":"; optional(sample.last_rx_ms, valid);
  std::cout << ",\"core_state\":"; optional(sample.state, sample.state <= 5);
  std::cout << "}" << std::endl;
}
int wmain(int argc, wchar_t** argv) {
  const std::wstring mode = argc >= 2 ? argv[1] : L"";
  if (mode == L"--traffic-watch" && argc == 2) {
    wchar_t disposable[8]{};
    if (GetEnvironmentVariableW(L"GITHUB_ACTIONS", disposable, 8) != 4 || std::wstring(disposable) != L"true") return 70;
    auto data = ServiceTrafficRequest();
    if (!(data.sample.flags & traffic::kValid)) { std::cout << "not_ready" << std::endl; return 71; }
    std::cout << "ready" << std::endl;
    const ULONGLONG deadline = GetTickCount64() + 8000;
    unsigned reads = 1, inactive = 0;
    bool valid = true;
    while (GetTickCount64() < deadline && reads < 1000) {
      data = ServiceTrafficRequest();
      ++reads;
      valid = valid && traffic::Valid(data.sample);
      if (!(data.sample.flags & traffic::kValid)) ++inactive;
      Sleep(5);
    }
    const bool passed = valid && inactive > 0;
    std::cout << "{\"passed\":" << (passed ? "true" : "false")
        << ",\"reads\":" << reads << ",\"inactive_after_active\":" << inactive
        << ",\"tunnel_started_by_watcher\":false}" << std::endl;
    return passed ? 0 : 72;
  }
  if (mode == L"--traffic" && argc == 2) { PrintTraffic(ServiceTrafficRequest()); return 0; }
  if (mode == L"--wfp-state" && argc == 2) return InspectOwnedWfpSessions();
  if (mode == L"--wfp-watch" && argc == 2) return InspectOwnedWfpSessions(true);
  if (mode == L"--disconnect-regression") {
    // Synthetic local transport reproducer: old disconnect-after-write loses
    // an unread reply. No service, credentials, SCM or network configuration.
    wchar_t environment[8]{};
    if (GetEnvironmentVariableW(L"GITHUB_ACTIONS", environment, 8) != 4 || std::wstring(environment) != L"true") return 60;
    const auto name = L"\\\\.\\pipe\\LiWeTun-CI-Reply-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64());
    Handle server(CreateNamedPipeW(name.c_str(), PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 16384, 16384, 0, nullptr));
    if (!server || server.get() == INVALID_HANDLE_VALUE) return 61;
    Handle client(CreateFileW(name.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr));
    if (!client || client.get() == INVALID_HANDLE_VALUE) return 62;
    Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    OVERLAPPED connection{}; connection.hEvent = event.get();
    if (!event || (ConnectNamedPipe(server.get(), &connection) == FALSE && GetLastError() != ERROR_PIPE_CONNECTED)) return 63;
    Reply sent{}, received{};
    if (!PipeIo(server.get(), nullptr, &sent, sizeof(sent), true) || !DisconnectNamedPipe(server.get())) return 64;
    if (PipeIo(client.get(), nullptr, &received, sizeof(received), false)) return 65;
    std::cout << "unread_reply_discard_reproduced\n";
    return 0;
  }
  if (mode == L"--delayed-read-query") {
    Image self;
    if (!OpenTrustedImage(SelfPath(), self)) return 66;
    Handle pipe = OpenControlPipe();
    if (!pipe || !VerifyServer(pipe.get(), self)) return 67;
    Request request{}; request.command = Command::Query; request.nonce = 37;
    if (!PipeIo(pipe.get(), nullptr, &request, sizeof(request), true)) return 68;
    Sleep(350); // Force server completion before this authenticated client reads.
    Reply reply{};
    if (!PipeIo(pipe.get(), nullptr, &reply, sizeof(reply), false) || reply.magic != kMagic ||
        reply.version != kVersion || reply.nonce != request.nonce || reply.code != Code::Ok) return 69;
    std::cout << "delayed_reply_received\n";
    return 0;
  }
  if (mode == L"--hold-pipe") {
    Handle pipe = OpenControlPipe();
    if (!pipe) return 52;
    std::cout << "held" << std::endl;
    Sleep(750);
    return 0;
  }
  if (mode == L"--network-session" && argc == 3) {
    // Keep the authenticated lease process alive while the external CI harness
    // probes its own TUN. Never print the profile or accept arbitrary commands.
    std::ifstream input{std::filesystem::path(argv[2])};
    std::string uri;
    std::getline(input, uri);
    if (!uri.empty() && uri.back() == '\r') uri.pop_back();
    if (!uri.starts_with("tt://?") || uri.size() > kMaxPayload) return 50;
    auto print = [](const Reply& r) {
      std::cout << "{\"code\":" << static_cast<uint32_t>(r.code)
          << ",\"state\":" << static_cast<uint32_t>(r.state)
          << ",\"core_state\":" << r.core_state << "}" << std::endl;
    };
    const auto start = ServiceRequest(Command::Start, uri, true);
    SecureZeroMemory(uri.data(), uri.size());
    print(start);
    std::string command;
    while (std::getline(std::cin, command)) {
      if (command == "query") print(ServiceRequest(Command::Query));
      else if (command == "traffic") {
        PrintTraffic(ServiceTrafficRequest());
      }
      else if (command == "stop") { print(ServiceRequest(Command::Stop)); return 0; }
      else return 51;
    }
    ServiceRequest(Command::Stop);
    return 0;
  }
  if (mode == L"--sdk-privacy") {
    Image self, sdk;
    if (!OpenTrustedImage(SelfPath(), self) || !OpenTrustedImage(Directory(self.path) + L"\\trusttunnel.dll", sdk) || !SameSigner(self, sdk)) return 40;
    HMODULE module = LoadLibraryExW(sdk.path.c_str(), nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!module) return 41;
    auto policy = reinterpret_cast<int (*)()>(GetProcAddress(module, "liwetun_core_policy_version"));
    auto decode = reinterpret_cast<char* (*)(const char*)>(GetProcAddress(module, "trusttunnel_decode_deeplink"));
    auto init = reinterpret_cast<void (*)(const wchar_t*)>(GetProcAddress(module, "trusttunnel_log_init"));
    auto export_logs = reinterpret_cast<void (*)(const wchar_t*, void (*)(void*, const wchar_t*), void*)>(GetProcAddress(module, "trusttunnel_log_export"));
    const auto root = Directory(self.path) + L"\\forbidden-raw-logs";
    if (!policy || !decode || !init || !export_logs || policy() != 1 || GetFileAttributesW(root.c_str()) != INVALID_FILE_ATTRIBUTES) { FreeLibrary(module); return 42; }
    init(root.c_str());
    if (decode("tt://?SDK_PRIVATE_SYNTHETIC_CANARY_261115") != nullptr) { FreeLibrary(module); return 43; }
    unsigned count = 0;
    export_logs(root.c_str(), [](void* value, const wchar_t*) { ++*static_cast<unsigned*>(value); }, &count);
    const bool clean = count == 0 && GetFileAttributesW(root.c_str()) == INVALID_FILE_ATTRIBUTES;
    FreeLibrary(module);
    if (!clean) return 44;
    std::cout << "privacy_profile_verified\n";
    return 0;
  }
  if (mode == L"--driver-cycle") {
    if (AdapterPresent(L"LiWeTun.Driver.CI") != false) return 20;
    Image self, driver;
    if (!OpenTrustedImage(SelfPath(), self) || !OpenTrustedImage(Directory(self.path) + L"\\wintun.dll", driver)) return 21;
    HMODULE module = LoadLibraryExW(driver.path.c_str(), nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!module) return 22;
    auto create = reinterpret_cast<void* (WINAPI*)(LPCWSTR, LPCWSTR, const GUID*)>(GetProcAddress(module, "WintunCreateAdapter"));
    auto close = reinterpret_cast<void (WINAPI*)(void*)>(GetProcAddress(module, "WintunCloseAdapter"));
    if (!create || !close) { FreeLibrary(module); return 23; }
    void* adapter = create(L"LiWeTun.Driver.CI", L"LiWeTun", nullptr);
    if (!adapter) { FreeLibrary(module); return 24; }
    bool seen = false;
    for (unsigned i = 0; i < 50; ++i) { if (AdapterPresent(L"LiWeTun.Driver.CI") == true) { seen = true; break; } Sleep(100); }
    close(adapter);
    bool removed = false;
    for (unsigned i = 0; i < 50; ++i) { if (AdapterPresent(L"LiWeTun.Driver.CI") == false) { removed = true; break; } Sleep(100); }
    FreeLibrary(module);
    std::cout << "{\"adapter_created\":" << (seen ? "true" : "false") << ",\"adapter_removed\":" << (removed ? "true" : "false") << "}\n";
    return seen && removed ? 0 : 25;
  }
  if (mode == L"--native-lifecycle" && argc == 3) {
    std::ifstream input{std::filesystem::path(argv[2])};
    std::string uri;
    std::getline(input, uri);
    if (!uri.empty() && uri.back() == '\r') uri.pop_back();
    if (!uri.starts_with("tt://?") || uri.size() > kMaxPayload) return 30;
    auto response = ServiceRequest(Command::Start, uri, true);
    SecureZeroMemory(uri.data(), uri.size());
    if (response.code != Code::Ok && response.code != Code::CoreFailure) return 31;
    bool observed = response.core_state <= 5;
    bool adapter_seen = false;
    for (unsigned i = 0; i < 60; ++i) {
      adapter_seen = adapter_seen || AdapterPresent(L"LiWeTun") == true;
      response = ServiceRequest(Command::Query);
      observed = observed || response.core_state <= 5;
      if (response.state == State::Error) break;
      Sleep(100);
    }
    response = ServiceRequest(Command::Stop);
    if (response.code != Code::Ok) return 32;
    bool stopped = false;
    for (unsigned i = 0; i < 50; ++i) {
      response = ServiceRequest(Command::Query);
      if (response.code == Code::Ok && response.state == State::Disconnected && AdapterPresent(L"LiWeTun") == false) { stopped = true; break; }
      Sleep(100);
    }
    std::cout << "{\"core_state_observed\":" << (observed ? "true" : "false")
        << ",\"adapter_seen\":" << (adapter_seen ? "true" : "false")
        << ",\"stopped_and_cleaned\":" << (stopped ? "true" : "false") << "}\n";
    return observed && stopped ? 0 : 33;
  }
  if (mode == L"--protocol") {
    Request request{};
    request.nonce = 7;
    if (!Valid(request)) return 1;
    request.length = 1;
    if (Valid(request)) return 2;
    request.command = Command::Start;
    request.length = kMaxPayload + 1;
    if (Valid(request)) return 3;
    request.command = Command::Traffic;
    request.length = 0;
    if (!Valid(request)) return 4;
    request.length = 1;
    if (Valid(request)) return 5;
    std::cout << "protocol_checks_passed\n";
    return 0;
  }
  if (mode == L"--query" || mode == L"--stop" || mode == L"--invalid-profile") {
    const auto command = mode == L"--stop" ? Command::Stop : mode == L"--invalid-profile" ? Command::Start : Command::Query;
    const std::string profile = mode == L"--invalid-profile" ? "tt://?SYNTHETIC_INVALID_CANARY_261115" : "";
    const Reply reply = ServiceRequest(command, profile, true);
    std::cout << "{\"code\":" << static_cast<uint32_t>(reply.code)
              << ",\"state\":" << static_cast<uint32_t>(reply.state)
              << ",\"runtime_ready\":" << reply.runtime_ready
              << ",\"core_state\":" << reply.core_state << "}\n";
    return 0;
  }
  if (mode == L"--attack" || mode == L"--bad-frame") {
    Handle pipe = OpenControlPipe();
    // An unavailable server is not evidence of authorization rejection.
    if (!pipe) { std::cout << "unavailable\n"; return 53; }
    Request request{};
    request.nonce = 9;
    if (mode == L"--bad-frame") request.length = kMaxPayload + 1;
    Reply reply{};
    const bool response = PipeIo(pipe.get(), nullptr, &request, sizeof(request), true) &&
        PipeIo(pipe.get(), nullptr, &reply, sizeof(reply), false);
    if (mode == L"--attack") {
      std::cout << (response ? "unexpected_acceptance\n" : "rejected\n");
      return response ? 1 : 0;
    }
    return response && reply.code == Code::Malformed ? 0 : 1;
  }
  return 4;
}
