// Disposable-runner CI client. Only synthetic loopback profiles are used.
#include <winsock2.h>
#include <ws2tcpip.h>
#include "client.h"
#include "pipe_io.h"
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
int wmain(int argc, wchar_t** argv) {
  const std::wstring mode = argc >= 2 ? argv[1] : L"";
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
    for (unsigned i = 0; i < 30; ++i) {
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
    Handle pipe(CreateFileW(kPipeName, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr));
    if (!pipe || pipe.get() == INVALID_HANDLE_VALUE) { std::cout << "rejected\n"; return 0; }
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
