#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <array>
#include <memory>
#include <string>
#include <vector>

namespace liwetun {
struct CloseHandleDeleter { void operator()(void* handle) const { if (handle && handle != INVALID_HANDLE_VALUE) CloseHandle(handle); } };
using Handle = std::unique_ptr<void, CloseHandleDeleter>;
using Digest = std::array<unsigned char, 32>;
struct Image {
  Handle handle;
  std::wstring path;
  Digest signer{};
};
struct Actor {
  Handle process;
  std::wstring sid;
  DWORD session = 0;
  LUID logon{};
  Image image;
};
std::wstring SelfPath();
std::wstring Directory(const std::wstring& path);
bool EqualPath(const std::wstring& a, const std::wstring& b);
bool ProtectedPath(const std::wstring& path);
bool OpenTrustedImage(const std::wstring& path, Image& image, bool require_signature = true);
bool SameSigner(const Image& a, const Image& b);
bool HashFile(HANDLE file, Digest& digest);
bool ProcessActor(DWORD pid, Actor& actor);
bool AuthorizePipe(HANDLE pipe, const std::wstring& owner_sid, const Image& service, Actor& actor);
bool VerifyServer(HANDLE pipe, const Image& client);
bool IsSystemProcess(HANDLE process);
}  // namespace liwetun
