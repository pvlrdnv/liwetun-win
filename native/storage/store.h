#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace liwetun::storage {
constexpr size_t kMaxPayload = 1024 * 1024;
enum class Code : uint32_t { Ok, Missing, Corrupt, Denied, Busy, Conflict, TooLarge, Failed, Unsupported };
enum class Area { Profiles, Journal };
struct Snapshot {
  Code code = Code::Failed;
  std::string payload;
  std::string revision;
  Snapshot() = default;
  explicit Snapshot(Code value) : code(value) {}
  Snapshot(Snapshot&&) noexcept = default;
  Snapshot& operator=(Snapshot&& other) noexcept;
  Snapshot(const Snapshot&) = delete;
  Snapshot& operator=(const Snapshot&) = delete;
  ~Snapshot();
};

// Fixed current-user location only. There is no caller-supplied file path.
Snapshot Load(Area area = Area::Profiles);
Snapshot Save(std::string payload, const std::string& expected_revision, Area area = Area::Profiles);
Snapshot Clear(const std::string& expected_revision, Area area = Area::Profiles);

#ifdef LIWETUN_STORAGE_TEST_ONLY
std::wstring TestDirectory();
bool TestCanDecryptContainer(const std::vector<unsigned char>& bytes);
#endif
}  // namespace liwetun::storage
