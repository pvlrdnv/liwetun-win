#pragma once
#include <array>
#include <cstddef>
#include <cstdint>

// Private SDK creation policy. No names, GUIDs, LUIDs or handles are diagnostics.
namespace liwetun::adapter {
struct Identity {
  std::array<uint8_t, 16> guid{};
  std::array<wchar_t, 41> name{};
};
struct Observation {
  Identity identity{};
  uint32_t index = 0;
  uint64_t luid = 0;
};
inline bool Matches(const Observation& actual, const Observation& created) noexcept {
  return created.index && created.luid && actual.index == created.index &&
      actual.luid == created.luid && actual.identity.guid == created.identity.guid &&
      actual.identity.name == created.identity.name;
}
template<class Handle> struct Created {
  Handle handle{};
  Observation authority{};
};

template<class Ops> Created<typename Ops::Handle> CreateFresh(Ops& ops) noexcept {
  // Separate random material for requested GUID and opaque physical alias.
  // The configured logical name is never an input to this API.
  std::array<uint8_t, 32> random{};
  if (!ops.Random(random)) return {};
  Identity identity;
  for (std::size_t i = 0; i < identity.guid.size(); ++i) identity.guid[i] = random[i];
  identity.guid[7] = static_cast<uint8_t>((identity.guid[7] & 15) | 64);
  identity.guid[8] = static_cast<uint8_t>((identity.guid[8] & 63) | 128);
  constexpr wchar_t prefix[] = L"LiWeTun-";
  constexpr wchar_t digits[] = L"0123456789abcdef";
  for (std::size_t i = 0; i < 8; ++i) identity.name[i] = prefix[i];
  for (std::size_t i = 0; i < 16; ++i) {
    identity.name[8 + i * 2] = digits[random[16 + i] >> 4];
    identity.name[9 + i * 2] = digits[random[16 + i] & 15];
  }
  // Refuse an observed collision. This is not an atomic reservation and does
  // not claim protection against a privileged exact-physical-name race.
  if (!ops.Vacant(identity)) return {};
  const auto handle = ops.Create(identity);
  if (!handle) return {};
  Observation actual{};
  if (!ops.Observe(handle, actual) || !actual.index || !actual.luid ||
      actual.identity.guid != identity.guid || actual.identity.name != identity.name) {
    ops.Close(handle); // only the handle returned by this attempt's Create
    return {};
  }
  return {handle, actual};
}
} // namespace liwetun::adapter
