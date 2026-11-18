#include "fresh_adapter.h"
#include <cassert>
#include <thread>
#include <vector>

using namespace liwetun::adapter;
struct Fake {
  using Handle = unsigned;
  unsigned random_calls = 0, vacant_calls = 0, creates = 0, observations = 0, closes = 0;
  unsigned fault = 0;
  uint8_t seed = 1;
  Identity requested{};
  bool Random(std::array<uint8_t, 32>& bytes) noexcept {
    ++random_calls;
    bytes.fill(seed);
    return fault != 1;
  }
  bool Vacant(const Identity&) noexcept { ++vacant_calls; return fault != 2; }
  Handle Create(const Identity& identity) noexcept {
    ++creates; requested = identity; return fault == 3 ? 0u : 71u;
  }
  bool Observe(Handle handle, Observation& result) noexcept {
    assert(handle == 71);
    ++observations;
    result = {requested, 5, 17};
    if (fault == 5) result.identity.guid[0] ^= 1;
    if (fault == 6) result.identity.name[0] = L'X';
    if (fault == 7) result.index = 0;
    if (fault == 8) result.luid = 0;
    return fault != 4;
  }
  void Close(Handle handle) noexcept { assert(handle == 71); ++closes; }
};
int main() {
  for (unsigned fault = 1; fault <= 8; ++fault) {
    Fake ops; ops.fault = fault;
    const auto result = CreateFresh(ops);
    assert(!result.handle && !result.authority.index && !result.authority.luid);
    assert(ops.random_calls == 1);
    assert(ops.vacant_calls == (fault == 1 ? 0u : 1u));
    assert(ops.creates == (fault <= 2 ? 0u : 1u));
    assert(ops.observations == (fault <= 3 ? 0u : 1u));
    assert(ops.closes == (fault <= 3 ? 0u : 1u));
  }
  Fake first;
  const auto created = CreateFresh(first);
  assert(created.handle == 71 && first.closes == 0 && Matches(created.authority, created.authority));
  auto changed = created.authority;
  changed.index++;
  assert(!Matches(changed, created.authority));
  changed = created.authority; changed.luid++;
  assert(!Matches(changed, created.authority));
  changed = created.authority; changed.identity.guid[0] ^= 1;
  assert(!Matches(changed, created.authority));
  changed = created.authority; changed.identity.name[0] = L'X';
  assert(!Matches(changed, created.authority));
  assert(!Matches(created.authority, {}));
  // No global identity/authority slot shared across concurrent creation attempts.
  std::array<Created<unsigned>, 16> results{};
  std::vector<std::thread> workers;
  for (unsigned i = 0; i < results.size(); ++i) workers.emplace_back([i, &results] {
    Fake ops; ops.seed = static_cast<uint8_t>(i + 1); results[i] = CreateFresh(ops);
  });
  for (auto& worker : workers) worker.join();
  for (size_t i = 0; i < results.size(); ++i) {
    assert(results[i].handle && results[i].authority.identity.name.back() == 0);
    for (size_t p = 40; p < kAliasCharacters; ++p) assert(results[i].authority.identity.name[p] == L'x');
    for (size_t j = i + 1; j < results.size(); ++j) {
      assert(results[i].authority.identity.name != results[j].authority.identity.name);
      assert(results[i].authority.identity.guid != results[j].authority.identity.guid);
    }
  }
}
