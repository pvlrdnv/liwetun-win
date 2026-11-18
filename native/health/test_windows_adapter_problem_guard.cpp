// Disposable read-only startup-refusal control, never linked into the product.
#include "adapter_problem_fixture.h"
#include "../service/adapter_admission.h"

int wmain(int argc, wchar_t** argv) {
  unsigned stage = 0;
  try {
    Check(Disposable() && argc == 2 && liwetun::ReservedAdapterNamesAbsent());
    Library library{LoadLibraryExW(argv[1], nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32)};
    Check(library.value != nullptr);
    const auto create = Symbol<Create>(library.value, "WintunCreateAdapter");
    const auto close = Symbol<Close>(library.value, "WintunCloseAdapter");
    const auto luid = Symbol<Luid>(library.value, "WintunGetAdapterLUID");
    Ops os(create, close, luid, L"LiWeTun.CI.ProblemGuard");
    const auto made = liwetun::adapter::CreateFresh(os);
    Adapter foreign{made.handle, close}; Check(foreign.value != nullptr);
    GUID guid{}; std::memcpy(&guid, made.authority.identity.guid.data(), sizeof(guid));
    Device device; device.Locate(guid);
    Sleep(2000);
    stage = 1;
    Check(liwetun::ReservedAdapterNamesAbsent()); // unrelated healthy fixture allowed
    device.disabled_by_fixture = true;
    device.Change(DICS_DISABLE);
    const auto disabled = device.Read();
    Check(disabled.present && (disabled.status & DN_HAS_PROBLEM) && disabled.problem == CM_PROB_DISABLED);
    stage = 2;
    unsigned candidate_calls = 0;
    Check(!liwetun::ReservedAdapterNamesAbsent());
    // This is the same refusal predicate invoked at Start and before SDK init.
    // Exercise the gated path, not a manually fabricated refusal result.
    if (liwetun::ReservedAdapterNamesAbsent()) {
      ++candidate_calls;
      const auto next = liwetun::adapter::CreateFresh(os);
      Adapter candidate{next.handle, close};
    }
    Check(candidate_calls == 0);
    for (unsigned i = 0; i < 60; ++i) {
      const auto state = device.Read();
      Check(state.present && state.status == disabled.status && state.problem == disabled.problem);
      Sleep(50);
    }
    stage = 3;
    device.Change(DICS_ENABLE);
    for (unsigned i = 0; i < 60; ++i) {
      const auto state = device.Read();
      if (state.present && !(state.status & DN_HAS_PROBLEM)) break;
      Sleep(50);
    }
    const auto restored = device.Read();
    Check(restored.present && !(restored.status & DN_HAS_PROBLEM));
    device.disabled_by_fixture = false;
    Check(liwetun::ReservedAdapterNamesAbsent());
    foreign.Release();
    std::printf("{\"experiment_completed\":true,\"healthy_foreign_node_accepted\":true,\"problem_disabled_observed\":true,\"problem_node_start_refused\":true,\"candidate_create_calls\":0,\"retained_disabled_node_unchanged\":true,\"creator_restored_own_node\":true,\"healthy_node_accepted_again\":true,\"preflight_only\":true,\"sdk_started\":false,\"later_problem_state_race_qualified\":false,\"identifiers_exported\":false,\"adapter_ownership_qualified\":false,\"release_ready\":false}\n");
    return 0;
  } catch (...) {
    std::printf("{\"experiment_completed\":false,\"stage\":%u,\"preflight_only\":true,\"identifiers_exported\":false,\"adapter_ownership_qualified\":false,\"release_ready\":false}\n", stage);
    return 2;
  }
}
