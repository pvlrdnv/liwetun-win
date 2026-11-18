// Disposable original-Wintun lifecycle reproduction; not a safety qualification.
#include "adapter_problem_fixture.h"

int wmain(int argc, wchar_t** argv) {
  unsigned stage = 0;
  try {
    Check(Disposable() && argc == 2);
    Library library{LoadLibraryExW(argv[1], nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32)};
    Check(library.value != nullptr);
    const auto create = Symbol<Create>(library.value, "WintunCreateAdapter");
    const auto close = Symbol<Close>(library.value, "WintunCloseAdapter");
    const auto luid = Symbol<Luid>(library.value, "WintunGetAdapterLUID");
    Ops os(create, close, luid, L"LiWeTun.CI.ProblemDevice");
    stage = 1;
    // The only device disabled by this executable is this returned creation
    // handle, after exact actual identity verification. No host selector input.
    const auto made = liwetun::adapter::CreateFresh(os);
    Adapter foreign{made.handle, close}; Check(foreign.value != nullptr);
    GUID guid{}; std::memcpy(&guid, made.authority.identity.guid.data(), sizeof(guid));
    Device device; device.Locate(guid);
    Sleep(2000); // allow the initial creation's asynchronous cleanup to settle
    stage = 2;
    device.disabled_by_fixture = true;
    device.Change(DICS_DISABLE);
    const auto disabled = device.Read();
    Check(disabled.present && (disabled.status & DN_HAS_PROBLEM) && disabled.problem == CM_PROB_DISABLED);
    stage = 3;
    const auto next = liwetun::adapter::CreateFresh(os);
    Adapter candidate{next.handle, close}; Check(candidate.value != nullptr);
    bool removed_after_create = false;
    for (unsigned i = 0; i < 60; ++i) {
      if (!device.Read().present) { removed_after_create = true; break; }
      Sleep(50);
    }
    stage = 4;
    candidate.Release();
    bool removed_after_candidate_close = false;
    for (unsigned i = 0; i < 60; ++i) {
      if (!device.Read().present) { removed_after_candidate_close = true; break; }
      Sleep(50);
    }
    stage = 5;
    if (device.Read().present) {
      // Only re-enable the exact node this fixture disabled, if it survives.
      device.Change(DICS_ENABLE);
      device.disabled_by_fixture = false;
    } else {
      device.disabled_by_fixture = false;
    }
    const bool removed = removed_after_create || removed_after_candidate_close;
    // Release only our retained creator handle, even if the node was removed
    // by the candidate's global cleanup. Never repair/recreate a foreign node.
    foreign.Release();
    std::printf("{\"experiment_completed\":true,\"fixture_created_and_retained_device\":true,\"fixture_disabled_own_exact_node\":true,\"problem_disabled_observed\":true,\"candidate_created\":true,\"foreign_removed_after_candidate_create\":%s,\"foreign_removed_after_candidate_close\":%s,\"foreign_removed_before_creator_close\":%s,\"foreign_preservation_passed\":%s,\"factory_only\":true,\"sdk_started\":false,\"identifiers_exported\":false,\"adapter_ownership_qualified\":false,\"release_ready\":false}\n",
      removed_after_create ? "true" : "false", removed_after_candidate_close ? "true" : "false",
      removed ? "true" : "false", removed ? "false" : "true");
    return 0;
  } catch (...) {
    std::printf("{\"experiment_completed\":false,\"stage\":%u,\"identifiers_exported\":false,\"adapter_ownership_qualified\":false,\"release_ready\":false}\n", stage);
    return 2;
  }
}
