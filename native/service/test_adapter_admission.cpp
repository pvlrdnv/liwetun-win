#include "adapter_admission.h"
#include <cstdlib>

// Disposable clean CI host: read-only OS binding/preflight, no adapter created.
int main() {
  if (!liwetun::ReservedAdapterNamesAbsent()) std::abort();
}
