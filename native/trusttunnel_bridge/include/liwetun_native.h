#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  uint32_t abi_version;
  uint32_t transport;
  uint32_t custom_certificate;
  uint32_t has_ipv6;
} LiwetunTtInfo;

// 0 accepted, 1 malformed, 2 TLS bypass, 3 unsupported, 4 internal.
// Never returns profile data, decoded config or arbitrary errors.
int32_t liwetun_tt_inspect(const uint8_t* input, size_t length, LiwetunTtInfo* output);

#ifdef __cplusplus
}
static_assert(sizeof(LiwetunTtInfo) == 16, "Unexpected native ABI layout");
#endif
