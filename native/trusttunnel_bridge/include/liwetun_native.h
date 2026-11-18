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

// UI-only private metadata, never diagnostic/report data. NUL-terminated UTF-8.
typedef struct {
  uint32_t abi_version;
  uint8_t name[1024];
  uint8_t hostname[2048];
  uint8_t addresses[8192];
} LiwetunTtPresentation;
int32_t liwetun_tt_presentation(const uint8_t* input, size_t length,
                               LiwetunTtPresentation* output);

#ifdef __cplusplus
}
static_assert(sizeof(LiwetunTtPresentation) == 11268, "Unexpected presentation ABI layout");
static_assert(sizeof(LiwetunTtInfo) == 16, "Unexpected native ABI layout");
#endif
