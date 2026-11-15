#pragma once
#include "security.h"
namespace liwetun {
bool PipeIo(HANDLE pipe, HANDLE stop, void* buffer, DWORD length, bool write);
}
