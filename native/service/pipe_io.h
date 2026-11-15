#pragma once
#include "security.h"
namespace liwetun {
Handle OpenControlPipe();
bool PipeIo(HANDLE pipe, HANDLE stop, void* buffer, DWORD length, bool write);
}
