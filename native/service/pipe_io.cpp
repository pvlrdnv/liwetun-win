#include "pipe_io.h"
namespace liwetun {
bool PipeIo(HANDLE pipe, HANDLE stop, void* buffer, DWORD length, bool write) {
  DWORD offset = 0;
  while (offset < length) {
    Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!event) return false;
    OVERLAPPED overlapped{};
    overlapped.hEvent = event.get();
    DWORD done = 0;
    auto* position = static_cast<unsigned char*>(buffer) + offset;
    const BOOL immediate = write ? WriteFile(pipe, position, length - offset, &done, &overlapped)
                                 : ReadFile(pipe, position, length - offset, &done, &overlapped);
    if (!immediate) {
      if (GetLastError() != ERROR_IO_PENDING) return false;
      HANDLE waits[]{event.get(), stop};
      const DWORD wait = WaitForMultipleObjects(stop ? 2 : 1, waits, FALSE, 5000);
      if (wait != WAIT_OBJECT_0) {
        CancelIoEx(pipe, &overlapped);
        // Keep OVERLAPPED/event alive until the cancelled operation completes.
        GetOverlappedResult(pipe, &overlapped, &done, TRUE);
        return false;
      }
      if (!GetOverlappedResult(pipe, &overlapped, &done, FALSE)) return false;
    }
    if (done == 0) return false;
    offset += done;
  }
  return true;
}
}
