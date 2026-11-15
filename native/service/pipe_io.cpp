#include "pipe_io.h"
#include "protocol.h"
namespace liwetun {
Handle OpenControlPipe() {
  // Wait only for transport availability; never resend a request whose outcome
  // is unknown. The server may still be disconnecting the previous client.
  for (unsigned attempt = 0; attempt < 8; ++attempt) {
    HANDLE pipe = CreateFileW(kPipeName, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
        OPEN_EXISTING, FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
    if (pipe != INVALID_HANDLE_VALUE) return Handle(pipe);
    if (GetLastError() != ERROR_PIPE_BUSY) return {};
    WaitNamedPipeW(kPipeName, 250);
  }
  return {};
}
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
