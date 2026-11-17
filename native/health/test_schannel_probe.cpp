#include "schannel_probe.h"
#include <cstdlib>

using namespace liwetun::health;
void Require(bool value) { if (!value) std::abort(); }
int main() {
  std::atomic<bool> cancel{true};
  SocketIo cancelled(INVALID_SOCKET, GetTickCount64() + 5000, cancel);
  SchannelProbe channel(cancelled);
  Require(channel.Handshake(L"health.liwetun.invalid") == TlsResult::Cancelled);
  Require(channel.Handshake(L"health.liwetun.invalid") == TlsResult::CredentialsUnavailable);
  Require(channel.Send(std::span("payload", 7)) == TlsResult::TlsRejected);
  std::vector<char> plain;
  Require(channel.Receive(plain) == TlsResult::TlsRejected && plain.empty());
  cancel = false;
  SocketIo expired(INVALID_SOCKET, GetTickCount64(), cancel);
  SchannelProbe late(expired);
  Require(late.Handshake(L"health.liwetun.invalid") == TlsResult::Deadline);
  SocketIo unavailable(INVALID_SOCKET, GetTickCount64() + 5000, cancel);
  for (const auto* host : {L"", L".invalid", L"-bad.invalid", L"bad-.invalid", L"bad..invalid", L"x\r\nHost: bad.invalid"}) {
    SchannelProbe invalid(unavailable);
    Require(invalid.Handshake(host) == TlsResult::CredentialsUnavailable);
  }
}
