#pragma once
#include "socket_io.h"
#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif
#ifndef SCHANNEL_USE_BLACKLISTS
#define SCHANNEL_USE_BLACKLISTS
#endif
#include <winternl.h>
#include <security.h>
#include <schannel.h>
#include <wincrypt.h>
#include <array>
#include <string>
#include <string_view>
#include <vector>

namespace liwetun::health {
enum class TlsResult : uint32_t {
  Ok, Cancelled, Deadline, TransportClosed, TransportFailed, Limit,
  CredentialsUnavailable, NameRejected, ChainRejected, TimeRejected,
  RevocationRejected, ClientAuthRejected, TlsRejected, ProtocolRejected,
  PeerShutdown, RenegotiationRejected
};
// Internal candidate, no exported service API. Fresh credentials/context per
// attempt; automatic chain/name validation, no implicit client certificate.
// Initial qualification deliberately limits this candidate to TLS 1.2.
class SchannelProbe {
 public:
  explicit SchannelProbe(SocketIo& io) : io_(io) {
    SecInvalidateHandle(&credential_); SecInvalidateHandle(&context_);
  }
  SchannelProbe(const SchannelProbe&) = delete;
  SchannelProbe& operator=(const SchannelProbe&) = delete;
  ~SchannelProbe() {
    if (SecIsValidHandle(&context_)) DeleteSecurityContext(&context_);
    if (SecIsValidHandle(&credential_)) FreeCredentialsHandle(&credential_);
  }
  TlsResult Handshake(std::wstring_view peer) {
    if (started_ || !ValidName(peer)) return TlsResult::CredentialsUnavailable;
    started_ = true;
    if (const auto state = io_.Control(); state != IoState::Ok) return FromIo(state);
    peer_.assign(peer);
    parameters_.grbitDisabledProtocols = static_cast<DWORD>(~SP_PROT_TLS1_2_CLIENT);
    credentials_.dwVersion = SCH_CREDENTIALS_VERSION;
    credentials_.dwFlags = SCH_CRED_AUTO_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS | SCH_USE_STRONG_CRYPTO |
        SCH_CRED_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | SCH_CRED_REVOCATION_CHECK_CACHE_ONLY |
        SCH_CRED_CACHE_ONLY_URL_RETRIEVAL | SCH_CRED_CACHE_ONLY_URL_RETRIEVAL_ON_CREATE;
    credentials_.cTlsParameters = 1; credentials_.pTlsParameters = &parameters_;
    wchar_t package[] = UNISP_NAME_W;
    TimeStamp expiry{};
    if (AcquireCredentialsHandleW(nullptr, package, SECPKG_CRED_OUTBOUND, nullptr,
          &credentials_, nullptr, nullptr, &credential_, &expiry) != SEC_E_OK) return TlsResult::CredentialsUnavailable;
    constexpr ULONG requested = ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_INTEGRITY |
        ISC_REQ_STREAM | ISC_REQ_USE_SUPPLIED_CREDS | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT;
    bool first = true;
    for (unsigned call = 0; call < 128; ++call) {
      if (const auto state = io_.Control(); state != IoState::Ok) return FromIo(state);
      SecBuffer input[2]{{static_cast<ULONG>(encrypted_.size()), SECBUFFER_TOKEN, encrypted_.data()}, {0, SECBUFFER_EMPTY, nullptr}};
      SecBufferDesc incoming{SECBUFFER_VERSION, 2, input};
      Output output;
      ULONG attributes = 0;
      const auto status = InitializeSecurityContextW(&credential_, first ? nullptr : &context_, peer_.data(),
          requested, 0, 0, first ? nullptr : &incoming, 0, &context_, &output.description, &attributes, &expiry);
      if (status == SEC_E_INCOMPLETE_MESSAGE) {
        if (first) return TlsResult::TlsRejected;
        if (const auto result = ReadEncrypted(); result != TlsResult::Ok) return result;
        continue;
      }
      if (status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED) return FromSecurity(status);
      if (output.buffer.cbBuffer > kCipherLimit || (output.buffer.cbBuffer && !output.buffer.pvBuffer)) return TlsResult::Limit;
      if (const auto state = io_.Send({static_cast<const char*>(output.buffer.pvBuffer), output.buffer.cbBuffer});
          state != IoState::Ok) return FromIo(state);
      const size_t extra = first ? 0 : (input[1].BufferType == SECBUFFER_EXTRA ? input[1].cbBuffer : 0);
      if (!KeepExtra(extra)) return TlsResult::TlsRejected;
      first = false;
      if (status == SEC_E_OK) {
        if ((attributes & (ISC_RET_CONFIDENTIALITY | ISC_RET_STREAM)) != (ISC_RET_CONFIDENTIALITY | ISC_RET_STREAM)) return TlsResult::TlsRejected;
        SecPkgContext_ConnectionInfo info{};
        if (QueryContextAttributesW(&context_, SECPKG_ATTR_CONNECTION_INFO, &info) != SEC_E_OK ||
            info.dwProtocol != SP_PROT_TLS1_2_CLIENT || info.dwCipherStrength < 128) return TlsResult::ProtocolRejected;
        PCCERT_CONTEXT certificate = nullptr;
        if (QueryContextAttributesW(&context_, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &certificate) != SEC_E_OK || !certificate) return TlsResult::ChainRejected;
        const auto certificate_result = ValidateCertificate(certificate);
        CertFreeCertificateContext(certificate);
        if (certificate_result != TlsResult::Ok) return certificate_result;
        if (QueryContextAttributesW(&context_, SECPKG_ATTR_STREAM_SIZES, &sizes_) != SEC_E_OK ||
            !sizes_.cbMaximumMessage || sizes_.cbMaximumMessage > kCipherLimit ||
            sizes_.cbHeader > kCipherLimit || sizes_.cbTrailer > kCipherLimit) return TlsResult::Limit;
        if (const auto state = io_.Control(); state != IoState::Ok) return FromIo(state);
        ready_ = true; return TlsResult::Ok;
      }
      if (encrypted_.empty()) {
        if (const auto result = ReadEncrypted(); result != TlsResult::Ok) return result;
      }
    }
    return TlsResult::Limit;
  }
  TlsResult Send(std::span<const char> plain) {
    if (!ready_) return TlsResult::TlsRejected;
    if (plain.empty() || plain.size() > sizes_.cbMaximumMessage ||
        plain.size() + sizes_.cbHeader + sizes_.cbTrailer > kCipherLimit) return Fail(TlsResult::Limit);
    if (const auto state = io_.Control(); state != IoState::Ok) return Fail(FromIo(state));
    std::vector<char> record(plain.size() + sizes_.cbHeader + sizes_.cbTrailer);
    std::copy(plain.begin(), plain.end(), record.begin() + sizes_.cbHeader);
    SecBuffer buffers[4]{{sizes_.cbHeader, SECBUFFER_STREAM_HEADER, record.data()},
        {static_cast<ULONG>(plain.size()), SECBUFFER_DATA, record.data() + sizes_.cbHeader},
        {sizes_.cbTrailer, SECBUFFER_STREAM_TRAILER, record.data() + sizes_.cbHeader + plain.size()},
        {0, SECBUFFER_EMPTY, nullptr}};
    SecBufferDesc message{SECBUFFER_VERSION, 4, buffers};
    const auto status = EncryptMessage(&context_, 0, &message, 0);
    if (status != SEC_E_OK) return Fail(FromSecurity(status));
    for (unsigned i = 0; i < 3; ++i) {
      if (!Inside(record, buffers[i])) return Fail(TlsResult::TlsRejected);
      if (const auto state = io_.Send({static_cast<const char*>(buffers[i].pvBuffer), buffers[i].cbBuffer});
          state != IoState::Ok) return Fail(FromIo(state));
    }
    return TlsResult::Ok;
  }
  TlsResult Receive(std::vector<char>& plain) {
    plain.clear();
    if (!ready_) return TlsResult::TlsRejected;
    bool delivered = false;
    struct ClearFailure {
      std::vector<char>& data;
      bool& delivered;
      ~ClearFailure() { if (!delivered) data.clear(); }
    } clear_failure{plain, delivered};
    for (unsigned call = 0; call < 128; ++call) {
      if (const auto state = io_.Control(); state != IoState::Ok) return Fail(FromIo(state));
      if (encrypted_.empty()) {
        if (const auto result = ReadEncrypted(); result != TlsResult::Ok) return Fail(result);
      }
      SecBuffer buffers[4]{{static_cast<ULONG>(encrypted_.size()), SECBUFFER_DATA, encrypted_.data()},
          {0, SECBUFFER_EMPTY, nullptr}, {0, SECBUFFER_EMPTY, nullptr}, {0, SECBUFFER_EMPTY, nullptr}};
      SecBufferDesc message{SECBUFFER_VERSION, 4, buffers};
      const auto status = DecryptMessage(&context_, &message, 0, nullptr);
      if (status == SEC_E_INCOMPLETE_MESSAGE) {
        if (const auto result = ReadEncrypted(); result != TlsResult::Ok) return Fail(result);
        continue;
      }
      if (status == SEC_I_CONTEXT_EXPIRED) { ready_ = false; return TlsResult::PeerShutdown; }
      if (status == SEC_I_RENEGOTIATE) { ready_ = false; return TlsResult::RenegotiationRejected; }
      if (status != SEC_E_OK) { ready_ = false; return FromSecurity(status); }
      size_t extra = 0;
      for (const auto& buffer : buffers) {
        if (buffer.BufferType == SECBUFFER_DATA) {
          if (!Inside(encrypted_, buffer) || buffer.cbBuffer > kCipherLimit - plain.size()) return Fail(TlsResult::Limit);
          const auto* data = static_cast<const char*>(buffer.pvBuffer);
          if (buffer.cbBuffer) plain.insert(plain.end(), data, data + buffer.cbBuffer);
        } else if (buffer.BufferType == SECBUFFER_EXTRA) {
          if (extra) return Fail(TlsResult::TlsRejected);
          extra = buffer.cbBuffer;
        }
      }
      if (plain.empty() && extra == encrypted_.size()) return Fail(TlsResult::TlsRejected);
      if (!KeepExtra(extra)) return Fail(TlsResult::TlsRejected);
      if (!plain.empty()) {
        if (const auto state = io_.Control(); state != IoState::Ok) { plain.clear(); return Fail(FromIo(state)); }
        delivered = true; return TlsResult::Ok;
      }
    }
    return Fail(TlsResult::Limit);
  }
 private:
  static TlsResult ValidateCertificate(PCCERT_CONTEXT certificate) {
    if (!certificate->pCertInfo || CertVerifyTimeValidity(nullptr, certificate->pCertInfo) != 0)
      return TlsResult::TimeRejected;
    // Schannel's automatic validation remains enabled. Independently require a
    // complete zero-error chain: the Schannel flags alone did not reject a
    // non-root fixture leaf without revocation information on Server 2022.
    CERT_CHAIN_PARA parameters{};
    parameters.cbSize = sizeof(parameters);
    char usage[] = szOID_PKIX_KP_SERVER_AUTH;
    char* usages[] = {usage};
    parameters.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
    parameters.RequestedUsage.Usage.cUsageIdentifier = 1;
    parameters.RequestedUsage.Usage.rgpszUsageIdentifier = usages;
    constexpr DWORD flags = CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL | CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE |
        CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY;
    PCCERT_CHAIN_CONTEXT chain = nullptr;
    if (!CertGetCertificateChain(HCCE_LOCAL_MACHINE, certificate, nullptr, certificate->hCertStore,
          &parameters, flags, nullptr, &chain) || !chain) return TlsResult::ChainRejected;
    const DWORD errors = chain->TrustStatus.dwErrorStatus;
    CertFreeCertificateChain(chain);
    if (errors & (CERT_TRUST_IS_REVOKED | CERT_TRUST_REVOCATION_STATUS_UNKNOWN | CERT_TRUST_IS_OFFLINE_REVOCATION))
      return TlsResult::RevocationRejected;
    if (errors & CERT_TRUST_IS_NOT_TIME_VALID) return TlsResult::TimeRejected;
    return errors ? TlsResult::ChainRejected : TlsResult::Ok;
  }
  TlsResult Fail(TlsResult result) { ready_ = false; return result; }
  static constexpr size_t kCipherLimit = 65536;
  struct Output {
    SecBuffer buffer{0, SECBUFFER_TOKEN, nullptr};
    SecBufferDesc description{SECBUFFER_VERSION, 1, &buffer};
    ~Output() { if (buffer.pvBuffer) FreeContextBuffer(buffer.pvBuffer); }
  };
  static bool ValidName(std::wstring_view peer) {
    if (peer.empty() || peer.size() > 253) return false;
    size_t label = 0;
    wchar_t last = 0;
    for (wchar_t c : peer) {
      if (c == L'.') {
        if (!label || last == L'-') return false;
        label = 0;
      } else {
        if (!((c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') || (c >= L'0' && c <= L'9') || c == L'-') ||
            (!label && c == L'-') || ++label > 63) return false;
      }
      last = c;
    }
    return label > 0 && last != L'-';
  }
  static bool Inside(const std::vector<char>& bytes, const SecBuffer& buffer) {
    if (!buffer.cbBuffer) return true;
    const auto start = reinterpret_cast<uintptr_t>(bytes.data()), pointer = reinterpret_cast<uintptr_t>(buffer.pvBuffer);
    return pointer >= start && pointer - start <= bytes.size() && buffer.cbBuffer <= bytes.size() - (pointer - start);
  }
  bool KeepExtra(size_t count) {
    if (count > encrypted_.size()) return false;
    encrypted_.erase(encrypted_.begin(), encrypted_.end() - static_cast<ptrdiff_t>(count));
    return true;
  }
  TlsResult ReadEncrypted() {
    if (encrypted_.size() == kCipherLimit) return TlsResult::Limit;
    std::array<char, 16384> incoming{};
    size_t count = 0;
    const auto status = io_.Receive(std::span(incoming).first(std::min(incoming.size(), kCipherLimit - encrypted_.size())), count);
    if (status != IoState::Ok) return FromIo(status);
    encrypted_.insert(encrypted_.end(), incoming.begin(), incoming.begin() + static_cast<ptrdiff_t>(count));
    return TlsResult::Ok;
  }
  static TlsResult FromIo(IoState state) {
    switch (state) {
      case IoState::Ok: return TlsResult::Ok;
      case IoState::Cancelled: return TlsResult::Cancelled;
      case IoState::Deadline: return TlsResult::Deadline;
      case IoState::Closed: return TlsResult::TransportClosed;
      case IoState::Failed: return TlsResult::TransportFailed;
      case IoState::Limit: return TlsResult::Limit;
    }
    return TlsResult::TransportFailed;
  }
  static TlsResult FromSecurity(SECURITY_STATUS status) {
    switch (status) {
      case SEC_E_WRONG_PRINCIPAL: return TlsResult::NameRejected;
      case SEC_E_UNTRUSTED_ROOT: return TlsResult::ChainRejected;
      case SEC_E_CERT_EXPIRED: return TlsResult::TimeRejected;
      case CRYPT_E_REVOCATION_OFFLINE:
      case CRYPT_E_NO_REVOCATION_CHECK:
      case CERT_E_REVOKED: return TlsResult::RevocationRejected;
      case SEC_I_INCOMPLETE_CREDENTIALS: return TlsResult::ClientAuthRejected;
      default: return TlsResult::TlsRejected;
    }
  }
  SocketIo& io_;
  CredHandle credential_{};
  CtxtHandle context_{};
  TLS_PARAMETERS parameters_{};
  SCH_CREDENTIALS credentials_{};
  SecPkgContext_StreamSizes sizes_{};
  std::wstring peer_;
  std::vector<char> encrypted_;
  bool ready_ = false;
  bool started_ = false;
};
} // namespace liwetun::health
