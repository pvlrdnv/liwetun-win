#pragma once
#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace liwetun::health {
// Candidate protocol only. This reserved host is not a production endpoint.
inline constexpr std::string_view kFixtureHealthHost = "health.liwetun.invalid";
using Nonce = std::array<char, 8>;
enum class HttpResult : uint32_t {
  NeedMore, Verified, WrongNonce, Redirect, EndpointStatus, Malformed, Limit, Truncated
};
inline bool NonzeroNonce(const Nonce& nonce) {
  for (auto byte : nonce) if (byte != 0) return true;
  return false;
}
inline std::optional<std::string> FixtureHealthRequest(const Nonce& nonce) {
  if (!NonzeroNonce(nonce)) return std::nullopt;
  std::string request = "POST /liwetun/health/v1 HTTP/1.1\r\nHost: ";
  request += kFixtureHealthHost;
  request += "\r\nContent-Type: application/octet-stream\r\nContent-Length: 8\r\n"
      "Cache-Control: no-store\r\nConnection: close\r\n\r\n";
  request.append(nonce.data(), nonce.size());
  return request;
}

// No server strings/body/headers leave this bounded parser. A caller can only
// observe a closed result, and must independently require TLS/path/epoch proof.
class HttpProbeParser {
 public:
  static constexpr size_t kHeaderLimit = 4096;
  explicit HttpProbeParser(const Nonce& nonce) : expected_(nonce) {
    if (!NonzeroNonce(nonce)) result_ = HttpResult::Malformed;
  }
  HttpResult Result() const { return result_; }
  HttpResult Finish() {
    if (result_ == HttpResult::NeedMore) result_ = HttpResult::Truncated;
    return result_;
  }
  HttpResult Feed(std::span<const char> bytes) {
    if (result_ != HttpResult::NeedMore) {
      if (result_ == HttpResult::Verified && !bytes.empty()) result_ = HttpResult::Limit;
      return result_;
    }
    for (char byte : bytes) {
      if (!headers_done_) {
        const auto n = static_cast<unsigned char>(byte);
        if (n > 126 || (n < 32 && byte != '\r' && byte != '\n' && byte != '\t')) return Fail(HttpResult::Malformed);
        if (headers_.size() == kHeaderLimit) return Fail(HttpResult::Limit);
        headers_ += byte;
        if (headers_.ends_with("\r\n\r\n")) {
          if (!ParseHeaders()) return result_;
          headers_done_ = true;
        }
      } else {
        if (body_size_ == body_.size()) return Fail(HttpResult::Limit);
        body_[body_size_++] = byte;
      }
    }
    if (headers_done_ && body_size_ == body_.size()) {
      uint32_t difference = 0;
      for (size_t i = 0; i < body_.size(); ++i) {
        difference |= static_cast<unsigned char>(body_[i]) ^ static_cast<unsigned char>(expected_[i]);
      }
      result_ = difference ? HttpResult::WrongNonce : HttpResult::Verified;
    }
    return result_;
  }
 private:
  HttpResult Fail(HttpResult value) { result_ = value; return value; }
  static char Lower(char c) { return c >= 'A' && c <= 'Z' ? static_cast<char>(c + ('a' - 'A')) : c; }
  static bool EqualAscii(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) if (Lower(a[i]) != b[i]) return false;
    return true;
  }
  static bool HeaderName(std::string_view value) {
    constexpr std::string_view punctuation = "!#$%&'*+-.^_`|~";
    if (value.empty() || value.size() > 80) return false;
    for (char c : value) {
      const char lower = Lower(c);
      if (!((lower >= 'a' && lower <= 'z') || (lower >= '0' && lower <= '9') || punctuation.find(c) != std::string_view::npos)) return false;
    }
    return true;
  }
  bool ParseHeaders() {
    const std::string_view all(headers_);
    const auto first_end = all.find("\r\n");
    if (first_end == std::string_view::npos) { Fail(HttpResult::Malformed); return false; }
    const auto status = all.substr(0, first_end);
    if (status.size() < 12 || !status.starts_with("HTTP/1.1 ") ||
        (status.size() > 12 && status[12] != ' ')) { Fail(HttpResult::Malformed); return false; }
    for (char c : status) if (c < 32 || c > 126) { Fail(HttpResult::Malformed); return false; }
    for (size_t i = 9; i < 12; ++i) if (status[i] < '0' || status[i] > '9') { Fail(HttpResult::Malformed); return false; }
    const auto code = status.substr(9, 3);
    if (code != "200") { Fail(code[0] == '3' ? HttpResult::Redirect : HttpResult::EndpointStatus); return false; }
    bool length = false, type = false, cache = false, close = false;
    size_t position = first_end + 2, fields = 0;
    while (position < all.size() - 2) {
      const auto end = all.find("\r\n", position);
      if (end == std::string_view::npos || ++fields > 24) { Fail(HttpResult::Limit); return false; }
      const auto line = all.substr(position, end - position);
      if (line.empty() || line.front() == ' ' || line.front() == '\t') { Fail(HttpResult::Malformed); return false; }
      for (char c : line) if (c < 32 && c != '\t') { Fail(HttpResult::Malformed); return false; }
      const auto colon = line.find(':');
      if (colon == std::string_view::npos || !HeaderName(line.substr(0, colon))) { Fail(HttpResult::Malformed); return false; }
      const auto name = line.substr(0, colon);
      auto value = line.substr(colon + 1);
      while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.remove_prefix(1);
      while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) value.remove_suffix(1);
      if (EqualAscii(name, "content-length")) {
        if (length || value != "8") { Fail(HttpResult::Malformed); return false; }
        length = true;
      } else if (EqualAscii(name, "content-type")) {
        if (type || !EqualAscii(value, "application/octet-stream")) { Fail(HttpResult::Malformed); return false; }
        type = true;
      } else if (EqualAscii(name, "cache-control")) {
        if (cache || !EqualAscii(value, "no-store")) { Fail(HttpResult::Malformed); return false; }
        cache = true;
      } else if (EqualAscii(name, "connection")) {
        if (close || !EqualAscii(value, "close")) { Fail(HttpResult::Malformed); return false; }
        close = true;
      } else if (EqualAscii(name, "location")) {
        Fail(HttpResult::Redirect); return false;
      } else if (EqualAscii(name, "transfer-encoding") || EqualAscii(name, "content-encoding") || EqualAscii(name, "set-cookie")) {
        Fail(HttpResult::Malformed); return false;
      }
      position = end + 2;
    }
    if (!length || !type || !cache || !close || position != all.size() - 2) { Fail(HttpResult::Malformed); return false; }
    return true;
  }
  Nonce expected_, body_{};
  size_t body_size_ = 0;
  std::string headers_;
  bool headers_done_ = false;
  HttpResult result_ = HttpResult::NeedMore;
};
} // namespace liwetun::health
