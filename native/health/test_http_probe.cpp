#include "http_probe.h"
#include <cstdlib>
#include <string>
#include <vector>

using namespace liwetun::health;
void Require(bool value) { if (!value) std::abort(); }
constexpr Nonce kNonce{'a', '\0', 'b', '\r', '\n', 'c', '\xff', 'd'};
const std::string kHeaders = "HTTP/1.1 200 OK\r\nContent-Length: 8\r\nContent-Type: application/octet-stream\r\n"
    "Cache-Control: no-store\r\nConnection: close\r\n\r\n";
std::string Response(std::string header = kHeaders) { return header + std::string(kNonce.data(), kNonce.size()); }
HttpResult Parse(const std::string& packet) { HttpProbeParser p(kNonce); return p.Feed(packet); }
std::string Replace(std::string data, const std::string& from, const std::string& to) {
  const auto index = data.find(from); Require(index != std::string::npos); data.replace(index, from.size(), to); return data;
}
int main() {
  const auto response = Response();
  for (size_t split = 0; split <= response.size(); ++split) {
    HttpProbeParser parser(kNonce);
    parser.Feed(std::span(response.data(), split));
    Require(parser.Feed(std::span(response.data() + split, response.size() - split)) == HttpResult::Verified);
  }
  HttpProbeParser fragmented(kNonce);
  for (char c : response) fragmented.Feed(std::span(&c, 1));
  Require(fragmented.Finish() == HttpResult::Verified);
  Require(fragmented.Feed(std::span("X", 1)) == HttpResult::Limit);
  for (size_t length = 0; length < response.size(); ++length) {
    HttpProbeParser parser(kNonce); parser.Feed(std::span(response.data(), length));
    Require(parser.Finish() == HttpResult::Truncated);
  }
  const std::vector<std::pair<std::string, std::string>> malformed{
    {"HTTP/1.1", "HTTP/1.0"}, {"Content-Length: 8", "Content-Length: +8"},
    {"Content-Length: 8", "Content-Length: 08"}, {"Content-Length: 8", "Content-Length: 0"},
    {"Content-Length: 8", "Content-Length: 9"}, {"Content-Length: 8", "Content-Length: 8\r\ncontent-length: 8"},
    {"Content-Length: 8", "Content-Length : 8"}, {"Content-Length: 8", "\tContent-Length: 8"},
    {"Content-Length: 8", "Content-Length: 8\nInjected: yes"},
    {"Content-Type: application/octet-stream", "Content-Type: text/plain"},
    {"Cache-Control: no-store", "Cache-Control: public"}, {"Connection: close", "Connection: keep-alive"},
    {"Content-Length: 8", "Transfer-Encoding: chunked\r\nContent-Length: 8"},
    {"Content-Length: 8", "Content-Encoding: gzip\r\nContent-Length: 8"},
    {"Content-Length: 8", "Set-Cookie: synthetic=value\r\nContent-Length: 8"},
    {"Cache-Control: no-store\r\n", ""}, {"Connection: close\r\n", ""},
  };
  for (const auto& [before, after] : malformed) Require(Parse(Response(Replace(kHeaders, before, after))) == HttpResult::Malformed);
  Require(Parse(Response(Replace(kHeaders, "200 OK", "302 Found"))) == HttpResult::Redirect);
  Require(Parse(Response(Replace(kHeaders, "200 OK", "503 Unavailable"))) == HttpResult::EndpointStatus);
  Require(Parse(Response(Replace(kHeaders, "Content-Length: 8", "Location: https://invalid.example/\r\nContent-Length: 8"))) == HttpResult::Redirect);
  Require(Parse(kHeaders + std::string(8, '\0')) == HttpResult::WrongNonce);
  HttpProbeParser sticky(kNonce);
  Require(sticky.Feed(kHeaders + std::string(8, '\0')) == HttpResult::WrongNonce);
  Require(sticky.Feed(response) == HttpResult::WrongNonce);
  Require(Parse(response + "extra") == HttpResult::Limit);
  Require(Parse("HTTP/1.1 200 OK\r\nX: " + std::string(4096, 'a')) == HttpResult::Limit);
  std::string too_many = "HTTP/1.1 200 OK\r\n";
  for (int i = 0; i < 25; ++i) too_many += "X: a\r\n";
  Require(Parse(Response(too_many + kHeaders.substr(kHeaders.find("\r\n") + 2))) == HttpResult::Limit);
  HttpProbeParser invalid(Nonce{});
  Require(invalid.Feed(response) == HttpResult::Malformed);
  Require(!FixtureHealthRequest(Nonce{}));
  auto request = FixtureHealthRequest(kNonce); Require(request.has_value());
  Require(request->starts_with("POST /liwetun/health/v1 HTTP/1.1\r\nHost: health.liwetun.invalid\r\n"));
  Require(request->substr(request->size() - 8) == std::string(kNonce.data(), kNonce.size()));
}
