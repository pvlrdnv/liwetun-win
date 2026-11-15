#include "trusttunnel_channel.h"
#include <flutter/standard_method_codec.h>
#include "liwetun_native.h"

namespace {
using Value = flutter::EncodableValue;
using Map = flutter::EncodableMap;
constexpr char kDecoderRevision[] = "48f424c0874eb6f6374ee84492c5cd55aa04dca9";
}

TrustTunnelChannel::~TrustTunnelChannel() {
  channel_->SetMethodCallHandler(nullptr);
}

TrustTunnelChannel::TrustTunnelChannel(flutter::BinaryMessenger* messenger) {
  channel_ = std::make_unique<flutter::MethodChannel<Value>>(
      messenger, "top.likeweb.liwetun/trusttunnel",
      &flutter::StandardMethodCodec::GetInstance());
  channel_->SetMethodCallHandler([](const auto& call, auto result) {
    if (call.method_name() == "capabilities") {
      result->Success(Value(Map{
          {Value("abiVersion"), Value(1)},
          {Value("canInspect"), Value(true)},
          {Value("canConnect"), Value(false)},
          {Value("decoderRevision"), Value(kDecoderRevision)},
          {Value("reason"), Value("service_not_qualified")},
      }));
      return;
    }
    if (call.method_name() != "inspectTrustTunnel") {
      result->NotImplemented();
      return;
    }
    const auto* args = call.arguments();
    const auto* map = args ? std::get_if<Map>(args) : nullptr;
    if (!map || map->size() != 1) {
      result->Error("invalid_arguments", "Invalid inspection arguments");
      return;
    }
    const auto found = map->find(Value("uri"));
    const auto* uri = found == map->end() ? nullptr : std::get_if<std::string>(&found->second);
    if (!uri || uri->empty() || uri->size() > 8192) {
      result->Error("invalid_arguments", "Invalid inspection arguments");
      return;
    }
    LiwetunTtInfo info{};
    const int32_t code = liwetun_tt_inspect(
        reinterpret_cast<const uint8_t*>(uri->data()), uri->size(), &info);
    const char* status;
    switch (code) {
      case 0: status = "accepted"; break;
      case 1: status = "malformed"; break;
      case 2: status = "insecure"; break;
      case 3: status = "unsupported"; break;
      default: status = "internal_error"; break;
    }
    Map response{{Value("status"), Value(status)}};
    if (code == 0 && info.abi_version == 1) {
      response.emplace(Value("transport"), Value(static_cast<int32_t>(info.transport)));
      response.emplace(Value("customCertificate"), Value(info.custom_certificate != 0));
      response.emplace(Value("hasIpv6"), Value(info.has_ipv6 != 0));
    }
    result->Success(Value(response));
  });
}
