#pragma once
#include <flutter/binary_messenger.h>
#include <flutter/encodable_value.h>
#include <flutter/method_channel.h>
#include <memory>

class TrustTunnelChannel {
 public:
  explicit TrustTunnelChannel(flutter::BinaryMessenger* messenger);
  ~TrustTunnelChannel();
 private:
  std::unique_ptr<flutter::MethodChannel<flutter::EncodableValue>> channel_;
};
