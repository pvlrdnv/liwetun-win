#pragma once
#include "protocol.h"

namespace liwetun {
// Read the optional tail only after a successful, authenticated base reply.
// Keeping this separate permits exact old-service/partial-read validation.
template <typename Read>
Reply ConsumeTrafficTail(const Reply& base, TrafficReply& output, Read read) {
  if (base.code != Code::Ok) { output = TrafficReply{}; return base; }
  Code failure = Code::Ok;
  if (!read(&output.instance, static_cast<uint32_t>(sizeof(TrafficReply) - sizeof(Reply)))) {
    failure = Code::Timeout;
  } else if (output.instance > traffic::kMaximum || !traffic::Valid(output.sample) ||
      ((output.sample.flags & traffic::kValid) &&
       (output.instance == 0 || base.state != State::TunnelReady || base.core_state != 2 || base.runtime_ready != 1))) {
    failure = Code::Malformed;
  }
  if (failure != Code::Ok) {
    output = TrafficReply{};
    Reply rejected;
    rejected.code = failure;
    rejected.core_state = UINT32_MAX;
    return rejected;
  }
  return base;
}
}  // namespace liwetun
