#pragma once
#include "protocol.h"
#include <string>
namespace liwetun {
Reply ServiceRequest(Command command, const std::string& profile = {}, bool start_service = false);
}
