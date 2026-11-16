#include "storage_channel.h"
#include <flutter/standard_method_codec.h>

namespace st = liwetun::storage;
StorageChannel::Value StorageChannel::Encode(const st::Snapshot& snapshot, bool load) {
  constexpr const char* codes[]{"ok", "missing", "corrupt", "denied", "busy", "conflict", "tooLarge", "failed", "unsupported"};
  const auto code = static_cast<uint32_t>(snapshot.code);
  return Value(flutter::EncodableMap{
      {Value("code"), Value(code < 9 ? codes[code] : "failed")},
      {Value("payload"), load && snapshot.code == st::Code::Ok ? Value(snapshot.payload) : Value()},
      {Value("revision"), Value(snapshot.revision)},
  });
}
StorageChannel::StorageChannel(flutter::BinaryMessenger* messenger, HWND window) : window_(window) {
  channel_ = std::make_unique<flutter::MethodChannel<Value>>(
      messenger, "top.likeweb.liwetun/storage", &flutter::StandardMethodCodec::GetInstance());
  channel_->SetMethodCallHandler([this](const auto& call, auto result) {
    Command command;
    std::string payload, revision;
    const auto& name = call.method_name();
    const auto area = name == "loadJournal" || name == "saveJournal" || name == "clearJournal" ? st::Area::Journal : st::Area::Profiles;
    if (name == "load" || name == "loadJournal") command = Command::Load;
    else if (name == "save" || name == "saveJournal") command = Command::Save;
    else if (name == "clear" || name == "clearJournal") command = Command::Clear;
    else { result->NotImplemented(); return; }
    const auto* args = call.arguments();
    bool valid = !args || std::holds_alternative<std::monostate>(*args);
    if (command != Command::Load) {
      const auto* map = args ? std::get_if<flutter::EncodableMap>(args) : nullptr;
      valid = map && map->size() == (command == Command::Save ? 2u : 1u);
      if (valid) {
        auto entry = map->find(Value("revision"));
        const auto* text = entry == map->end() ? nullptr : std::get_if<std::string>(&entry->second);
        valid = text && (text->empty() || (text->size() == 64 && text->find_first_not_of("0123456789abcdef") == std::string::npos));
        if (valid) revision = *text;
        if (command == Command::Save && valid) {
          entry = map->find(Value("payload"));
          text = entry == map->end() ? nullptr : std::get_if<std::string>(&entry->second);
          valid = text && text->size() <= st::kMaxPayload;
          if (valid) payload = *text;
        }
      }
    }
    if (!valid) { result->Error("invalid_arguments", "Invalid storage request"); return; }
    std::lock_guard lock(mutex_);
    if (stopping_ || jobs_.size() + completions_.size() >= 4) {
      if (!payload.empty()) SecureZeroMemory(payload.data(), payload.size());
      result->Success(Encode(st::Snapshot(st::Code::Busy), false)); return;
    }
    jobs_.emplace_back(command, area, std::move(payload), std::move(revision), std::move(result));
    wake_.notify_one();
  });
  worker_ = std::thread([this] { Run(); });
}
StorageChannel::~StorageChannel() {
  channel_->SetMethodCallHandler(nullptr);
  { std::lock_guard lock(mutex_); stopping_ = true; jobs_.clear(); }
  wake_.notify_one();
  if (worker_.joinable()) worker_.join();
}
void StorageChannel::Run() {
  for (;;) {
    std::unique_lock lock(mutex_);
    wake_.wait(lock, [this] { return stopping_ || !jobs_.empty(); });
    if (stopping_) return;
    Job job = std::move(jobs_.front()); jobs_.pop_front();
    lock.unlock();
    auto snapshot = job.command == Command::Load ? st::Load(job.area) :
        job.command == Command::Save ? st::Save(std::move(job.payload), job.revision, job.area) : st::Clear(job.revision, job.area);
    lock.lock();
    if (stopping_) return;
    completions_.push_back({Completion{std::move(job.result), std::move(snapshot)}, job.command == Command::Load});
    PostMessageW(window_, kCompletion, 0, 0);
  }
}
void StorageChannel::Complete() {
  std::deque<std::pair<Completion, bool>> values;
  { std::lock_guard lock(mutex_); values.swap(completions_); }
  for (auto& value : values) value.first.result->Success(Encode(value.first.snapshot, value.second));
}
