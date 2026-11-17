#pragma once
#include <windows.h>
#include <shellapi.h>
#include <flutter/binary_messenger.h>
#include <flutter/method_channel.h>
#include <flutter/encodable_value.h>
#include <memory>

class DesktopChannel {
 public:
  static constexpr UINT kTrayMessage = WM_APP + 0x543;
  DesktopChannel(flutter::BinaryMessenger* messenger, HWND window);
  ~DesktopChannel();
  bool Handle(UINT message, WPARAM wparam, LPARAM lparam);
  bool HideOnClose();
 private:
  using Value = flutter::EncodableValue;
  bool AddIcon();
  void Show();
  Value Status() const;
  HWND window_;
  UINT taskbar_created_;
  NOTIFYICONDATAW icon_{};
  bool installed_ = false, close_to_tray_ = false, exiting_ = false;
  std::unique_ptr<flutter::MethodChannel<Value>> channel_;
};
