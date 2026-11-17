#include "desktop_channel.h"
#include "resource.h"
#include <cwchar>
#include <flutter/standard_method_codec.h>

DesktopChannel::DesktopChannel(flutter::BinaryMessenger* messenger, HWND window)
    : window_(window), taskbar_created_(RegisterWindowMessageW(L"TaskbarCreated")) {
  icon_.cbSize = sizeof(icon_);
  icon_.hWnd = window_;
  icon_.uID = 1;
  icon_.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
  icon_.uCallbackMessage = kTrayMessage;
  icon_.hIcon = LoadIconW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDI_APP_ICON));
  wcscpy_s(icon_.szTip, L"LiWeTun");
  AddIcon();
  channel_ = std::make_unique<flutter::MethodChannel<Value>>(
      messenger, "top.likeweb.liwetun/desktop", &flutter::StandardMethodCodec::GetInstance());
  channel_->SetMethodCallHandler([this](const auto& call, auto result) {
    if (call.method_name() == "configure") {
      const auto* map = call.arguments() ? std::get_if<flutter::EncodableMap>(call.arguments()) : nullptr;
      if (!map || map->size() != 1) { result->Error("invalid_arguments", "Invalid desktop request"); return; }
      auto found = map->find(Value("closeToTray"));
      const auto* enabled = found != map->end() ? std::get_if<bool>(&found->second) : nullptr;
      if (!enabled) { result->Error("invalid_arguments", "Invalid desktop request"); return; }
      if (!installed_) AddIcon();
      close_to_tray_ = *enabled && installed_;
    } else if (call.method_name() == "query" || call.method_name() == "show" || call.method_name() == "hide") {
      if (call.arguments() && !std::holds_alternative<std::monostate>(*call.arguments())) {
        result->Error("invalid_arguments", "Invalid desktop request"); return;
      }
      if (call.method_name() == "show") Show();
      if (call.method_name() == "hide") HideOnClose();
    } else { result->NotImplemented(); return; }
    result->Success(Status());
  });
}
DesktopChannel::~DesktopChannel() {
  channel_->SetMethodCallHandler(nullptr);
  if (installed_) Shell_NotifyIconW(NIM_DELETE, &icon_);
}
bool DesktopChannel::AddIcon() {
  installed_ = icon_.hIcon && Shell_NotifyIconW(NIM_ADD, &icon_) != FALSE;
  return installed_;
}
DesktopChannel::Value DesktopChannel::Status() const {
  return Value(flutter::EncodableMap{
      {Value("available"), Value(installed_)},
      {Value("closeToTray"), Value(installed_ && close_to_tray_)},
      {Value("visible"), Value(IsWindowVisible(window_) != FALSE)},
  });
}
void DesktopChannel::Show() {
  ShowWindow(window_, SW_RESTORE);
  SetForegroundWindow(window_);
}
bool DesktopChannel::HideOnClose() {
  if (exiting_ || !installed_ || !close_to_tray_) return false;
  ShowWindow(window_, SW_HIDE);
  return true;
}
bool DesktopChannel::Handle(UINT message, WPARAM wparam, LPARAM lparam) {
  if (taskbar_created_ && message == taskbar_created_) {
    installed_ = false;
    if (!AddIcon()) Show(); // A hidden window must never become unreachable.
    return true;
  }
  if (message != kTrayMessage || wparam != icon_.uID) return false;
  if (lparam == WM_LBUTTONDBLCLK || lparam == WM_LBUTTONUP || lparam == NIN_SELECT || lparam == NIN_KEYSELECT) {
    Show();
  } else if (lparam == WM_RBUTTONUP || lparam == WM_CONTEXTMENU) {
    HMENU menu = CreatePopupMenu();
    if (!menu) { Show(); return true; }
    AppendMenuW(menu, MF_STRING, 1, L"Открыть LiWeTun");
    AppendMenuW(menu, MF_STRING, 2, L"Выход");
    POINT point{};
    GetCursorPos(&point);
    SetForegroundWindow(window_);
    const UINT action = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_NONOTIFY,
                                      point.x, point.y, 0, window_, nullptr);
    DestroyMenu(menu);
    PostMessageW(window_, WM_NULL, 0, 0);
    if (action == 1) Show();
    else if (action == 2) {
      // Actual process exit releases the authenticated service lease. Existing
      // service-side UI-death cleanup remains the final independent boundary.
      exiting_ = true;
      PostMessageW(window_, WM_CLOSE, 0, 0);
    }
  }
  return true;
}
