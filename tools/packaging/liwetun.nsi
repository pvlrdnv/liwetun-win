# -*- coding: utf-8 -*-
Unicode true
!include MUI2.nsh
!include LogicLib.nsh
!include FileFunc.nsh
!include WinVer.nsh
!include x64.nsh
!include "${DELETE_INCLUDE}"

!ifdef OWNER_TEST
Name "LiWeTun — тестовая сборка"
!else
Name "LiWeTun"
!endif
OutFile "${OUTPUT_EXE}"
InstallDir "$PROGRAMFILES64\LiWeTun"
RequestExecutionLevel admin
SetCompressor /SOLID zlib
ShowInstDetails nevershow
ShowUninstDetails nevershow
Icon "${ICON_FILE}"
UninstallIcon "${ICON_FILE}"
VIProductVersion "0.1.0.1"
VIAddVersionKey /LANG=1049 "ProductName" "LiWeTun"
VIAddVersionKey /LANG=1049 "FileDescription" "LiWeTun — предварительная сборка"
VIAddVersionKey /LANG=1049 "FileVersion" "0.1.0.1"
VIAddVersionKey /LANG=1049 "LegalCopyright" "LiWeTun contributors"
!uninstfinalize 'signtool sign /q /fd SHA256 /sm /s My /sha1 ${SIGN_THUMBPRINT} "%1"' = 0

!define UNINSTALL_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\LiWeTun"
!define MUI_FINISHPAGE_TEXT "Установка завершена. Откройте LiWeTun из меню «Пуск»."
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "Russian"

Var SetupMutex
Var OwnerSid
Var OwnedDirectory
Var ServiceAttempted

!macro Initialize
  SetDetailsPrint none
  SetShellVarContext all
  SetRegView 64
  StrCpy $INSTDIR "$PROGRAMFILES64\LiWeTun"
  ${IfNot} ${IsNativeAMD64}
    SetErrorLevel 20
    Quit
  ${EndIf}
  ${IfNot} ${AtLeastWin10}
    SetErrorLevel 20
    Quit
  ${EndIf}
  System::Call 'kernel32::SetLastError(i 0)'
  System::Call 'kernel32::CreateMutexW(p 0, i 0, w "Global\LiWeTun.Setup") p .r0 ?e'
  Pop $1
  StrCpy $SetupMutex $0
  ${If} $SetupMutex == 0
  ${OrIf} $1 == 183
    SetErrorLevel 25
    Quit
  ${EndIf}
!macroend

!macro ServiceState PREFIX
Function ${PREFIX}ServiceState
  StrCpy $3 2
  System::Call 'advapi32::OpenSCManagerW(p 0, p 0, i 1) p .r0'
  ${If} $0 != 0
    System::Call 'advapi32::OpenServiceW(p r0, w "LiWeTun", i 4) p .r1 ?e'
    Pop $2
    ${If} $1 != 0
      StrCpy $3 1
      System::Call 'advapi32::CloseServiceHandle(p r1)'
    ${ElseIf} $2 == 1060
      StrCpy $3 0
    ${EndIf}
    System::Call 'advapi32::CloseServiceHandle(p r0)'
  ${EndIf}
  Push $3
FunctionEnd
!macroend
!insertmacro ServiceState ""
!insertmacro ServiceState "un."

Function .onInit
  !insertmacro Initialize
  StrCpy $OwnedDirectory 0
  StrCpy $ServiceAttempted 0
  IfFileExists "$INSTDIR" existing_directory
  IfFileExists "$SMPROGRAMS\LiWeTun.lnk" existing_metadata
  Call ServiceState
  Pop $0
  ${If} $0 == 1
    SetErrorLevel 22
    Quit
  ${ElseIf} $0 != 0
    SetErrorLevel 24
    Quit
  ${EndIf}
  System::Call 'advapi32::RegOpenKeyExW(p 0x80000002, w "${UNINSTALL_KEY}", i 0, i 0x20119, *p .r0) i .r1'
  ${If} $1 == 0
    System::Call 'advapi32::RegCloseKey(p r0)'
    Goto existing_metadata
  ${ElseIf} $1 != 2
    SetErrorLevel 24
    Quit
  ${EndIf}
  ${GetParameters} $0
  ${GetOptions} $0 "/OWNER_SID=" $OwnerSid
  Return
existing_directory:
  MessageBox MB_OK|MB_ICONSTOP "Обнаружена существующая папка LiWeTun. Удалите прежнюю установку перед повторной установкой." /SD IDOK
  SetErrorLevel 21
  Quit
existing_metadata:
  SetErrorLevel 23
  Quit
FunctionEnd

Function Rollback
  ${If} $OwnedDirectory != 1
    Return
  ${EndIf}
  SetOutPath "$TEMP"
  ${If} $ServiceAttempted == 1
    StrCpy $0 -1
    ExecWait '"$INSTDIR\liwetun_service.exe" --uninstall' $0
    ${If} $0 != 0
      SetErrorLevel 50
      Return
    ${EndIf}
    StrCpy $ServiceAttempted 0
  ${EndIf}
  !insertmacro RemovePayload rollback_failed
  Delete "$SMPROGRAMS\LiWeTun.lnk"
  IfFileExists "$SMPROGRAMS\LiWeTun.lnk" rollback_failed
  DeleteRegKey HKLM "${UNINSTALL_KEY}"
  System::Call 'advapi32::RegOpenKeyExW(p 0x80000002, w "${UNINSTALL_KEY}", i 0, i 0x20119, *p .r0) i .r1'
  ${If} $1 == 0
    System::Call 'advapi32::RegCloseKey(p r0)'
    Goto rollback_failed
  ${ElseIf} $1 != 2
    Goto rollback_failed
  ${EndIf}
  ; Optional metadata may never have existed. Verify absence above, then
  ; isolate error flags for removal of this invocation's remaining directory.
  ClearErrors
  Delete "$INSTDIR\installation.ini"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"
  IfErrors rollback_failed
  StrCpy $OwnedDirectory 0
  Return
rollback_failed:
  SetErrorLevel 50
FunctionEnd

Function .onInstFailed
  Call Rollback
FunctionEnd

Section "LiWeTun"
  SetOverwrite off
  SetErrorLevel 30
  ClearErrors
  CreateDirectory "$INSTDIR"
  IfErrors install_failed
  StrCpy $OwnedDirectory 1
  StrCpy $0 -1
  ExecWait '"$SYSDIR\icacls.exe" "$INSTDIR" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" /Q' $0
  ${If} $0 != 0
    Goto install_failed
  ${EndIf}
  SetOutPath "$INSTDIR"
  File /r "${PAYLOAD}\*"
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  WriteINIStr "$INSTDIR\installation.ini" "LiWeTun" "Package" "1"
  IfErrors install_failed
  StrCpy $0 -1
  ExecWait '"$SYSDIR\icacls.exe" "$INSTDIR" /setowner "*S-1-5-32-544" /T /Q' $0
  ${If} $0 != 0
    Goto install_failed
  ${EndIf}
  StrCpy $ServiceAttempted 1
  StrCpy $0 -1
  ${If} $OwnerSid == ""
    ExecWait '"$INSTDIR\liwetun_service.exe" --install-desktop-owner' $0
  ${Else}
    ExecWait '"$INSTDIR\liwetun_service.exe" --install "$OwnerSid"' $0
  ${EndIf}
  ${If} $0 != 0
    SetErrorLevel 31
    Goto install_failed
  ${EndIf}
  ClearErrors
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayName" "LiWeTun"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayVersion" "0.1.0-preview"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegStr HKLM "${UNINSTALL_KEY}" "QuietUninstallString" '"$INSTDIR\Uninstall.exe" /S'
  WriteRegStr HKLM "${UNINSTALL_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "NoRepair" 1
  CreateShortcut "$SMPROGRAMS\LiWeTun.lnk" "$INSTDIR\liwetun.exe"
  IfErrors metadata_failed
  SetErrorLevel 0
  Goto install_done
metadata_failed:
  SetErrorLevel 32
install_failed:
  Call Rollback
  Quit
install_done:
SectionEnd

Function un.onInit
  !insertmacro Initialize
  ReadINIStr $0 "$INSTDIR\installation.ini" "LiWeTun" "Package"
  ${If} $0 != "1"
    SetErrorLevel 42
    Quit
  ${EndIf}
  System::Call 'kernel32::OpenMutexW(i 0x100000, i 0, w "Global\LiWeTun.AppPresence.v1") p .r0 ?e'
  Pop $1
  ${If} $0 != 0
    System::Call 'kernel32::CloseHandle(p r0)'
    Goto gui_busy
  ${ElseIf} $1 != 2
    Goto gui_busy
  ${EndIf}
  Return
gui_busy:
  MessageBox MB_OK|MB_ICONINFORMATION "Закройте LiWeTun во всех сеансах Windows и повторите удаление." /SD IDOK
  SetErrorLevel 43
  Quit
FunctionEnd

Section "Uninstall"
  SetOutPath "$TEMP"
  Call un.ServiceState
  Pop $0
  ${If} $0 == 1
    StrCpy $0 -1
    ExecWait '"$INSTDIR\liwetun_service.exe" --uninstall' $0
  ${EndIf}
  ${If} $0 != 0
    SetErrorLevel 40
    Quit
  ${EndIf}
  !insertmacro RemovePayload uninstall_failed
  ; Preserve unknown files and retain the recovery uninstaller/registration.
  FindFirst $0 $1 "$INSTDIR\*"
uninstall_remaining:
  ${If} $1 == ""
    Goto uninstall_empty
  ${EndIf}
  ${If} $1 != "."
  ${AndIf} $1 != ".."
  ${AndIf} $1 != "installation.ini"
  ${AndIf} $1 != "Uninstall.exe"
    FindClose $0
    Goto uninstall_failed
  ${EndIf}
  FindNext $0 $1
  Goto uninstall_remaining
uninstall_empty:
  FindClose $0
  ClearErrors
  Delete "$INSTDIR\installation.ini"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"
  IfErrors uninstall_failed
  Delete "$SMPROGRAMS\LiWeTun.lnk"
  DeleteRegKey HKLM "${UNINSTALL_KEY}"
  SetErrorLevel 0
  Goto uninstall_done
uninstall_failed:
  MessageBox MB_OK|MB_ICONSTOP "Не удалось полностью удалить LiWeTun. Закройте приложение и сохраните дополнительные файлы из его папки, затем повторите удаление." /SD IDOK
  SetErrorLevel 41
  Quit
uninstall_done:
SectionEnd
