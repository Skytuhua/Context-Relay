; Capture this here: __FILEDIR__ inside a macro refers to its expansion site.
!define CONTEXT_RELAY_HOOK_DIR "${__FILEDIR__}"

!macro ContextRelayStopService EXECUTABLE
  Push $0
  Push $1
  nsExec::ExecToStack /TIMEOUT=60000 '"${EXECUTABLE}" --shutdown'
  Pop $0
  Pop $1
  ${If} $0 != 0
    Pop $1
    Pop $0
    SetErrorLevel 1
    Abort "Context Relay could not stop its local service. Close Context Relay and connected AI tools, then run Setup again. Your workspace has been kept."
  ${EndIf}
  Pop $1
  Pop $0
!macroend

!macro NSIS_HOOK_PREINSTALL
  !insertmacro CheckIfAppIsRunning "${MAINBINARYNAME}.exe" "${PRODUCTNAME}"
  ; Always use the new helper: older daemon binaries ignore --shutdown and start.
  ; The embedded helper authenticates shutdown only for current and legacy 1.4 IPC.
  InitPluginsDir
  SetOutPath "$PLUGINSDIR"
  File /oname=context-relay-service-control.exe "${CONTEXT_RELAY_HOOK_DIR}\..\binaries\context-relay-contextd-x86_64-pc-windows-msvc.exe"
  !insertmacro ContextRelayStopService "$PLUGINSDIR\context-relay-service-control.exe"
  SetOutPath "$INSTDIR"
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  !insertmacro CheckIfAppIsRunning "${MAINBINARYNAME}.exe" "${PRODUCTNAME}"
  ${If} ${FileExists} "$INSTDIR\context-relay-contextd.exe"
    !insertmacro ContextRelayStopService "$INSTDIR\context-relay-contextd.exe"
  ${EndIf}
  ; Tauri removes only its installed files. The encrypted vault is retained.
!macroend
