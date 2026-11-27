@echo off
setlocal
rem SFguard launcher.
rem Use this if double-clicking SFguard.exe does nothing. That can happen when the
rem folder carries a restrictive integrity label (e.g. a sandboxed workspace), which
rem prevents the single-file executable from unpacking to %TEMP%.
rem This launcher copies the exe to %LOCALAPPDATA%\SFguard and starts it there.
set "SRC=%~dp0SFguard.exe"
if not exist "%SRC%" (
  echo SFguard.exe not found next to this script.
  pause
  exit /b 1
)
set "DEST=%LOCALAPPDATA%\SFguard"
if not exist "%DEST%" mkdir "%DEST%" >nul 2>&1
copy /Y "%SRC%" "%DEST%\SFguard.exe" >nul 2>&1
if exist "%DEST%\SFguard.exe" (
  start "" "%DEST%\SFguard.exe"
) else (
  start "" "%SRC%"
)
