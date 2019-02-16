@echo off
set "CURR_PATH=%~dp0"
set "STARTUP_PATH=%userprofile%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
FOR /F %%i IN ('wsl pwd') DO @set DIR_IN_WSL=%%i

wsl sudo %DIR_IN_WSL%/../../install -i
IF NOT %ERRORLEVEL% == 0 (
  echo Install smartdns failed.
  pause
  exit 1
)

copy %CURR_PATH%\wsl-run.vbs "%STARTUP_PATH%/"
IF NOT %ERRORLEVEL% == 0 (
  echo Install startupt script failed.
  pause
  exit 1
)

echo Install smartdns success
pause
