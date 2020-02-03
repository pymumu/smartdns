@echo off
set "CURR_PATH=%~dp0"
set "STARTUP_PATH=%userprofile%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
FOR /F %%i IN ('wsl pwd') DO @set DIR_IN_WSL=%%i

bash ./init.sh
IF %ERRORLEVEL% == 0 (
  wsl sudo %DIR_IN_WSL%/../../install -i
)^
ELSE (
  wsl -d ubuntu sudo %DIR_IN_WSL%/../../install -i
)
IF NOT %ERRORLEVEL% == 0 (
  echo Install smartdns failed.
  pause
  exit 1
)
md "%programdata%\smartdns\"
copy %CURR_PATH%\init.sh "%programdata%\smartdns\"
copy %CURR_PATH%\wsl-run.vbs "%STARTUP_PATH%/"
IF NOT %ERRORLEVEL% == 0 (
  echo Install startupt script failed.
  pause
  exit 1
)

echo Install smartdns success
pause
