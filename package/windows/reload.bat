@echo off
set "CURR_PATH=%~dp0"
set "STARTUP_PATH=%userprofile%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
FOR /F %%i IN ('wsl pwd') DO @set DIR_IN_WSL=%%i

wsl sudo cp -avf %DIR_IN_WSL%/../../etc/smartdns/* /etc/smartdns/ 
IF NOT %ERRORLEVEL% == 0 (
  echo copy smartdns configuration file failed.
  pause
  exit 1
)

wsl sudo /etc/init.d/smartdns restart
IF NOT %ERRORLEVEL% == 0 (
  echo reload smartdns failed.
  pause
  exit 1
)

echo reload smartdns success
pause
