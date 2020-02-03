@echo off
set "CURR_PATH=%~dp0"
set "STARTUP_PATH=%userprofile%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
FOR /F %%i IN ('wsl pwd') DO @set DIR_IN_WSL=%%i

bash ./init.sh
IF %ERRORLEVEL% == 0 (
  wsl sudo cp -avf %DIR_IN_WSL%/../../etc/smartdns/* /etc/smartdns/ 
  wsl sudo /etc/init.d/smartdns restart
)^
ELSE (
  wsl -d ubuntu sudo cp -avf %DIR_IN_WSL%/../../etc/smartdns/* /etc/smartdns/ 
  wsl -d ubuntu sudo /etc/init.d/smartdns restart
)
IF NOT %ERRORLEVEL% == 0 (
  echo reload smartdns failed.
  pause
  exit 1
)

echo reload smartdns success
pause
