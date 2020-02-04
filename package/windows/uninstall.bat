@echo off
set "CURR_PATH=%~dp0"
set "STARTUP_PATH=%userprofile%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
set "StartMenuDir=%userprofile%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs"
FOR /F %%i IN ('wsl pwd') DO @set DIR_IN_WSL=%%i

bash "$(wslpath -u "%CURR_PATH%\script\init.sh")"
IF %ERRORLEVEL% == 0 (
  wsl sudo %DIR_IN_WSL%/../../install -u
)^
ELSE IF %ERRORLEVEL% == 10 (
  wsl -d ubuntu sudo %DIR_IN_WSL%/../../install -u
)^
ELSE echo error:%ERRORLEVEL%

IF NOT %ERRORLEVEL% == 0 (
  echo Uninstall smartdns failed.
  pause 
  exit 1
)

del "%StartMenuDir%\smartdns\init.sh"
del "%StartMenuDir%\smartdns\restart.lnk"
del "%StartMenuDir%\smartdns\stop.lnk"
del "%StartMenuDir%\smartdns\test.lnk"

del "%STARTUP_PATH%\wsl-run.vbs"
IF NOT %ERRORLEVEL% == 0 (
  echo Uninstall startup script failed.
  pause 
  exit 1
)

echo uninstall success
pause
