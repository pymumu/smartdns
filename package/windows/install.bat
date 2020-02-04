@echo off
set "CURR_PATH=%~dp0"
set "STARTUP_PATH=%userprofile%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
set "StartMenuDir=%userprofile%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs"
FOR /F %%i IN ('wsl pwd') DO @set DIR_IN_WSL=%%i

bash "$(wslpath -u "%CURR_PATH%\script\init.sh")"
IF %ERRORLEVEL% == 0 (
  wsl sudo %DIR_IN_WSL%/../../install -i
)^
ELSE IF %ERRORLEVEL% == 10 (
  wsl -d ubuntu sudo %DIR_IN_WSL%/../../install -i
)^
ELSE echo error:%ERRORLEVEL%

IF NOT %ERRORLEVEL% == 0 (
  echo Install smartdns failed.
  pause
  exit 1
)

md "%StartMenuDir%\Smartdns"
copy %CURR_PATH%\script\init.sh "%StartMenuDir%\smartdns\"

call %CURR_PATH%\script\startmenu.vbs

copy %CURR_PATH%\wsl-run.vbs "%STARTUP_PATH%\"
IF NOT %ERRORLEVEL% == 0 (
  echo Install startupt script failed.
  pause
  exit 1
)

echo Install smartdns success
pause
