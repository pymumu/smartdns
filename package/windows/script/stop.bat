@echo off
bash "$(wslpath -u "%~dp0\init.sh")"
IF %ERRORLEVEL% == 0 (
  wsl sudo /etc/init.d/smartdns stop
)^
ELSE IF %ERRORLEVEL% == 10 (
  wsl -d ubuntu sudo /etc/init.d/smartdns stop
)^
ELSE echo error:%ERRORLEVEL%
pause