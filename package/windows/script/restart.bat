@echo off
bash "$(wslpath -u "%~dp0\init.sh")"
IF %ERRORLEVEL% == 0 (
  wsl sudo /etc/init.d/smartdns restart
)^
ELSE IF %ERRORLEVEL% == 10 (
  wsl -d ubuntu sudo /etc/init.d/smartdns restart
)^
ELSE echo error:%ERRORLEVEL%
pause
