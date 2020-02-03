Set ws = WScript.CreateObject("WScript.Shell")
returnCode = ws.Run("bash %programdata%\\smartdns\\init.sh", 0 , True) 

if returnCode = 0 Then
    ws.run "wsl sudo /etc/init.d/smartdns restart", vbhide
else
    ws.run "wsl -d ubuntu sudo /etc/init.d/smartdns restart", vbhide
End If