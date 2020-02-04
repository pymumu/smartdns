Set ws = WScript.CreateObject("WScript.Shell")
returnCode = ws.run ("bash.exe ../smartdns/init.sh",0, True)

if returnCode = 0 Then
    ws.run "wsl sudo /etc/init.d/smartdns restart", vbhide
elseif returnCode = 10 Then 
    ws.run "wsl -d ubuntu sudo /etc/init.d/smartdns restart", vbhide
else
    WScript.Echo "Start smartdns failed"
End If
