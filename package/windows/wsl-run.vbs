Set ws = WScript.CreateObject("WScript.Shell")

USERPROFILE = ws.ExpandEnvironmentStrings("%USERPROFILE%")
initScriptPath = Chr(34) + USERPROFILE + "\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\smartdns\init.sh" + Chr(34)
tmp = replace(initScriptPath ,"\", "/")
unixPath = replace(tmp ,"C:", "/mnt/c")

command = "bash " + unixPath

returnCode = ws.run(command,0,True)

if returnCode = 0 Then
    ws.run "wsl sudo /etc/init.d/smartdns restart", vbhide
elseif returnCode = 10 Then 
    ws.run "wsl -d ubuntu sudo /etc/init.d/smartdns restart", vbhide
else
    WScript.Echo "Start smartdns failed"
End If
