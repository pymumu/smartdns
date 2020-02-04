Set ws = WScript.CreateObject("WScript.Shell")
Set fs = WScript.CreateObject("Scripting.FileSystemObject")

CURR_PATH =fs.GetParentFolderName(WScript.ScriptFullName)
USERPROFILE = ws.ExpandEnvironmentStrings("%USERPROFILE%")
SmartdnsDir = USERPROFILE + "\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\smartdns"

Set lnk = ws.CreateShortcut(SmartdnsDir & "\restart.lnk")
lnk.TargetPath = CURR_PATH +"\restart.bat"
lnk.WindowStyle = "1"
lnk.WorkingDirectory = CURR_PATH
lnk.Save
Set lnk = Nothing

Set lnk = ws.CreateShortcut(SmartdnsDir & "\stop.lnk")
lnk.TargetPath = CURR_PATH +"\stop.bat"
lnk.WindowStyle = "1"
lnk.WorkingDirectory = CURR_PATH
lnk.Save
Set lnk = Nothing

Set lnk = ws.CreateShortcut(SmartdnsDir & "\test.lnk")
lnk.TargetPath = CURR_PATH +"\test.bat"
lnk.WindowStyle = "1"
lnk.WorkingDirectory = CURR_PATH
lnk.Save
Set lnk = Nothing
