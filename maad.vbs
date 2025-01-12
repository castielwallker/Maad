On Error Resume Next

Dim shell
Set shell = CreateObject("WScript.Shell")

'
Dim commands
commands = Array( _ 
    "REG DELETE ""HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"" /va /f", _ 
    "REG DELETE ""HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store"" /va /f", _ 
    "REG DELETE ""HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"" /va /f", _ 
    "REG DELETE ""HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Persisted"" /va /f", _ 
    "REG DELETE ""HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched"" /va /f", _ 
    "REG DELETE ""HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"" /va /f", _ 
    "REG DELETE ""HKEY_CURRENT_USER\Software\Microsoft\Windows\ShellNoRoam"" /va /f", _ 
    "REG DELETE ""HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU"" /f", _ 
    "REG DELETE ""HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags"" /f", _ 
    "REG DELETE ""HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"" /va /f", _ 
    "REG DELETE ""HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU"" /va /f", _ 
    "REG DELETE ""HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU"" /f", _ 
    "REG DELETE ""HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}"" /va /f", _ 
    "REG DELETE ""HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR"" /va /f", _ 
    "REG DELETE ""HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"" /va /f", _ 
    "REG DELETE ""HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"" /va /f", _ 
    "REG DELETE ""HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store"" /va /f", _ 
    "REG DELETE ""HKEY_CURRENT_USER\SOFTWARE\WinRAR\ArcHistory"" /va /f", _ 
    "REG DELETE ""HKLM\SYSTEM\CurrentControlSet\Services\bam\UserSettings"" /va /f", _ 
    "REG DELETE ""HKLM\SYSTEM\CurrentControlSet\Services\bam"" /va /f", _ 
    "REG DELETE ""HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags"" /va /f", _ 
    "REG DELETE ""HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU"" /va /f" _ 
)

Dim sid
sid = GetSID()

If Not IsEmpty(sid) Then
    commands = Array( _
        "REG DELETE ""HKEY_USERS\" & sid & "\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched"" /va /f", _ 
        "REG DELETE ""HKEY_USERS\" & sid & "\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\Show JumpView"" /va /f" _
    )
End If

Dim command
For Each command In commands
    shell.Run command, 0, True
Next


'
Dim tempFolder, folder, subFolder
tempFolder = CreateObject("WScript.Shell").ExpandEnvironmentStrings("%temp%")

If fso.FolderExists(tempFolder) Then
    Set folder = fso.GetFolder(tempFolder)
    For Each file In folder.Files
        file.Attributes = 0 
        file.Delete True
    Next
    For Each subFolder In folder.SubFolders
        subFolder.Attributes = 0 
        subFolder.Delete True
    Next
End If

Set fso = Nothing
Set folder = Nothing
Set shell = Nothing


'
services = Array("EventLog", "DPS", "SysMain", "DiagTrack", "PcaSvc")
For Each service In services
    shell.Run "sc config " & service & " start= disabled", 0, True
    shell.Run "sc stop " & service, 0, True
Next

shell.Run "wevtutil cl Application", 0, True
shell.Run "wevtutil cl Security", 0, True
shell.Run "wevtutil cl System", 0, True
shell.Run "sc config eventlog start= disabled", 0, True

'
shell.Run "cmd.exe /c fsutil usn deletejournal /D C:", 0, True
Set shell = Nothing

'
Set objFSO = CreateObject("Scripting.FileSystemObject")
PrefetchPath = "C:\Windows\Prefetch"
If objFSO.FolderExists(PrefetchPath) Then
    objFSO.DeleteFolder PrefetchPath, True
End If

shell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\InstallDate", "1499414400", "REG_DWORD"
shell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\RegisteredOwner", "Maad", "REG_SZ"
shell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\RegisteredOrganization", "Maad", "REG_SZ"
shell.RegWrite "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\PCI\{ID_da_Placa}\DeviceDesc", "Maad", "REG_SZ"
shell.RegWrite "HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\CentralProcessor\0\ProcessorNameString", "MAAD - PROCESSADOR RLK DO PODER", "REG_SZ"
shell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductName", "Windows - Maad Version", "REG_SZ"
shell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\RegisteredOrganization", "Maad", "REG_SZ"
shell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA", 0, "REG_DWORD"
shell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Disabled", 1, "REG_DWORD"
shell.RegWrite "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName\ComputerName", "Maad", "REG_SZ"
shell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoUpdate", 1, "REG_DWORD"
shell.RegWrite "HKEY_LOCAL_MACHINE\SYSTEM\MountedDevices\##Server#C#", "Maad", "REG_SZ"
shell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\explorer.exe\CpuPriorityClass", 128, "REG_DWORD"
shell.RegWrite "HKEY_CURRENT_USER\Control Panel\Desktop\MenuShowDelay", 0, "REG_SZ"
shell.RegWrite "HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics\MinAnimate", 0, "REG_SZ"
shell.RegWrite "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\EnableTransparency", 0, "REG_DWORD"
shell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry", 0, "REG_DWORD"
shell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System\EnableActivityFeed", 0, "REG_DWORD"
shell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SmartScreenEnabled", "Off", "REG_SZ"
shell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\DontSendAdditionalData", 1, "REG_DWORD"
shell.RegWrite "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wbengine\Start", 4, "REG_DWORD"
shell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate\updateenabled", 0, "REG_DWORD"
shell.RegWrite "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usermode\Start", 4, "REG_DWORD"
shell.RegWrite "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HelpSvc\Start", 4, "REG_DWORD"
shell.RegWrite "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Start", 4, "REG_DWORD"
shell.RegWrite "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinMgmt\Start", 4, "REG_DWORD"
shell.RegWrite "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\NOC_GLOBAL_SETTING", 0, "REG_DWORD"
shell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoErrorReporting", 1, "REG_DWORD"
shell.RegWrite "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\PushNotifications\ToastEnabled", 0, "REG_DWORD"
shell.RegWrite "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ProxyEnable", 0, "REG_DWORD"
shell.RegWrite "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\NameServer", "8.8.8.8,8.8.4.4", "REG_SZ"
shell.RegWrite "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\EnableTcpAckFrequency", 1, "REG_DWORD"
shell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged\EnableAutoconnect", 0, "REG_DWORD"
shell.Run "reg add HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters /v EnablePrefetcher /t REG_DWORD /d 0 /f", 0, True
shell.Run "wmic computersystem where name='%computername%' call rename name='Maad'", 0, True
shell.Run "wmic computersystem where name='%computername%' set workgroup='Maad'", 0, True
shell.Run "wmic computersystem where name='%computername%' set description='Maad'", 0, True
shell.Run "cmd /c del /f /s /q C:\Windows\Temp\*", 0, True
shell.Run "cmd /c del /f /s /q %USERPROFILE%\AppData\Local\Microsoft\Windows\INetCache\*", 0, True
shell.Run "cmd /c del /f /s /q C:\Windows\SoftwareDistribution\Download\*", 0, True
shell.Run "cmd /c del /f /s /q C:\Windows\System32\winevt\Logs\*", 0, True
shell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemManufacturer", "Maad", "REG_SZ"
shell.Run "cmd /c del /f /s /q %APPDATA%\Microsoft\Windows\Recent\*", 0, True
shell.Run "ipconfig /flushdns", 0, True
shell.RegWrite "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\TimeZoneInformation\ActiveTimeBias", -180, "REG_DWORD"

If objFSO.FolderExists("C:\Windows\Prefetch") Then
    Set objFolder = objFSO.GetFolder("C:\Windows\Prefetch")
    For Each objFile In objFolder.Files
        objFile.Delete
    Next
End If

If objFSO.FolderExists("C:\Windows\System32\winevt\Logs") Then
    Set objFolder = objFSO.GetFolder("C:\Windows\System32\winevt\Logs")
    For Each objFile In objFolder.Files
        objFile.Delete
    Next
End If


Function GetSID()
    Dim objWMIService, objAccount, userName, userDomain
    On Error Resume Next
    Set objWMIService = GetObject("winmgmts:\\.\root\cimv2")
    userName = CreateObject("WScript.Network").UserName
    userDomain = CreateObject("WScript.Network").UserDomain
    Set objAccount = objWMIService.Get("Win32_UserAccount.Name='" & userName & "',Domain='" & userDomain & "'")
    If Not objAccount Is Nothing Then
        GetSID = objAccount.SID
    Else
        GetSID = ""
    End If
End Function
