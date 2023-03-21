@echo off
SETLOCAL EnableDelayedExpansion

:VBSDynamicBuild
SET TempVBSFile=%temp%\~tmpSendKeysTemp.vbs
IF EXIST "%TempVBSFile%" DEL /F /Q "%TempVBSFile%"
ECHO Set WshShell = WScript.CreateObject("WScript.Shell") >>"%TempVBSFile%"
ECHO Wscript.Sleep 1                                    >>"%TempVBSFile%"
ECHO WshShell.SendKeys "{F11}"                            >>"%TempVBSFile%
ECHO Wscript.Sleep 1                                    >>"%TempVBSFile%"

CSCRIPT //nologo "%TempVBSFile%"

>nul 2>&1 reg.exe query "HKU\S-1-5-19" || (
    echo set UAC = CreateObject^("Shell.Application"^) > "%temp%\Getadmin.vbs"
    echo UAC.ShellExecute "%~f0", "%1", "", "runas", 1 >> "%temp%\Getadmin.vbs"
    "%temp%\Getadmin.vbs"
    DEL /f /q "%temp%\Getadmin.vbs" >nul 2>&1
    exit /b
)

echo Wait for script finish optimizing your PC.
echo Do not turn off your computer until the script was finish setting up because it can degrade system performance.
echo.
echo.
taskkill /F /IM explorer.exe >nul 2>&1

echo Installing
echo	  - VCredistx64
start /b /wait C:\ProgramData\OwlOS\VC_redist.x64.exe /q /norestart >nul 2>&1
echo	  - VCredistx86
start /b /wait C:\ProgramData\OwlOS\VC_redist.x86.exe /q /norestart >nul 2>&1
echo	  - 7-Zip
start /b /wait "" "C:\ProgramData\OwlOS\7zip.msi" /passive /norestart >nul 2>&1
reg import "C:\ProgramData\OwlOS\7zip.reg" >nul 2>&1
echo	  - .NET Desktop Runtime 7.0.4
C:\ProgramData\OwlOS\windowsdesktop-runtime-7.0.4-win-x64.exe /silent >nul 2>&1
echo	  - OwlOS Utility
C:\ProgramData\OwlOS\Utility-Setup.exe /silent >nul 2>&1
del "C:\Users\Public\Desktop\OwlOS.lnk" >nul 2>&1

echo Setting bcdedit
bcdedit /set disabledynamictick yes >nul 2>&1
bcdedit /set useplatformtick yes >nul 2>&1
bcdedit /set nx alwaysoff >nul 2>&1
bcdedit /set {globalsettings} custom:16000067 true >nul 2>&1
bcdedit /set {globalsettings} custom:16000068 true >nul 2>&1
bcdedit /set {globalsettings} custom:16000069 true >nul 2>&1
bcdedit /set bootmenupolicy legacy >nul 2>&1
bcdedit /timeout 10 >nul 2>&1
bcdedit /set {current} description "OwlOS 22H2 (Windows 11)" >nul 2>&1

echo Setting fsutil behaviors
::source: https://github.com/amitxv/PC-Tuning
fsutil behavior set disable8dot3 1 >nul 2>&1
fsutil behavior set disablelastaccess 1 >nul 2>&1
fsutil behavior set disabledeletenotify 0 >nul 2>&1

echo Setting svchost behaviors
for /f "tokens=2 delims==" %%i in ('wmic os get TotalVisibleMemorySize /value') do set /a memory=%%i + 1000000 >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "%memory%" /f >nul 2>&1

echo Disabling algorithm nagle
for /f "tokens=3*" %%i in ('reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards" /f "Name" /s^|findstr /i /l "Name"') do (
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpAckFrequency" /d "1" /t REG_DWORD /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpDelAckTicks" /d "0" /t REG_DWORD /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TCPNoDelay" /d "1" /t REG_DWORD /f
) >nul 2>&1

echo Disabling services
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WSearch" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\wuauserv" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\BITS" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1

echo Disabling scheduled tasks
schtasks /Change /Disable /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" >nul 2>nul
schtasks /Change /Disable /TN "\Microsoft\Windows\Application Experience\StartupAppTask" >nul 2>nul
schtasks /Change /Disable /TN "\Microsoft\Windows\ApplicationData\CleanupTemporaryState" >nul 2>nul
schtasks /Change /Disable /TN "\Microsoft\Windows\ApplicationData\DsSvcCleanup" >nul 2>nul
schtasks /Change /Disable /TN "\Microsoft\Windows\Autochk\Proxy" >nul 2>nul
schtasks /Change /Disable /TN "\Microsoft\Windows\BrokerInfrastructure\BgTaskRegistrationMaintenanceTask" >nul 2>nul
schtasks /Change /Disable /TN "\Microsoft\Windows\Chkdsk\ProactiveScan" >nul 2>nul
schtasks /Change /Disable /TN "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask" >nul 2>nul
schtasks /Change /Disable /TN "\Microsoft\Windows\CloudRestore\Restore" >nul 2>nul
schtasks /Change /Disable /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" >nul 2>nul
schtasks /Change /Disable /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" >nul 2>nul
schtasks /Change /Disable /TN "\Microsoft\Windows\Data Integrity Scan\Data Integrity Check And Scan" >nul 2>nul
schtasks /Change /Disable /TN "\Microsoft\Windows\Data Integrity Scan\Data Integrity Scan" >nul 2>nul
schtasks /Change /Disable /TN "\Microsoft\Windows\Data Integrity Scan\Data Integrity Scan for Crash Recovery" >nul 2>nul
schtasks /Change /Disable /TN "\Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\Diagnosis\Scheduled" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\DiskFootprint\StorageSense" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\DiskFootprint\Diagnostics" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\FileHistory\File History (maintenance mode)" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\InstallService\ScanForUpdates" >nul 2>nul
schtasks /Change /Disable /TN "\Microsoft\Windows\InstallService\ScanForUpdatesAsUser" >nul 2>nul
schtasks /Change /Disable /TN "\Microsoft\Windows\Maintenance\WinSAT" >nul 2>nul
schtasks /Change /Disable /TN "\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\Speech\SpeechModelDownloadTask" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\StateRepository\MaintenanceTasks" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\Time Synchronization\SynchronizeTime" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\Time Zone\SynchronizeTimeZone" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\USB\Usb-Notifications" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\WindowsUpdate\Scheduled Start" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\Wininet\CacheTask" >nul 2>&1

echo Disabling driver power saving
::source: https://github.com/amitxv/PC-Tuning
for %%a in (
      EnhancedPowerManagementEnabled
      AllowIdleIrpInD3
      EnableSelectiveSuspend
      DeviceSelectiveSuspended
      SelectiveSuspendEnabled
      SelectiveSuspendOn
      WaitWakeEnabled
      D3ColdSupported
      WdfDirectedPowerTransitionEnable
      EnableIdlePowerManagement
      IdleInWorkingState
) do for /f "delims=" %%b in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum" /s /f "%%a" ^| findstr "HKEY"') do Reg.exe add "%%b" /v "%%a" /t REG_DWORD /d "0" /f > NUL 2>&1
for /f "tokens=*" %%i in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum\PCI"^| findstr "HKEY"') do (
			for /f "tokens=*" %%a in ('reg query "%%i"^| findstr "HKEY"') do Reg.exe delete "%%a\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >nul 2>&1
		)
)

echo Removing firewall rules
::source: https://github.com/amitxv/PC-Tuning
Reg.exe delete "HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /f >nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /f >nul 2>&1

echo Importing custom powerplan
powercfg -import "C:\ProgramData\OwlOS\owlos.pow" 99999999-9999-9999-9999-999999999999 >nul 2>&1
powercfg -setactive 99999999-9999-9999-9999-999999999999 >nul 2>&1

echo Setting visual effects
Reg.exe add "HKCU\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d "9012038010000000" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d "3" /f >nul 2>&1
Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewAlphaSelect" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconsOnly" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Accent" /v "AccentPalette" /t REG_BINARY /d "9b9a9900848381006d6b6a004c4a4800363533002625240019191900107c1000" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Accent" /v "AccentColorMenu" /t REG_DWORD /d "4282927692" /f >nul 2>&1
Reg.exe add "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t "REG_DWORD" /d "100" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "0" /f >nul 2>&1

echo Enabling legacy photo viewer
Reg.exe add "HKCU\SOFTWARE\Classes\.jpg" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Classes\.jpeg" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Classes\.gif" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Classes\.png" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Classes\.bmp" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Classes\.tiff" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Classes\.ico" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Classes\.tif" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Classes\.wdp" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Wdp" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Classes\.jfif" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Classes\.dib" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Classes\.jpe" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Classes\.jxr" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >nul 2>&1

echo Running .ps1 scripts
echo	  - disable devices
PowerShell -File "C:\ProgramData\OwlOS\disable devices.ps1" >nul 2>&1
echo	  - network optimizations
PowerShell -File "C:\ProgramData\OwlOS\network optimizations.ps1" >nul 2>&1
echo	  - sound scheme
PowerShell -File "C:\ProgramData\OwlOS\sound scheme.ps1" >nul 2>&1
echo	  - uninstall microsoft store
PowerShell -File "C:\ProgramData\OwlOS\uninstall microsoft store.ps1" >nul 2>&1
echo	  - usb power managment
PowerShell -File "C:\ProgramData\OwlOS\usb power managment.ps1" >nul 2>&1

::włączanie przypinania aplikacji sklepu do paska zadań
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "NoPinningStoreToTaskbar" /t REG_DWORD /d "0" /f >nul 2>&1

del /q/f/s %TEMP%\* >nul 2>&1
shutdown -r -t 5 /c "Restarting"
DEL "%~f0"