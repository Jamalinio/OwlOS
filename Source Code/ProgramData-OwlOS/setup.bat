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
echo Do not turn off your computer until the script was finish setting up because it can degrade system performance

start /b /wait C:\ProgramData\OwlOS\VC_redist.x64.exe /q /norestart >nul 2>&1
start /b /wait C:\ProgramData\OwlOS\VC_redist.x86.exe /q /norestart >nul 2>&1
start /b /wait "" "C:\ProgramData\OwlOS\openshell.exe" /qn ADDLOCAL=StartMenu >nul 2>&1
move "C:\ProgramData\OwlOS\Dark.skin7" "C:\Program Files\Open-Shell\Skins" >nul 2>&1
reg import "C:\ProgramData\OwlOS\openshell.reg" >nul 2>&1
start /b /wait "" "C:\ProgramData\OwlOS\7zip.msi" /passive /norestart >nul 2>&1
reg import "C:\ProgramData\OwlOS\7zip.reg" >nul 2>&1
bcdedit /set disabledynamictick yes >nul 2>&1
bcdedit /set useplatformtick yes >nul 2>&1
bcdedit /set nx alwaysoff >nul 2>&1
bcdedit /set {globalsettings} custom:16000067 true >nul 2>&1
bcdedit /set {globalsettings} custom:16000068 true >nul 2>&1
bcdedit /set {globalsettings} custom:16000069 true >nul 2>&1
bcdedit /set bootmenupolicy legacy >nul 2>&1
bcdedit /timeout 10 >nul 2>&1
bcdedit /set {current} description "OwlOS 22H2" >nul 2>&1
powershell Disable-NetAdapterBinding -Name "*" -ComponentID ms_msclient >nul 2>&1
powershell Disable-NetAdapterBinding -Name "*" -ComponentID ms_server >nul 2>&1
powershell Disable-NetAdapterBinding -Name "*" -ComponentID ms_lldp >nul 2>&1
powershell Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6 >nul 2>&1
PowerShell Disable-NetAdapterBinding -Name "*" -ComponentID ms_rspndr >nul 2>&1
powershell Disable-NetAdapterBinding -Name "*" -ComponentID ms_lltdio >nul 2>&1
wmic /interactive:off nicconfig where TcpipNetbiosOptions=0 call SetTcpipNetbios 2 >nul 2>&1
wmic /interactive:off nicconfig where TcpipNetbiosOptions=1 call SetTcpipNetbios 2 >nul 2>&1
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0000" /v "*ReceiveBuffers" /t REG_SZ /d "1024" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0000" /v "*TransmitBuffers" /t REG_SZ /d "1024" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0000" /v "*JumboPacket" /t REG_SZ /d "1514" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0000" /v "*LsoV2IPv4" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0000" /v "*LsoV2IPv6" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0000" /v "*TCPChecksumOffloadIPv6" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0000" /v "*UDPChecksumOffloadIPv6" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0000" /v "*WakeOnPattern" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0000" /v "*WakeOnMagicPacket" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0000" /v "S5WakeOnLan" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0000" /v "PowerDownPll" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0000" /v "*EEE" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0000" /v "EnableGreenEthernet" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0000" /v "PowerSavingMode" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0000" /v "GigaLite" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0000" /v "EnableSavePowerNow" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0000" /v "AutoPowerSaveModeEnabled" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0000" /v "PnPCapabilities" /t REG_SZ /d "24" /f >nul 2>&1
for /f "tokens=3*" %%i in ('reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards" /f "Name" /s^|findstr /i /l "Name"') do (
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpAckFrequency" /d "1" /t REG_DWORD /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpDelAckTicks" /d "0" /t REG_DWORD /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TCPNoDelay" /d "1" /t REG_DWORD /f
) >nul 2>&1
reg.exe delete "HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /f >nul 2>&1
reg.exe add "HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /f >nul 2>&1
fsutil behavior set disable8dot3 1 >nul 2>&1
fsutil behavior set disablelastaccess 1 >nul 2>&1
fsutil behavior set disabledeletenotify 0 >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\wuauserv" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\InstallService" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\BITS" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f >nul 2>&1
netsh advfirewall firewall set rule group="Remote Assistance" new enable=no >nul 2>&1
PowerShell "Disable-MMAgent -MemoryCompression" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" >nul 2>nul
schtasks /Change /Disable /TN "\Microsoft\Windows\Application Experience\StartupAppTask" >nul 2>nul
schtasks /Change /Disable /TN "\Microsoft\Windows\ApplicationData\DsSvcCleanup" >nul 2>nul
schtasks /Change /Disable /TN "\Microsoft\Windows\Autochk\Proxy" >nul 2>nul
schtasks /Change /Disable /TN "\Microsoft\Windows\BrokerInfrastructure\BgTaskRegistrationMaintenanceTask" >nul 2>nul
schtasks /Change /Disable /TN "\Microsoft\Windows\Chkdsk\ProactiveScan" >nul 2>nul
schtasks /Change /Disable /TN "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask" >nul 2>nul
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
schtasks /Change /Disable /TN "\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\Time Synchronization\SynchronizeTime" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\Time Zone\SynchronizeTimeZone" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\WindowsUpdate\Scheduled Start" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\Wininet\CacheTask" >nul 2>&1
for /f "tokens=2 delims==" %%i in ('wmic os get TotalVisibleMemorySize /value') do set /a memory=%%i + 1000000 >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "%memory%" /f >nul 2>&1
powershell "Get-PnpDevice -FriendlyName *'SM Bus Controller'* | Disable-PnpDevice -Confirm:$False" >nul 2>&1
powershell "Get-PnpDevice -FriendlyName *'Microsoft GS Wavetable Synth'* | Disable-PnpDevice -Confirm:$False" >nul 2>&1
powershell "Get-PnpDevice -FriendlyName *'Composite Bus Enumerator'* | Disable-PnpDevice -Confirm:$False" >nul 2>&1
powershell "Get-PnpDevice -FriendlyName *'High precision event timer'* | Disable-PnpDevice -Confirm:$False" >nul 2>&1
powershell "Get-PnpDevice -FriendlyName *'Microsoft Virtual Drive Enumerator'* | Disable-PnpDevice -Confirm:$False" >nul 2>&1
powershell "Get-PnpDevice -FriendlyName *'NDIS Virtual Network Adapter Enumerator'* | Disable-PnpDevice -Confirm:$False" >nul 2>&1
powershell "Get-PnpDevice -FriendlyName *'Programmable interrupt controller'* | Disable-PnpDevice -Confirm:$False" >nul 2>&1
powershell "Get-PnpDevice -FriendlyName *'System timer'* | Disable-PnpDevice -Confirm:$False" >nul 2>&1
powershell "Get-PnpDevice -FriendlyName *'UMBus Root Bus Enumerator'* | Disable-PnpDevice -Confirm:$False" >nul 2>&1
powershell "Get-PnpDevice -FriendlyName *'Numeric data processor'* | Disable-PnpDevice -Confirm:$False" >nul 2>&1
powershell "Get-PnpDevice -FriendlyName *'PCI Simple Communications Controller'* | Disable-PnpDevice -Confirm:$False" >nul 2>&1
powershell "Get-PnpDevice -FriendlyName *'PCI Memory Controller'* | Disable-PnpDevice -Confirm:$False" >nul 2>&1
powershell "Get-PnpDevice -FriendlyName *'PCI Data Acquisition and Signal Processing Controller'* | Disable-PnpDevice -Confirm:$False" >nul 2>&1
powercfg -import "C:\ProgramData\OwlOS\owlos.pow" 99999999-9999-9999-9999-999999999999 >nul 2>&1
powercfg -setactive 99999999-9999-9999-9999-999999999999 >nul 2>&1
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
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationOptions" /t REG_BINARY /d "222222222222222222222222222222222222222222222222" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationAuditOptions" /t REG_BINARY /d "222222222222222222222222222222222222222222222222" /f >nul 2>&1
Reg.exe add "HKCU\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d "9012038010000000" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d "3" /f >nul 2>&1
Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewAlphaSelect" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconsOnly" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\CTF\LangBar" /v "ShowStatus" /t REG_DWORD /d "3" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Accent" /v "AccentPalette" /t REG_BINARY /d "9b9a9900848381006d6b6a004c4a4800363533002625240019191900107c1000" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Accent" /v "AccentColorMenu" /t REG_DWORD /d "4282927692" /f >nul 2>&1
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
PowerShell -File "C:\ProgramData\OwlOS\sound scheme.ps1" >nul 2>&1
PowerShell -File "C:\ProgramData\OwlOS\uninstall microsoft store.ps1" >nul 2>&1
PowerShell -File "C:\ProgramData\OwlOS\usb power managment.ps1" >nul 2>&1
taskkill /F /IM explorer.exe >nul 2>&1
shutdown -r -t 5 /c "Restarting"
DEL "%~f0"