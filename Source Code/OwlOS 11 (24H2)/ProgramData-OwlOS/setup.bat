@echo off
@title "OwlOS 11 (24H2) v0.3"
SETLOCAL EnableDelayedExpansion
taskkill /f /im explorer.exe >nul 2>&1
::Running script as administrator
>nul 2>&1 reg.exe query "HKU\S-1-5-19" || (
    echo set UAC = CreateObject^("Shell.Application"^) > "%temp%\Getadmin.vbs"
    echo UAC.ShellExecute "%~f0", "%1", "", "runas", 1 >> "%temp%\Getadmin.vbs"
    "%temp%\Getadmin.vbs"
    DEL /f /q "%temp%\Getadmin.vbs" >nul 2>&1
    exit /b
)

echo INSTALLING VCRedist x64, x86 (It can take a while)
start /b /wait C:\ProgramData\OwlOS\VCRedist\VC_redist.x64.exe /q /norestart >nul 2>&1
start /b /wait C:\ProgramData\OwlOS\VCRedist\VC_redist.x86.exe /q /norestart >nul 2>&1
cls

echo CONFIGURING BCDEdit
::This command disables the dynamic ticking of the system clock, which stabilizes its frequency.
bcdedit /set disabledynamictick yes >nul 2>&1

::Disables NX (No-Execute) function, which protects against executing unauthorized code in memory.
::Disabling this feature may improve performance and compatibility with some older programs, but reduces system security. 
bcdedit /set nx alwaysoff >nul 2>&1

::Disables hypervisor at system startup.
::This may improve performance and compatibility with other virtualization programs that are not compatible with Hyper-V.
bcdedit /set hypervisorlaunchtype off >nul 2>&1

::These commands change the global Windows boot settings by adding custom parameters.
::They can improve system performance or adapt the boot process to specific hardware or environments.
bcdedit /set {globalsettings} custom:16000067 true >nul 2>&1
bcdedit /set {globalsettings} custom:16000068 true >nul 2>&1
bcdedit /set {globalsettings} custom:16000069 true >nul 2>&1

::These commands edit windows boot settings
::Changes the appearance of the boot menu, time to selection and sets a custom name.
bcdedit /set bootmenupolicy legacy >nul 2>&1
bcdedit /timeout 10 >nul 2>&1
bcdedit /set {current} description "OwlOS 11 (24H2)" >nul 2>&1
timeout /t 2 /nobreak >nul 2>&1
cls

echo CONFIGURING FSUTIL BEHAVIORS
::Disables the creation of short file names. Increasing system performance.
fsutil behavior set disable8dot3 1 >nul 2>&1

::Disabling file access indexing. Increasing system performance.
fsutil behavior set disablelastaccess 1 >nul 2>&1

::Enabling TRIM. Improves write and read performance and overall drive speed on SSD.
fsutil behavior set disabledeletenotify 0 >nul 2>&1
timeout /t 2 /nobreak >nul 2>&1
cls

echo CONFIGURING SVCHOST BEHAVIORS
::This command increases the amount of memory available to svchost.exe processes by modifying the SvcHostSplitThresholdInKB registry key.
::This will result in fewer processes running in separate instances, which can reduce overall system resource usage and improve performance on computers with a lot of RAM.
for /f "tokens=2 delims==" %%i in ('wmic os get TotalVisibleMemorySize /value') do set /a memory=%%i + 1000000 >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "%memory%" /f >nul 2>&1
cls

echo CONFIGURING ALGORITHM NAGLE's
::This command modifies TCP/IP settings.
::Benefits include increased responsiveness and reduced latency in low-latency applications such as online gaming.
for /f "tokens=3*" %%i in ('reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards" /f "Name" /s^|findstr /i /l "Name"') do (
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpAckFrequency" /d "1" /t REG_DWORD /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpDelAckTicks" /d "0" /t REG_DWORD /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TCPNoDelay" /d "1" /t REG_DWORD /f
) >nul 2>&1
timeout /t 2 /nobreak >nul 2>&1
cls

echo OPTIMIZING NETWORK SETTINGS
powershell -command "(New-Object -ComObject Shell.Application).MinimizeAll()" >nul 2>&1
powershell -ExecutionPolicy Bypass -File C:\ProgramData\OwlOS\PowerShell_Scripts\network.ps1 >nul 2>&1
cls

echo DISABLING PROCESS MITIGATIONS
::Disables process security measures designed to protect the system against various types of attacks, such as malware and exploits.
::Disabling these mitigations can improve application performance, especially in high-demand environments such as games or resource-intensive applications.
powershell -command "(New-Object -ComObject Shell.Application).MinimizeAll()" >nul 2>&1
powershell -ExecutionPolicy Bypass -File C:\ProgramData\OwlOS\PowerShell_Scripts\mitigations.ps1 >nul 2>&1
cls

echo DISABLING DEVICES
powershell -command "(New-Object -ComObject Shell.Application).MinimizeAll()" >nul 2>&1
powershell -ExecutionPolicy Bypass -File C:\ProgramData\OwlOS\PowerShell_Scripts\devices.ps1 >nul 2>&1
cls

echo DISABLING SCHEDULED TASKS
schtasks /Change /Disable /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser Exp" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\Application Experience\StartupAppTask" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\ApplicationData\CleanupTemporaryState" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\ApplicationData\DsSvcCleanup" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\Autochk\Proxy" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\BrokerInfrastructure\BgTaskRegistrationMaintenanceTask" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\Chkdsk\ProactiveScan" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\CloudRestore\Restore" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\Data Integrity Scan\Data Integrity Check And Scan" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\Data Integrity Scan\Data Integrity Scan" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\Data Integrity Scan\Data Integrity Scan for Crash Recovery" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\Defrag\ScheduledDefrag" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\Diagnosis\Scheduled" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\DiskFootprint\StorageSense" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\DiskFootprint\Diagnostics" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\Feedback\Siuf\DmClient" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\FileHistory\File History (maintenance mode)" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\InstallService\ScanForUpdates" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\InstallService\ScanForUpdatesAsUser" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\InstallService\WakeUpAndContinueUpdates" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\InstallService\WakeUpAndScanForUpdates" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\Maintenance\WinSAT" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\NlaSvc\WiFiTask" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\PerformanceTrace\RequestTrace" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\Servicing\StartComponentCleanup" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\Speech\SpeechModelDownloadTask" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\StateRepository\MaintenanceTasks" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\Time Synchronization\SynchronizeTime" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\Time Zone\SynchronizeTimeZone" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\USB\Usb-Notifications" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\WDI\ResolutionHost" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\Windows Defender\Windows Defender Verification" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\Windows Error Reporting\QueueReporting" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\WindowsUpdate\Scheduled Start" >nul 2>&1
schtasks /Change /Disable /TN "\Microsoft\Windows\Wininet\CacheTask" >nul 2>&1
timeout /t 2 /nobreak >nul 2>&1
cls

echo DISABLING POWER-SAVING FEATURES
::By amit.
::This part of script disable useless power-saving features in windows.
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
) do for /f "delims=" %%b in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum" /s /f "%%a" ^| findstr "HKEY"') do Reg.exe add "%%b" /v "%%a" /t REG_DWORD /d "0" /f >nul 2>&1
for /f "tokens=*" %%i in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum\PCI"^| findstr "HKEY"') do (
			for /f "tokens=*" %%a in ('reg query "%%i"^| findstr "HKEY"') do Reg.exe delete "%%a\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >nul 2>&1
		) >nul 2>&1
) >nul 2>&1
timeout /t 2 /nobreak >nul 2>&1
cls

echo DISABLING USB CONTROLLER's AND HUB's POWER-SAVING
powershell -command "(New-Object -ComObject Shell.Application).MinimizeAll()" >nul 2>&1
powershell -ExecutionPolicy Bypass -File C:\ProgramData\OwlOS\PowerShell_Scripts\usb.ps1 >nul 2>&1
cls

echo DISABLING DMA REMAPPING
::Disables memory address mapping for devices using DMA (Direct Memory Access).
::Disabling this feature can improve data transfer performance by reducing latency and simplifying the memory model.
powershell -command "(New-Object -ComObject Shell.Application).MinimizeAll()" >nul 2>&1
powershell -ExecutionPolicy Bypass -File C:\ProgramData\OwlOS\PowerShell_Scripts\dma.ps1 >nul 2>&1
cls

echo BLOCKING TELEMETRY
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\ClientTelemetry" /v "IsCensusDisabled" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\ClientTelemetry" /v "DontRetryOnError" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\ClientTelemetry" /v "TaskEnableRun" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f >nul 2>&1
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" /v "NoExplicitFeedback" /t REG_DWORD /d "1" /f >nul 2>&1
::Disable windows media player tracking
Reg.exe add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "UsageTracking" /t REG_DWORD /d "0" /f >nul 2>&1
timeout /t 2 /nobreak >nul 2>&1
cls

echo REMOVING FIREWALL RULES
::These commands remove all firewall rules from the registry and then add a new, default rule.
::Benefits include resolving network connection issues and restoring the correct firewall configuration.
Reg.exe delete "HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /f >nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /f >nul 2>&1
timeout /t 2 /nobreak >nul 2>&1
cls

echo CONFIGURING SOUND SETTINGS
::Setting sound scheme to "No Sounds"
::Disabling windows startup song
powershell -command "(New-Object -ComObject Shell.Application).MinimizeAll()" >nul 2>&1
powershell -ExecutionPolicy Bypass -File C:\ProgramData\OwlOS\PowerShell_Scripts\sounds.ps1 >nul 2>&1
cls

echo IMPORTING AND SETTING AS ACTIVE CUSTOM "OwlOS" POWER PLAN
powercfg -import "C:\ProgramData\OwlOS\owlos.pow" 99999999-9999-9999-9999-999999999999 >nul 2>&1
powercfg -setactive 99999999-9999-9999-9999-999999999999 >nul 2>&1
timeout /t 2 /nobreak >nul 2>&1
cls

echo CONFIGURING SYSTEM VISUAL SETTINGS
Reg.exe add "HKCU\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d "9012038010000000" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d "3" /f >nul 2>&1
Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewAlphaSelect" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconsOnly" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Accent" /v "AccentPalette" /t REG_BINARY /d  "9b9a9900848381006d6b6a004c4a4800363533002625240019191900107c1000" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Accent" /v "AccentColorMenu" /t REG_DWORD /d "4282927692" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t "REG_DWORD" /d "100" /f >nul 2>&1
timeout /t 2 /nobreak >nul 2>&1
cls

echo ENABLING LEGACY PHOTO VIEWER
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
timeout /t 2 /nobreak >nul 2>&1
cls

::other
echo FINISHING...
powershell "Get-AppxPackage *windowsstore* | Remove-AppxPackage" >nul 2>&1
powershell "Get-AppxPackage | Where-Object {$_.Name -Like '*Microsoft.Copilot*'} | Remove-AppxPackage -ErrorAction Continue" >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdate" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdatem" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\wuauserv" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\BITS" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "AllowAutoWindowsUpdateDownloadOverMeteredNetwork" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "IsContinuousInnovationOptedIn" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "FlightSettingsMaxPauseDays" /t REG_DWORD /d "1460" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "PauseFeatureUpdatesStartTime" /t REG_SZ /d "2024-10-01T20:00:00Z" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "PauseQualityUpdatesStartTime" /t REG_SZ /d "2024-10-01T20:00:00Z" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "PauseFeatureUpdatesEndTime" /t REG_SZ /d "2028-08-03T20:00:00Z" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "PauseQualityUpdatesEndTime" /t REG_SZ /d "2028-08-03T20:00:00Z" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "PauseUpdatesExpiryTime" /t REG_SZ /d "2028-08-03T20:00:00Z" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "PauseUpdatesStartTime" /t REG_SZ /d "2024-10-01T20:00:00Z" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "AllowMUUpdateService" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /v "AutoDownload" /t REG_DWORD /d "2" /f >nul 2>&1
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "NoPinningStoreToTaskbar" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" /f >nul 2>&1
Reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SystemSettings\AccountNotifications" /v "EnableAccountNotifications" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" /ve /t REG_SZ /d "" /f >nul 2>&1
Reg.exe add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /ve /t REG_SZ /d "" /f >nul 2>&1
powershell -command "(New-Object -ComObject Shell.Application).MinimizeAll()" >nul 2>&1
powershell -ExecutionPolicy Bypass -File C:\ProgramData\OwlOS\PowerShell_Scripts\wallpaper.ps1 >nul 2>&1
rmdir /S /Q C:\ProgramData\OwlOS >nul 2>&1
rmdir /S /Q C:\Windows.old >nul 2>&1
del /q/f/s %TEMP%\* >nul 2>&1
cls

shutdown -r -t 5 /c "Restarting..."
DEL "%~f0"
