@echo off
::Running script as administrator
>nul 2>&1 reg.exe query "HKU\S-1-5-19" || (
    echo set UAC = CreateObject^("Shell.Application"^) > "%temp%\Getadmin.vbs"
    echo UAC.ShellExecute "%~f0", "%1", "", "runas", 1 >> "%temp%\Getadmin.vbs"
    "%temp%\Getadmin.vbs"
    DEL /f /q "%temp%\Getadmin.vbs" >nul 2>&1
    exit /b
)

echo Installing Microsoft Store...
echo.

powershell -command "Get-AppxPackage -AllUsers | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register \"$($_.InstallLocation)\AppXManifest.xml\"}" >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\UsoSvc" /v "Start" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\wuauserv" /v "Start" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\BITS" /v "Start" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PushToInstall" /v "Start" /t REG_DWORD /d "3" /f

echo.
echo Micrososft Store Installed, Reboot Computer for Apply Changes.

pause
