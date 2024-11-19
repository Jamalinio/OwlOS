@echo off
::Running script as administrator
>nul 2>&1 reg.exe query "HKU\S-1-5-19" || (
    echo set UAC = CreateObject^("Shell.Application"^) > "%temp%\Getadmin.vbs"
    echo UAC.ShellExecute "%~f0", "%1", "", "runas", 1 >> "%temp%\Getadmin.vbs"
    "%temp%\Getadmin.vbs"
    DEL /f /q "%temp%\Getadmin.vbs" >nul 2>&1
    exit /b
)

echo Disabling Remote Desktop Connection...
echo.

Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\TermService" /v "Start" /t REG_DWORD /d "4" /f
Powershell "Get-PnpDevice -FriendlyName *'Remote Desktop Device Redirector Bus'* | Disable-PnpDevice -Confirm:$False"
echo 'Remote Desktop Device Redirector Bus' Device Has Been Disabled

echo.
echo Remote Desktop Connection Disabled, Reboot Computer for Apply Changes.

pause