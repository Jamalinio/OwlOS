@echo off
::Running script as administrator
>nul 2>&1 reg.exe query "HKU\S-1-5-19" || (
    echo set UAC = CreateObject^("Shell.Application"^) > "%temp%\Getadmin.vbs"
    echo UAC.ShellExecute "%~f0", "%1", "", "runas", 1 >> "%temp%\Getadmin.vbs"
    "%temp%\Getadmin.vbs"
    DEL /f /q "%temp%\Getadmin.vbs" >nul 2>&1
    exit /b
)

echo Enabling Data Execution Prevention...
echo.

bcdedit /set nx optin

echo.
echo Data Execution Prevention Enabled, Reboot Computer for Apply Changes.

pause