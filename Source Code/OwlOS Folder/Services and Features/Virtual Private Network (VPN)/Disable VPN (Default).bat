@echo off
::Running script as administrator
>nul 2>&1 reg.exe query "HKU\S-1-5-19" || (
    echo set UAC = CreateObject^("Shell.Application"^) > "%temp%\Getadmin.vbs"
    echo UAC.ShellExecute "%~f0", "%1", "", "runas", 1 >> "%temp%\Getadmin.vbs"
    "%temp%\Getadmin.vbs"
    DEL /f /q "%temp%\Getadmin.vbs" >nul 2>&1
    exit /b
)

echo Disabling VPN...
echo.

Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\RasMan" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PptpMiniport" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\RasAgileVpn" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Rasl2tp" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\RasSstp" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\RasPppoe" /v "Start" /t REG_DWORD /d "4" /f

echo.
echo VPN Disabled, Reboot Computer for Apply Changes.

pause