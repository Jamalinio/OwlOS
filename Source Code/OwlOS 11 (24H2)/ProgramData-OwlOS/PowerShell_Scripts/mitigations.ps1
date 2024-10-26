function Disable-AllProcessMitigations {
    $command = Get-Command Set-ProcessMitigation
    $disableValues = $command.Parameters["Disable"].Attributes.ValidValues
    foreach ($value in $disableValues) {
        Try {
            Set-ProcessMitigation -SYSTEM -Disable $value -ErrorAction Stop
        } Catch {
        }
    }
}
Disable-AllProcessMitigations
function Get-MitigationAuditMask {
    $kernelKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
    Try {
        $mask = (Get-ItemProperty -Path $kernelKey -Name "MitigationAuditOptions").MitigationAuditOptions
        return $mask
    } Catch {
        Write-Error "Unable to retrieve value from registry"
        return ""
    }
}
function Convert-MitigationMask {
    param(
        [string]$mask
    )

    return ($mask -replace '[0-9]', '2')
}
function Set-ProcessMitigationOptions {
    param(
        [string]$processName,
        [string]$mitigationMask
    )

    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$processName"

    New-Item -Path $regPath -Force | Out-Null
    Set-ItemProperty -Path $regPath -Name "MitigationOptions" -Value ([byte[]][convert]::FromBase64String($mitigationMask)) -Force
    Set-ItemProperty -Path $regPath -Name "MitigationAuditOptions" -Value ([byte[]][convert]::FromBase64String($mitigationMask)) -Force
}
$mitigationMask = Get-MitigationAuditMask
$convertedMask = Convert-MitigationMask -mask $mitigationMask
$systemProcesses = @(
    "csrss.exe",
    "svchost.exe",
    "dwm.exe",
    "services.exe"
    "winlogon.exe",
    "ntoskrnl.exe",
    "lsass.exe",
)
foreach ($process in $systemProcesses) {
    Set-ProcessMitigationOptions -processName $process -mitigationMask $convertedMask
}
function Set-KernelMitigationOptions {
    param(
        [string]$mitigationMask
    )

    $kernelPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"

    Set-ItemProperty -Path $kernelPath -Name "MitigationOptions" -Value ([byte[]][convert]::FromBase64String($mitigationMask)) -Force
    Set-ItemProperty -Path $kernelPath -Name "MitigationAuditOptions" -Value ([byte[]][convert]::FromBase64String($mitigationMask)) -Force
}
Set-KernelMitigationOptions -mitigationMask $convertedMask