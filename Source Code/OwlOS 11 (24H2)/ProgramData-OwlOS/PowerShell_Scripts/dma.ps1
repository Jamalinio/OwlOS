$regPath1 = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\DmaGuard"
$propertyName1 = "DeviceEnumerationPolicy"
if (-not (Test-Path $regPath1)) {
    New-Item -Path $regPath1 -Force
}
Set-ItemProperty -Path $regPath1 -Name $propertyName1 -Value 2 -PropertyType DWord -Force
$servicesPath = "HKLM:\SYSTEM\CurrentControlSet\Services"
$propertyName2 = "DmaRemappingCompatible"
$serviceKeys = Get-ChildItem -Path $servicesPath -Recurse |
               Where-Object { Get-ItemProperty -Path $_.PSPath -Name $propertyName2 -ErrorAction SilentlyContinue } 
foreach ($key in $serviceKeys) {
    Set-ItemProperty -Path $key.PSPath -Name $propertyName2 -Value 0 -PropertyType DWord -Force
}