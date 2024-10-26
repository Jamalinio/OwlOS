$Path = "HKCU:\AppEvents\Schemes"
$Keyname = "(Default)"
$SetValue = ".None"
$TestPath = Test-Path $Path
if (-Not($TestPath -eq $True)) {
   New-item $path -force
}
if (Get-ItemProperty -path $Path -name $KeyName -EA SilentlyContinue) {
   $Keyvalue = (Get-ItemProperty -path $Path).$keyname
   if ($KeyValue -eq $setValue) {
   }
   else {
       New-itemProperty -path $Path -Name $keyname -value $SetValue -force # Set 'No Sound' Schemes
       Get-ChildItem -Path "HKCU:\AppEvents\Schemes\Apps" | # Apply 'No Sound' Schemes
        Get-ChildItem |
        Get-ChildItem |
        Where-Object { $_.PSChildName -eq ".Current" } |
        Set-ItemProperty -Name "(Default)" -Value ""
   }
}
else {
   New-itemProperty -path $Path -Name $keyname -value $SetValue -force
   Get-ChildItem -Path "HKCU:\AppEvents\Schemes\Apps" |
       Get-ChildItem |
       Get-ChildItem |
       Where-Object { $_.PSChildName -eq ".Current" } |
       Set-ItemProperty -Name "(Default)" -Value ""
}

Set-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name DisableStartupSound -Value 1 -Force