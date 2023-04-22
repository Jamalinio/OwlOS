Write-Host "`nSetting Sound Schemes to 'No Sound' .." -foregroundcolor Gray 

$Path = "HKCU:\AppEvents\Schemes"

$Keyname = "(Default)"

$SetValue = ".None"

$TestPath = Test-Path $Path
if (-Not($TestPath -eq $True)) {
    Write-Host " Creating Folder.. " -foregroundcolor Gray 
    New-item $path -force
} 
 
if (Get-ItemProperty -path $Path -name $KeyName -EA SilentlyContinue) {
  
    $Keyvalue = (Get-ItemProperty -path $Path).$keyname  
  
    if ($KeyValue -eq $setValue) {
 
        Write-Host " The Registry Key Already Exists. " -foregroundcolor green 
 
 
    }
    else {
 
        Write-Host " Changing Key Value.. " -foregroundcolor Gray 
 
        New-itemProperty -path $Path -Name $keyname -value $SetValue -force # Set 'No Sound' Schemes
        Get-ChildItem -Path "HKCU:\AppEvents\Schemes\Apps" | # Apply 'No Sound' Schemes
         Get-ChildItem | 
         Get-ChildItem | 
         Where-Object { $_.PSChildName -eq ".Current" } | 
         Set-ItemProperty -Name "(Default)" -Value ""
 
        Write-Host " The Registry Key Value Changed Sucessfully. " -foregroundcolor green 
    }
 
}
else {
  
    Write-Host " Creating Registry Key.. " -foregroundcolor Gray 
   
    New-itemProperty -path $Path -Name $keyname -value $SetValue -force
    Get-ChildItem -Path "HKCU:\AppEvents\Schemes\Apps" | 
        Get-ChildItem | 
        Get-ChildItem | 
        Where-Object { $_.PSChildName -eq ".Current" } | 
        Set-ItemProperty -Name "(Default)" -Value ""

  
    Write-Host " The Registry Key Created Sucessfully. " -foregroundcolor green 
}