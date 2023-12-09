#disabling devices
Get-PnpDevice -FriendlyName *'SM Bus Controller'* | Disable-PnpDevice -Confirm:$False
Get-PnpDevice -FriendlyName *'Microsoft GS Wavetable Synth'* | Disable-PnpDevice -Confirm:$False
Get-PnpDevice -FriendlyName *'Composite Bus Enumerator'* | Disable-PnpDevice -Confirm:$False
Get-PnpDevice -FriendlyName *'High precision event timer'* | Disable-PnpDevice -Confirm:$False
Get-PnpDevice -FriendlyName *'Microsoft Virtual Drive Enumerator'* | Disable-PnpDevice -Confirm:$False
Get-PnpDevice -FriendlyName *'NDIS Virtual Network Adapter Enumerator'* | Disable-PnpDevice -Confirm:$False
Get-PnpDevice -FriendlyName *'Remote Desktop Device Redirector Bus'* | Disable-PnpDevice -Confirm:$False
Get-PnpDevice -FriendlyName *'Programmable interrupt controller'* | Disable-PnpDevice -Confirm:$False
Get-PnpDevice -FriendlyName *'System timer'* | Disable-PnpDevice -Confirm:$False
Get-PnpDevice -FriendlyName *'UMBus Root Bus Enumerator'* | Disable-PnpDevice -Confirm:$False
Get-PnpDevice -FriendlyName *'Numeric data processor'* | Disable-PnpDevice -Confirm:$False
Get-PnpDevice -FriendlyName *'PCI Simple Communications Controller'* | Disable-PnpDevice -Confirm:$False
Get-PnpDevice -FriendlyName *'PCI Memory Controller'* | Disable-PnpDevice -Confirm:$False
Get-PnpDevice -FriendlyName *'PCI Data Acquisition and Signal Processing Controller'* | Disable-PnpDevice -Confirm:$False

#disabling network adapters
Disable-NetAdapterBinding -Name "*" -ComponentID ms_msclient
Disable-NetAdapterBinding -Name "*" -ComponentID ms_server
Disable-NetAdapterBinding -Name "*" -ComponentID ms_lldp
Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6
Disable-NetAdapterBinding -Name "*" -ComponentID ms_rspndr
Disable-NetAdapterBinding -Name "*" -ComponentID ms_lltdio

#disabling netbios over tcpip
wmic /interactive:off nicconfig where TcpipNetbiosOptions=0 call SetTcpipNetbios 2
wmic /interactive:off nicconfig where TcpipNetbiosOptions=1 call SetTcpipNetbios 2

#setting up advanced section
Set-NetAdapterAdvancedProperty -Name "*" -DisplayName "Advanced EEE" -DisplayValue "Disabled"
Set-NetAdapterAdvancedProperty -Name "*" -DisplayName "Energy-Efficient Ethernet" -DisplayValue "Disabled"
Set-NetAdapterAdvancedProperty -Name "*" -DisplayName "Gigabit Lite" -DisplayValue "Disabled"
Set-NetAdapterAdvancedProperty -Name "*" -DisplayName "Green Ethernet" -DisplayValue "Disabled"
Set-NetAdapterAdvancedProperty -Name "*" -DisplayName "Jumbo Frame" -DisplayValue "Disabled"
Set-NetAdapterAdvancedProperty -Name "*" -DisplayName "Large Send Offload V2 (IPv4)" -DisplayValue "Disabled"
Set-NetAdapterAdvancedProperty -Name "*" -DisplayName "Large Send Offload V2 (IPv6)" -DisplayValue "Disabled"
Set-NetAdapterAdvancedProperty -Name "*" -DisplayName "Power Saving Mode" -DisplayValue "Disabled"
Set-NetAdapterAdvancedProperty -Name "*" -DisplayName "Shutdown Wake-On-Lan" -DisplayValue "Disabled"
Set-NetAdapterAdvancedProperty -Name "*" -DisplayName "UDP Checksum Offload (IPv6)" -DisplayValue "Disabled"
Set-NetAdapterAdvancedProperty -Name "*" -DisplayName "Wake on Magic Packet" -DisplayValue "Disabled"
Set-NetAdapterAdvancedProperty -Name "*" -DisplayName "Wake on pattern match" -DisplayValue "Disabled"
Set-NetAdapterAdvancedProperty -Name "*" -DisplayName "Power Saving Mode" -DisplayValue "Disabled"
Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0000" -Name "*ReceiveBuffers" -Value 1024
Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0000" -Name "*TransmitBuffers" -Value 1024
Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0000" -Name "PnPCapabilities" -Value 24

#disabling usb power managment
$power_device_enable = Get-WmiObject MSPower_DeviceEnable -Namespace root\wmi
$usb_devices = @("Win32_USBController", "Win32_USBControllerDevice", "Win32_USBHub")

foreach ($power_device in $power_device_enable) {
    $instance_name = $power_device.InstanceName.ToUpper()
    foreach ($device in $usb_devices) {
        foreach ($hub in Get-WmiObject $device) {
            $pnp_id = $hub.PNPDeviceID
            if ($instance_name -like "*$pnp_id*"){
                $power_device.enable = $False
                $power_device.psbase.put()
            }
        }
    }
}

#uninstalling microsoft store
Get-AppxPackage *windowsstore* | Remove-AppxPackage

#setting up sound scheme
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


