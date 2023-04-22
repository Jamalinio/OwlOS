#disable network adapters
Disable-NetAdapterBinding -Name "*" -ComponentID ms_msclient
Disable-NetAdapterBinding -Name "*" -ComponentID ms_server
Disable-NetAdapterBinding -Name "*" -ComponentID ms_lldp
Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6
Disable-NetAdapterBinding -Name "*" -ComponentID ms_rspndr
Disable-NetAdapterBinding -Name "*" -ComponentID ms_lltdio

#disable netbios over tcpip
wmic /interactive:off nicconfig where TcpipNetbiosOptions=0 call SetTcpipNetbios 2
wmic /interactive:off nicconfig where TcpipNetbiosOptions=1 call SetTcpipNetbios 2

#advanced section
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
