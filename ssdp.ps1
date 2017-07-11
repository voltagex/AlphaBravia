#thanks https://chickenshell.blogspot.com.au/2015/02/roku-controls-with-powershell.html

Function Discover-SonyDevices($Port){
    #Use unused port or it will fail
    $LocalEndPoint = New-Object System.Net.IPEndPoint([ipaddress]::Parse("0.0.0.0"),$Port)

    $MulticastEndPoint = New-Object System.Net.IPEndPoint([ipaddress]::Parse("239.255.255.250"),1900)

    $UDPSocket = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork,[System.Net.Sockets.SocketType]::Dgram,[System.Net.Sockets.ProtocolType]::Udp)

    $UDPSocket.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket, [System.Net.Sockets.SocketOptionName]::ReuseAddress,$true)

    $UDPSocket.Bind($LocalEndPoint)

    $UDPSocket.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::IP,[System.Net.Sockets.SocketOptionName]::AddMembership, (New-Object System.Net.Sockets.MulticastOption($MulticastEndPoint.Address, [ipaddress]::Any)))
    $UDPSocket.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::IP, [System.Net.Sockets.SocketOptionName]::MulticastTimeToLive, 2)
    $UDPSocket.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::IP, [System.Net.Sockets.SocketOptionName]::MulticastLoopback, $true)

    #Write-Host "UDP-Socket setup done...`r`n"
    #All SSDP Search
    $SearchString = "M-SEARCH * HTTP/1.1`r`nHOST:239.255.255.250:1900`r`nMAN:`"ssdp:discover`"`r`nST:ssdp:all`r`nMX:3`r`n`r`n"
	

    $UDPSocket.SendTo([System.Text.Encoding]::UTF8.GetBytes($SearchString), [System.Net.Sockets.SocketFlags]::None, $MulticastEndPoint) | Out-Null

    #Write-Host "M-Search sent...`r`n"

    [byte[]]$RecieveBuffer = New-Object byte[] 64000

    [int]$RecieveBytes = 0

    $Response_RAW = ""
    $Timer = [System.Diagnostics.Stopwatch]::StartNew()
    $Delay = $True
    while($Delay){
        #15 Second delay so it does not run forever
        if($Timer.Elapsed.TotalSeconds -ge 5){Remove-Variable Timer; $Delay = $false}
        if($UDPSocket.Available -gt 0){
            $RecieveBytes = $UDPSocket.Receive($RecieveBuffer, [System.Net.Sockets.SocketFlags]::None)

            if($RecieveBytes -gt 0){
                $Text = "$([System.Text.Encoding]::UTF8.GetString($RecieveBuffer, 0, $RecieveBytes))"
                $Response_RAW += $Text
            }
        }
    }
	
    $Sony = [regex]::Matches($ssdp,'HTTP/1.1 200 OK.+LOCATION: http://(.+?)\:.+Sony Corporation.+').Groups[1]
    #[regex]::Matches($Rokus, "(\d{1,3}\.)(\d{1,3}\.?){3}") | select -ExpandProperty value
    return $Sony
}

write-host (Discover-SonyDevices 57600)