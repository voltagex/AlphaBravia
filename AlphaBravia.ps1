$Global:PacketCounter = 1
$Script:BraviaConfig = @{}

function Get-TVAddress {
Param([Parameter(Mandatory=$true, HelpMessage='Address or hostname of TV')][String]$Address)
   Update-Configuration -Name "Address" -Value $Address
}


function Get-ConfigurationPath {
    return Join-Path $env:LocalAppData -ChildPath AlphaBravia
}

function Create-ConfigurationPath {
    mkdir -Force -Path (Get-ConfigurationPath)
}

function Update-Configuration {
    Param(
    [Parameter(Mandatory=$true)]
    [String]$Name,
    [Parameter(Mandatory=$true)]
    $Value
    )
    
    $Script:BraviaConfigPath = (Join-Path (Get-ConfigurationPath) -ChildPath "config.json")
    $Script:BraviaConfig | Add-Member -MemberType NoteProperty $Name $Value -Force
    $Script:BraviaConfig | convertto-json | out-file $Script:BraviaConfigPath
}

function Reload-Configuration {
    $Script:BraviaConfig = Get-Content $Script:BraviaConfigPath | ConvertFrom-Json
    return $Script:BraviaConfig

}

function Get-ModuleConfiguration {
    Create-ConfigurationPath | Out-Null
    $Script:BraviaConfigPath = (Join-Path (Get-ConfigurationPath) -ChildPath "config.json")
    if (!(Test-Path $Script:BraviaConfigPath)) {
        Set-Content $Script:BraviaConfigPath "{}"
        Write-Output "Module not configured, running first time setup"
        Get-TVAddress
        Start-BraviaRegistration
    }

    Reload-Configuration | Out-Null

    if ($Script:BraviaConfig.Auth -eq $null) {
        Start-BraviaRegistration
    }

    Reload-Configuration | Out-Null

    Update-Configuration -Name "RemoteCodes" -Value (Get-BraviaRemoteCodes)

    
}

function New-PayloadObject($Method, $MethodParams, $Version = "1.0") {
	$payload = @{'id'=$Global:PacketCounter++;'method'=$Method; 'version'=$Version} 
	if ($MethodParams.Count -eq 0) {
		$payload.Add('params',@())
	}
	else {
		$payload.Add('params',$MethodParams)
	}
	 return $payload | ConvertTo-JSON -Compress
}


function New-RegistrationObject($clientid='PowerShell:1',$nickname='Powershell on Windows') {
	#this was the hardest part - the first parameter/s of the registration method are an object but the second is objects in an array (?!)
	#in this case the second parameter can be omitted
	$registrationParams = @(@{'clientid'=$clientid;'nickname'=$nickname},@())
	return New-PayloadObject -Method 'actRegister' -MethodParams $registrationParams
}

function Start-BraviaRegistration() {
	$reg = New-RegistrationObject
	$response = try {
		Invoke-WebRequest -Method POST -Uri ('http://' + $Script:BraviaConfig.Address + '/sony/accessControl') -Body $reg -ContentType "application/json"
		}
	catch {write-host ($_.Exception.Response.StatusCode)}

    if ($response.StatusCode -eq 200 -and !($response.Headers.'Set-Cookie' -eq $null)) {
        $cookieValues = $response.Headers.'Set-Cookie'.Split(';')
	    $auth = $cookieValues[0].Split('=')[1]
	    $expiry = $cookieValues[3]
        Update-Configuration -Name "Auth" -Value $auth
        Update-Configuration -Name "AuthExpiry" -Value $expiry
        Write-Output "Already authorised with the TV, saving cookie"
        Exit

    }

    else {
        Complete-BraviaRegistration
    }
}


function Complete-BraviaRegistration {
    Param(
    [Parameter(Mandatory=$true)]
    [String]$PIN
    )

	#https://stackoverflow.com/a/27951845/229631
	$encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$PIN"))
	$basicAuthValue = "Basic $encodedCreds"
	$Headers = @{Authorization = $basicAuthValue}
	
    #todo: remove duplication and handle errors
    $response = Invoke-WebRequest -Method POST -Uri ('http://' + $Script:BraviaConfig.Address + '/sony/accessControl') -Body $reg -ContentType "application/json" -Headers $Headers
	$cookieValues = $response.Headers.'Set-Cookie'.Split(';')
	$auth = $cookieValues[0].Split('=')[1]
	$expiry = $cookieValues[3]
    Update-Configuration -Name "Auth" -Value $auth
    Update-Configuration -Name "AuthExpiry" -Value $expiry
}


function Get-BraviaSession {
	$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
	$cookie = New-Object System.Net.Cookie 
	$cookie.Name = "auth"
	$cookie.Value = $Script:BraviaConfig.Auth
	$cookie.Domain = $Script:BraviaConfig.Address
	$session.Cookies.Add($cookie);
	return $session
}

function Send-BraviaPostRequest($Path, $Headers, $Body, $ContentType = 'application/json') {
    if ($Body -eq $null) { #empty POST?

            Write-Output   "empty"
            Invoke-WebRequest ('http://' + $Script:BraviaConfig.Address + '/' + $Path) -WebSession (Get-BraviaSession) -Method POST
    } 
    
    else {
            Invoke-WebRequest ('http://' + $Script:BraviaConfig.Address + '/' + $Path) -WebSession (Get-BraviaSession) -Headers $Headers -Body $Body -ContentType $ContentType -Method POST
    }
}

function Send-BraviaGetRequest($Path, $Headers, $ContentType = 'application/json') {
    Invoke-WebRequest ('http://' + $Script:BraviaConfig.Address + '/' + $Path) -WebSession (Get-BraviaSession)
}

function Get-BraviaApps {
    $Script:BraviaConfig = Reload-Configuration
	$response = Send-BraviaGetRequest 'DIAL/sony/applist'
	$XmlDocument = [xml]$response

    $Apps = @{}
    $XmlDocument.service.app | %{$Apps[$_.Name] = $_.id}

	return $Apps
}

function Start-BraviaApp {
    Param(
    [Parameter(Mandatory=$true)]
    [String]$AppName
    )
    $Apps = Get-BraviaApps
    $response = Send-BraviaPostRequest -Path ('DIAL/apps/' + $apps[$AppName])
}

function Send-BraviaRemoteCode($code_name) {
    Write-Output $Script:BraviaConfig.RemoteCodes[$code_name]
    $code = $Script:BraviaConfig.RemoteCodes[$code_name]
    $Headers = @{'SOAPACTION' = '"urn:schemas-sony-com:service:IRCC:1#X_SendIRCC"'}
    #Seriously, Sony?
    $Body = '<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
    $Body += '<s:Body><u:X_SendIRCC xmlns:u="urn:schemas-sony-com:service:IRCC:1"><IRCCCode>'
    $Body += $code + '</IRCCCode></u:X_SendIRCC></s:Body></s:Envelope>'
    Send-BraviaPostRequest -Path "sony/IRCC" -Headers $Headers -Body $Body -ContentType "text/xml"

}

function Get-BraviaRemoteCodes {
    $payload = New-PayloadObject -Method "getRemoteControllerInfo"
    $response = Send-BraviaPostRequest -Path 'sony/system' -WebSession (Get-BraviaSession) -Method Post -Body $payload
    $codes = @{}
    $response_object = $response | ConvertFrom-Json #| %{if (!($_.name -eq $null)) {$codes[$_.name] = $_.value}}
    $response_object.result[1] | %{$codes[$_.name] = $_.value}
    return $codes
}

Get-ModuleConfiguration

