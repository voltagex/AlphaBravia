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
    [String]$Value
    )
    
    $Script:BraviaConfigPath = (Join-Path (Get-ConfigurationPath) -ChildPath "config.json")
    
    $JsonConfig = get-content $Script:BraviaConfigPath | convertfrom-json
    $JsonConfig | Add-Member NoteProperty $Name $Value
    $Script:BraviaConfig | Add-Member NoteProperty $Name $Value
    $Script:BraviaConfig | convertto-json | out-file $Script:BraviaConfigPath
}

function Reload-Configuration {
    $Script:BraviaConfig = Get-Content $Script:BraviaConfigPath | ConvertFrom-Json
    $Script:BraviaConfig | Add-Member "Session" (Get-BraviaSession) -TypeName Microsoft.PowerShell.Commands.WebRequestSession
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

function Get-BraviaApps {
    $Script:BraviaConfig = Reload-Configuration
	$response = invoke-webrequest ('http://' + $Script:BraviaConfig.Address + '/DIAL/sony/applist') -WebSession (Get-BraviaSession)
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
    $response = invoke-webrequest -Method POST ('http://' + $Script:BraviaConfig.Address + '/DIAL/apps/' + $apps[$AppName]) -WebSession (Get-BraviaSession)
}

Get-ModuleConfiguration

