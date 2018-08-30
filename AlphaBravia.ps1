$Global:PacketCounter = 1
$Script:BraviaConfig = @{}

function Get-TVAddress {
	param([Parameter(Mandatory = $true,HelpMessage = 'Address or hostname of TV')] [string]$Address)
	Update-Configuration -Name "Address" -Value $Address
}


function Get-ConfigurationPath {
	return Join-Path $env:LocalAppData -ChildPath AlphaBravia
}

function Create-ConfigurationPath {
	mkdir -Force -Path (Get-ConfigurationPath)
}

function Update-Configuration {
	param(
		[Parameter(Mandatory = $true)]
		[string]$Name,
		[Parameter(Mandatory = $true)]
		$Value
	)

	$Script:BraviaConfigPath = (Join-Path (Get-ConfigurationPath) -ChildPath "config.json")
	$Script:BraviaConfig | Add-Member -MemberType NoteProperty $Name $Value -Force
	$Script:BraviaConfig | ConvertTo-Json | Out-File $Script:BraviaConfigPath
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

function New-PayloadObject ($Method,$MethodParams,$Version = "1.0") {
	$payload = @{ 'id' = $Global:PacketCounter++; 'method' = $Method; 'version' = $Version }
	if ($MethodParams.Count -eq 0) {
		$payload.Add('params',@())
	}
	else {
		$payload.Add('params',$MethodParams)
	}
	return $payload | ConvertTo-Json -Compress
}


function New-RegistrationObject ($clientid = 'PowerShell:1',$nickname = 'Powershell on Windows') {
	#this was the hardest part - the first parameter/s of the registration method are an object but the second is objects in an array (?!)
	#in this case the second parameter can be omitted
	$registrationParams = @(@{ 'clientid' = $clientid; 'nickname' = $nickname },@())
	return New-PayloadObject -Method 'actRegister' -MethodParams $registrationParams
}

function Start-BraviaRegistration () {
	$reg = New-RegistrationObject
	$response = try {
		Invoke-WebRequest -Method POST -Uri ('http://' + $Script:BraviaConfig.Address + '/sony/accessControl') -Body $reg -ContentType "application/json"
	}
	catch { Write-Host ($_.Exception.Response.StatusCode) }

	if ($response.StatusCode -eq 200 -and !($response.Headers. 'Set-Cookie' -eq $null)) {
		$cookieValues = $response.Headers. 'Set-Cookie'.Split(';')
		$auth = $cookieValues[0].Split('=')[1]
		$expiry = $cookieValues[3]
		Update-Configuration -Name "Auth" -Value $auth
		Update-Configuration -Name "AuthExpiry" -Value $expiry
		Write-Output "Already authorised with the TV, saving cookie"
	}

	else {
		Complete-BraviaRegistration
	}
}


function Complete-BraviaRegistration {
	param(
		[Parameter(Mandatory = $true)]
		[string]$PIN
	)

	#https://stackoverflow.com/a/27951845/229631
	$encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$PIN"))
	$basicAuthValue = "Basic $encodedCreds"
	$Headers = @{ Authorization = $basicAuthValue }

	#todo: remove duplication and handle errors
	$response = Invoke-WebRequest -Method POST -Uri ('http://' + $Script:BraviaConfig.Address + '/sony/accessControl') -Body $reg -ContentType "application/json" -Headers $Headers
	$cookieValues = $response.Headers. 'Set-Cookie'.Split(';')
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

function Send-BraviaPostRequest ($Path,$Headers,$Body,$ContentType = 'application/json') {

	try {
		if ($Body -eq $null) { #empty POST?

			Write-Output "empty"
			Invoke-WebRequest ('http://' + $Script:BraviaConfig.Address + '/' + $Path) -WebSession (Get-BraviaSession) -Method POST -ContentType $ContentType
		}

		else {
			Invoke-WebRequest ('http://' + $Script:BraviaConfig.Address + '/' + $Path) -WebSession (Get-BraviaSession) -Headers $Headers -Body $Body -ContentType $ContentType -Method POST
		}
	}

	catch {
		Write-Output "Caught exception"
		Start-BraviaRegistration
		Write-Output "Retry your command"
	}
}

function Send-BraviaGetRequest ($Path,$Headers,$ContentType = 'application/json') {
	Invoke-WebRequest ('http://' + $Script:BraviaConfig.Address + '/' + $Path) -WebSession (Get-BraviaSession)
}

function Get-BraviaApps {
	$Script:BraviaConfig = Reload-Configuration
	$response = Send-BraviaGetRequest 'DIAL/sony/applist'
	$XmlDocument = [xml]$response

	$Apps = @{}
	$XmlDocument.service.app | ForEach-Object { $Apps[$_.Name] = $_.id }

	return $Apps
}

function Start-BraviaApp {
	param(
		[Parameter(Mandatory = $true)]
		[string]$AppName
	)
	$Apps = Get-BraviaApps
	$response = Send-BraviaPostRequest ('DIAL/apps/' + $apps[$AppName])
}

function Send-BraviaRemoteCode {

	[Alias("tv")]
	#https://foxdeploy.com/2017/01/13/adding-tab-completion-to-your-powershell-functions/
	[CmdletBinding()]
	param()
	dynamicparam {

		# Set the dynamic parameters' name
		$ParameterName = 'Code'

		# Create the dictionary
		$RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

		# Create the collection of attributes
		$AttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]

		# Create and set the parameters' attributes
		$ParameterAttribute = New-Object System.Management.Automation.ParameterAttribute
		$ParameterAttribute.Mandatory = $true
		$ParameterAttribute.Position = 1

		# Add the attributes to the attributes collection
		$AttributeCollection.Add($ParameterAttribute)

		# Generate and set the ValidateSet
		$arrSet = $Script:BraviaConfig.RemoteCodes.Keys
		$ValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute ($arrSet)

		# Add the ValidateSet to the attributes collection
		$AttributeCollection.Add($ValidateSetAttribute)

		# Create and return the dynamic parameter
		$RuntimeParameter = New-Object System.Management.Automation.RuntimeDefinedParameter ($ParameterName,[string],$AttributeCollection)
		$RuntimeParameterDictionary.Add($ParameterName,$RuntimeParameter)
		return $RuntimeParameterDictionary
	}

	begin {
		# Bind the parameter to a friendly variable
		$Code = $PsBoundParameters[$ParameterName]
	}


	process {
		$selectedCode = $Script:BraviaConfig.RemoteCodes.$Code

		$Headers = @{ 'SOAPACTION' = '"urn:schemas-sony-com:service:IRCC:1#X_SendIRCC"' }
		#Seriously, Sony?
		$Body = '<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
		$Body += '<s:Body><u:X_SendIRCC xmlns:u="urn:schemas-sony-com:service:IRCC:1"><IRCCCode>'
		$Body += $selectedCode + '</IRCCCode></u:X_SendIRCC></s:Body></s:Envelope>'
		Send-BraviaPostRequest -Path "sony/IRCC" -Headers $Headers -Body $Body -ContentType "text/xml"
	}
}

function Get-BraviaRemoteCodes {
	$payload = New-PayloadObject -Method "getRemoteControllerInfo"
	$response = Send-BraviaPostRequest -Path 'sony/system' -WebSession (Get-BraviaSession) -Method Post -Body $payload
	$codes = @{}
	$response_object = $response | ConvertFrom-Json #| %{if (!($_.name -eq $null)) {$codes[$_.name] = $_.value}}
	$response_object.result[1] | ForEach-Object { $codes[$_.Name] = $_.Value }
	return $codes
}

Get-ModuleConfiguration
