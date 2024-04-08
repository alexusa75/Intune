###########################################################################
# The sample scripts are not supported under any Microsoft standard support
# program or service. The sample scripts are provided AS IS without warranty
# of any kind. Microsoft further disclaims all implied warranties including,
# without limitation, any implied warranties of merchantability or of fitness
# for a particular purpose. The entire risk arising out of the use or
# performance of the sample scripts and documentation remains with you. In no
# event shall Microsoft, its authors, or anyone else involved in the creation,
# production, or delivery of the scripts be liable for any damages whatsoever
# (including, without limitation, damages for loss of business profits,
# business interruption, loss of business information, or other pecuniary
# loss) arising out of the use of or inability to use the sample scripts or
# documentation, even if Microsoft has been advised of the possibility of such
# damages.
############################################################################

### Group devices by Country
Function Write-Log {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [ValidateSet("INFO", "WARN", "ERROR", "FATAL", "DEBUG")]
        [String]
        $Level = "INFO",

        [Parameter(Mandatory = $True)]
        [string]
        $Message,

        [Parameter(Mandatory = $False)]
        [string]
        $logfile
    )

    $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
    #$Line = $Stamp + "," + $Level + "," + $Message
    If($logfile){
        $csvobject = New-Object system.collections.arraylist
        $csvobject = "" | Select-Object DateTime, Level, Message
        $csvobject.DateTime = $Stamp
        $csvobject.Level = $Level
        $csvobject.Message = $Message
        $csvobject | Export-Csv $logfile -Append -NoTypeInformation
    }
    Else{
        $DesktopPath = [Environment]::GetFolderPath("Desktop")
        $logfile = $DesktopPath + "\Logs.csv"
        $csvobject = New-Object system.collections.arraylist
        $csvobject = "" | Select-Object DateTime, Level, Message
        $csvobject.DateTime = $Stamp
        $csvobject.Level = $Level
        $csvobject.Message = $Message
        $csvobject | Export-Csv $logfile -NoTypeInformation
    }
}

Function MyJWTToken{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [string]
        $token
    )
    if (!$token.Contains(".") -or !$token.StartsWith("eyJ")) { Write-Error "Invalid token" -ErrorAction Stop }else{#Write-Host "Good Token"
                                                                }

    # Token
    foreach ($i in 0..1) {
        $data = $token.Split('.')[$i].Replace('-', '+').Replace('_', '/')
        switch ($data.Length % 4) {
            0 { break }
            2 { $data += '==' }
            3 { $data += '=' }
        }
    }
    $decodedToken = [System.Text.Encoding]::UTF8.GetString([convert]::FromBase64String($data)) | ConvertFrom-Json

    # Signature
    foreach ($i in 0..2) {
        $sig = $token.Split('.')[$i].Replace('-', '+').Replace('_', '/')
        switch ($sig.Length % 4) {
            0 { break }
            2 { $sig += '==' }
            3 { $sig += '=' }
        }
    }
    Write-Verbose "JWT Signature:"
    Write-Verbose $sig
    $decodedToken | Add-Member -Type NoteProperty -Name "sig" -Value $sig

    # Convert Expiry time to PowerShell DateTime
    $orig = (Get-Date -Year 1970 -Month 1 -Day 1 -hour 0 -Minute 0 -Second 0 -Millisecond 0)
    $timeZone = Get-TimeZone
    $utcTime = $orig.AddSeconds($decodedToken.exp)
    $localTime = $utcTime.AddHours($timeZone.BaseUtcOffset.Hours)     # Return local time
    $decodedToken | Add-Member -Type NoteProperty -Name "expiryDateTime" -Value $localTime

    # Time to Expiry
    $timeToExpiry = ($localTime - (get-date))
    $decodedToken | Add-Member -Type NoteProperty -Name "timeToExpiry" -Value $timeToExpiry
    Return $decodedToken
}

Function RawToken(){
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [string]
        $appid,
        [Parameter(Mandatory = $True)]
        [string]
        $secret,
        [Parameter(Mandatory = $True)]
        [string]
        $tenantid
    )
    $body =  @{
        Grant_Type    = "client_credentials"
        Scope         = "https://graph.microsoft.com/.default"
        Client_Id     = $appid
        Client_Secret = $secret
    }

    $response = Invoke-RestMethod -Uri https://login.microsoftonline.com/$tenantid/oauth2/v2.0/token -Method POST -Body $body

    #$response | ConvertTo-Json
    $token = $response.access_token
    Return $token
}
Function Get-AccessToken{
    ####################
    #  Authentication  #
    ####################
    If($token){
        #$tok = get-JWTDetails($token)
        $tok = MyJWTToken -token $token
        $numericDate = $tok.exp
        $epoch = New-Object DateTime 1970, 1, 1, 0, 0, 0, ([DateTimeKind]::Utc)
        $accessTokenExpiration = $epoch.AddSeconds($numericDate).ToLocalTime()
        if ($accessTokenExpiration -lt (Get-Date)) {
            $global:token = RawToken -appid $AppId -secret $client_secret -tenantid $Tenant
            $null = Connect-MgGraph -AccessToken ($token | ConvertTo-SecureString -AsPlainText -Force)
        }else {
            # The access token is still valid.
            #Write-Host "Access token is still valid."
            #Return
            $global:token = $token
            $null = Connect-MgGraph -AccessToken ($token | ConvertTo-SecureString -AsPlainText -Force)
        }
    }else{
        # No Access Token, Creating a new one.
        #Write-Host "New Access Token."
        #Update-MSGraphEnvironment -AppId $AppId -Quiet
        #Update-MSGraphEnvironment -AuthUrl $authority -Quiet
        #$global:token = Connect-MSGraph -ClientSecret $client_secret -PassThru -Verbose
        $global:token = RawToken -appid $AppId -secret $client_secret -tenantid $Tenant
        $null = Connect-MgGraph -AccessToken ($token | ConvertTo-SecureString -AsPlainText -Force)
    }

}
function Set-ExtAttribute {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet("ExtensionAttribute10", "ExtensionAttribute11", "ExtensionAttribute12", "ExtensionAttribute13", "ExtensionAttribute14","ExtensionAttribute15")]
        [string]$extentionAttribute,
        [Parameter(Mandatory=$true)]
        [string]$deviceID,  #<-- This is the Azure device ID
        [Parameter(Mandatory=$true)]
        [string]$value
    )

    #$hash = @{}
    #$hash["$($extentionAttribute)"] = $value

    $Attributes = @{
        "extensionAttributes" = @{
        "$($extentionAttribute)" = $value
         }
       }  | ConvertTo-Json

    $_azuredeviceId = (Get-MgDevice -Filter "DeviceId eq '$($deviceID)'" -ErrorAction SilentlyContinue).id
    If($_azuredeviceId){
        try{
            #$uri = "https://graph.microsoft.com/beta/devices/$()"
            Update-MgDevice -DeviceId $_azuredeviceId -BodyParameter $Attributes
            #Get-MgDevice -DeviceId $_azuredeviceId
        }
        catch{
            Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        }

    }else{
        $Script:NoDevice = $true
        Write-Host "No device found in Azure with the ID $($deviceID)" -ForegroundColor Red -BackgroundColor Yellow
    }
}

function Check-IPInCIDRRangeAllCIRDatonece {
    param(
        [string]$IPAddress,
        [array]$CIDRRanges
    )

    # Convert an IP address to a 32-bit integer
    function Convert-IPToUInt32 {
        param([string]$IP)
        $bytes = $IP.Split('.') | ForEach-Object { [byte]$_ }
        [Array]::Reverse($bytes)
        return [BitConverter]::ToUInt32($bytes, 0)
    }

    # Convert CIDR to start IP and calculate the number of addresses in the range
    function Convert-CIDRToRange {
        param([string]$CIDR)
        $parts = $CIDR -split '/'
        $baseIP = $parts[0]
        $subnetSize = [math]::Pow(2, (32 - [int]$parts[1]))
        $baseUInt = Convert-IPToUInt32 $baseIP
        return @{ "Start" = $baseUInt; "End" = $baseUInt + $subnetSize - 1 }
    }

    $ipUInt = Convert-IPToUInt32 $IPAddress
    $ranges = @()
    foreach ($cidr in $CIDRRanges) {
        $range = Convert-CIDRToRange $cidr.CIDR
        if ($ipUInt -ge $range.Start -and $ipUInt -le $range.End) {
            $ranges += [PSCustomObject]@{
                CIDR = $cidr.CIDR
                IP = $IPAddress
                Category = $cidr.Category
            }
        }
    }

    return $ranges
}

function Set-DeviceName {
    param (
        [Parameter(Mandatory = $true)]
        [string]$deviceID,
        [Parameter(Mandatory = $true)]
        [string]$deviceName,
        [Parameter(Mandatory = $true)]
        [string]$ManagedName
    )

    $body = @"
{deviceName: "$($deviceName)"}
"@
    $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices('$($deviceID)')/setDeviceName"
    try {
        $responseDeviceName = Invoke-MgGraphRequest -Method POST -Uri $uri -Body $body
        If($ManagedName){
            $body = @"
{managedDeviceName: "$($ManagedName)"}
"@
            $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices('$($deviceID)')"
            $responseDeviceName = Invoke-MgGraphRequest -Method PATCH -Uri $uri -Body $body
        }
    }
    catch {
        <#Do this if a terminating exception happens#>
    }


}

function Set-ManageDeviceName {
    param (
        [Parameter(Mandatory = $true)]
        [string]$deviceID,
        [Parameter(Mandatory = $true)]
        [string]$ManagedName
    )
    try {
        $body = @"
{managedDeviceName: "$($ManagedName)"}
"@
        $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices('$($deviceID)')"
        $responseDeviceName = Invoke-MgGraphRequest -Method PATCH -Uri $uri -Body $body
    }
    catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

##############################
#  Connection and Variables  #
##############################
#Install-Module Microsoft.Graph.Intune
#Install-Module Microsoft.Graph.Users
#Install-Module Microsoft.Graph.Identity.DirectoryManagement
#Import-Module Microsoft.Graph.Intune
#Install-Module get-JWTDetails


## Authentication using an AppID
$AppId = "XXXXXXXXXXXXXXXXXXXXXXXXXXX"
$client_secret = "XXXXXXXXXXXXXXXXXXXXXXXXXXXX"
$Tenant = "<tenantname>.onmicrosoft.com"
$authority = "https://login.windows.net/$tenant"


## Manual authentication
#$RequiredScopes = ("DeviceManagementConfiguration.ReadWrite.Al", "DeviceManagementManagedDevices.ReadWrite.All", "User.Read.All", "Device.ReadWrite.All", "Directory.Read.All")
#Connect-MgGraph -Scope $RequiredScopes


Get-AccessToken
$IntuneDevices = Get-MgDeviceManagementManagedDevice -Filter "(operatingSystem eq 'iOS' or operatingSystem eq 'Android') and managedDeviceOwnerType eq 'company'" -Property id,azureADDeviceId, deviceName,userId,userPrincipalName,managedDeviceName -All | ?{($_.userId -ne '') -and ($_.managedDeviceName -notmatch "Filtered$")} | Select-Object id,azureADDeviceId, deviceName,userId,userPrincipalName,managedDeviceName

$c = 0
$count = @($IntuneDevices.Count)
ForEach($device in $IntuneDevices){
    $c++
    Get-AccessToken
    #Write-Progress -Activity "$($device.deviceName)" -Status "$c out of $count" -PercentComplete (($c/$count)*100)
    $country = (Get-MgUser -UserId $device.userId -Property country).country
    $managedNameNew = $device.managedDeviceName + "_Filtered"
    if($country){
        $_azuredeviceId = (Get-MgDevice -Filter "DeviceId eq '$($device.azureADDeviceId)'" -ErrorAction SilentlyContinue).id
        If($_azuredeviceId){
            try{
                Set-ExtAttribute -extentionAttribute ExtensionAttribute10 -deviceID $_azuredeviceId -value $country
                Set-ManageDeviceName -DeviceID $device.deviceId -ManagedName $managedNameNew
            }
            catch{
                Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
            }

        }
    }

}


$allusersWithCountry = Get-MgUser -Property country -All | select country | ?{$_.Country -ne $null}

$allusersWithCountry | group-object -Property Country

$country = "USA2"
$_azuredeviceId = 'ffa6f27f-19ec-4369-a305-e65753e87875'
Set-ExtAttribute -extentionAttribute ExtensionAttribute10 -deviceID $_azuredeviceId -value $country

(Get-MgDevice -Filter "DeviceId eq '$($_azuredeviceId)'").AdditionalProperties
((Get-MgDevice -Filter "DeviceId eq '$($_azuredeviceId)'").AdditionalProperties).extensionAttributes