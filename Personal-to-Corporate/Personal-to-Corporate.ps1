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

###############
#  Functions  #
###############

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
Function Get-httprequest(){
    [cmdletbinding()]
    param(
        $NextPage
    )
    $graphApiVersion = "Beta"
    $Resource = "/deviceAppManagement/managedAppStatuses('appregistrationsummary')?fetch=6000&policyMode=0&columns=DisplayName,UserEmail,ApplicationName,ApplicationInstanceId,ApplicationVersion,DeviceName,DeviceType,DeviceManufacturer,DeviceModel,AndroidPatchVersion,AzureADDeviceId,MDMDeviceID,Platform,PlatformVersion,ManagementLevel,PolicyName,LastCheckInDate"

    if ($NextPage -ne "" -and $NextPage -ne $null) {
        $Resource += "&seek=$NextPage"
    }
    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
    Invoke-GraphRequest -Method GET -Uri $uri
}

function Invoke-GraphApiRequest {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Uri,

        [Parameter(Mandatory=$true)]
        [ValidateSet("GET", "POST", "PUT", "PATCH", "DELETE")]
        [string]$Method,

        [string]$AccessToken,

        [Parameter(Mandatory=$false)]
        [hashtable]$Headers,

        [Parameter(Mandatory=$false)]
        [string]$Body
    )

    # Base headers including authorization
    $baseHeaders = @{
        Authorization = "Bearer $AccessToken"
    }

    # If additional headers are provided, merge them with the base headers
    if ($Headers) {
        $baseHeaders = $baseHeaders + $Headers
    }

    # Initialize parameters for Invoke-RestMethod
    $restParams = @{
        Uri     = $Uri
        Method  = $Method
        Headers = $baseHeaders
    }

    # Include body if applicable
    if ($Body) {
        $restParams.Body = $Body
        $restParams.ContentType = "application/json" # Assuming JSON body; adjust as needed
    }

    do {
        $response = Invoke-RestMethod @restParams

        # Output the current batch of data
        $response

        # Check for and handle pagination
        $nextUri = if ($response.'@odata.nextLink') {
            $response.'@odata.nextLink'
        } else {
            $null
        }

        if ($nextUri) {
            $restParams.Uri = $nextUri
            # Ensure the Body is not included in GET requests during pagination
            if ($Method -eq "GET") {
                $restParams.Remove("Body")
                $restParams.Remove("ContentType")
            }
        }

    } while ($nextUri)
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
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }


}

function Set-PersonalToCorp {
    param(
        [Parameter(Mandatory = $true)]
        [string]$deviceID,
        [Parameter(Mandatory = $true)]
        [ValidateSet("company","personal")]
        [string]$owner
    )
    $Body = @"
{
    ownerType:"$($owner)"
}
"@
    $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices('$deviceID')"
    Invoke-MgGraphRequest -Uri $uri -Body $Body -method Patch -ContentType "application/json"

}

##############################
#  Connection and Variables  #
##############################
#Install-Module Microsoft.Graph.Intune
#Import-Module Microsoft.Graph.Intune
#Install-Module get-JWTDetails

#
#$AppId = "xxxxxxxxxxxxxxxxxxxxx"
#$client_secret = "xxxxxxxxxxxxxxxxxxxxxxxx"
#$Tenant = "<tenantName>.onmicrosoft.com"
#$authority = "https://login.windows.net/$tenant"
#

$RequiredScopes = ("DeviceManagementManagedDevices.Read.All", "DeviceManagementManagedDevices.ReadWrite.All", "AuditLog.Read.All", "User.Read.All")
Connect-MgGraph -Scope $RequiredScopes


###################################
#     Get all Android Devices     #
###################################
#Get-AccessToken

$csvPath = "C:\temp\personalTocorporate.csv"
$csvIMEIs = Import-Csv -Path $csvPath
$logfile = "C:\temp\Rename_Devices_Log" + [DateTime]::Now.ToString("yyyy_MM_dd_HH_mm_ss") + ".csv"


#$alliOS = Get-MgDeviceManagementManagedDevice -Filter ("operatingSystem eq 'iOS'") -Select id,azureADDeviceId,deviceName,deviceCategoryDisplayName, manufacturer,Model,imei,serialNumber,managedDeviceOwnerType,phoneNumber,operatingSystem,lastSyncDateTime,deviceEnrollmentType,operatingSystem -All

#$alliOS| select deviceName,imei,managedDeviceOwnerType

ForEach($imei in $csvIMEIs.IMEI){
    $devicetemp = Get-MgDeviceManagementManagedDevice -filter "imei eq '$($imei)'" -Property id,deviceName,imei,managedDeviceOwnerType | select id,deviceName,imei, managedDeviceOwnerType
    $count = @($devicetemp).Count
    If($count -eq 1){
        If($devicetemp.managedDeviceOwnerType -ne "company"){
            try {
                Set-PersonalToCorp -deviceID $devicetemp.id -owner company
                Write-Host "We change to company the ownership of the device IMEI: $imei" -ForegroundColor Green
            }
            catch {
                Write-Host "Failed to set the ownership with error: $($_.Exception.Message)" -f Red
                Write-Log ERROR -Message "Failed to set the ownership with error: $($_.Exception.Message)" -logfile $logfile
            }

        }else{
            Write-Host "The device with IMEI: $($imei) was already a company device" -ForegroundColor Cyan
            Write-Log INFO "The device with IMEI: $($imei) was already a company device" -logfile $logfile
        }
    }elseif ($count -gt 1) {
        Write-Host "$($count) devices with this emei: $imei" -ForegroundColor Yellow
        Write-Log WARN "$($count) devices with this emei: $imei" -logfile $logfile
    }else{
        Write-Host "No device was found with this $imei" -ForegroundColor red
        Write-Log FATAL "No device was found with this $imei" -logfile $logfile
    }

}



#$deviceId = "18701485-d7c7-4e29-adef-63b4427bb320"
#Set-PersonalToCorp -deviceID $deviceId -owner company

