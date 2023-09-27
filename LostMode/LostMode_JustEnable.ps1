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
    if (!$token.Contains(".") -or !$token.StartsWith("eyJ")) { Write-Error "Invalid token" -ErrorAction Stop } #else{Write-Host "Good Token"}

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

Function Get-LostModeStatus{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [string]
        $DeviceId,

        [Parameter(Mandatory = $True)]
        [string]
        $SerialNumber
    )
    Get-AccessToken
    try{
        $uri = 'https://graph.microsoft.com/beta/deviceManagement/managedDevices/' + $DeviceId + '?$select=id,deviceName,serialNumber,lostModeState,deviceactionresults'
        $checklostmode = Invoke-MSGraphRequest -Url $uri #-ErrorAction Stop
        $lostModeEnabled = ($checklostmode.deviceActionResults | ?{$_.actionName -eq 'enableLostMode'}).actionState
        If($lostModeEnabled){
            Return $lostModeEnabled # Possible results (done, )
        }else{
            throw "No Data"
        }
    }catch{
        $ex = $error[0].Exception
        #$errorResponse = $ex.Response.GetResponseStream()
        Write-Log FATAL -Message "Error enabling Locate Device to Device: $($SerialNumber)" -logfile $logs
        Return "Error: $ex"
    }
}

Function Get-DisabledLostModeStatus{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [string]
        $DeviceId,

        [Parameter(Mandatory = $True)]
        [string]
        $SerialNumber
    )
    Get-AccessToken
    try{
        $uri = 'https://graph.microsoft.com/beta/deviceManagement/managedDevices/' + $DeviceId + '?$select=id,deviceName,serialNumber,lostModeState,deviceactionresults'
        $checklostmode = Invoke-MSGraphRequest -Url $uri #-ErrorAction Stop
        $lostModeEnabled = ($checklostmode.deviceActionResults | ?{$_.actionName -eq 'disableLostMode'}).actionState
        If($lostModeEnabled){
            Return $lostModeEnabled # Possible results (done, )
        }else{
            throw "No Data"
        }
    }catch{
        $ex = $error[0].Exception
        #$errorResponse = $ex.Response.GetResponseStream()
        Write-Log FATAL -Message "Error enabling Locate Device to Device: $($SerialNumber)" -logfile $logs
        Return "Error: $ex"
    }
}

Function Get-LostModeEnable{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [string]
        $DeviceId,

        [Parameter(Mandatory = $True)]
        [string]
        $SerialNumber
    )
    Get-AccessToken
    try{
        $uri = 'https://graph.microsoft.com/beta/deviceManagement/managedDevices/' + $DeviceId + '?$select=id,deviceName,serialNumber,lostModeState,deviceactionresults'
        $checklostmode = Invoke-MSGraphRequest -Url $uri #-ErrorAction Stop
        If($checklostmode.lostModeState){
            Return $checklostmode.lostModeState # Possible results (enabled,disabled)
        }else{
            throw "No Data"
        }
    }catch{
        $ex = $error[0].Exception
        #$errorResponse = $ex.Response.GetResponseStream()
        Write-Log FATAL -Message "Error enabling Locate Device to Device: $($SerialNumber)" -logfile $logs
        Return "Error: $ex"
    }
}

Function Enable-LostMode{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [string]
        $DeviceId,

        [Parameter(Mandatory = $True)]
        [string]
        $SerialNumber
    )
    Get-AccessToken
    try{
        $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices('$($DeviceId)')/enableLostMode"
        $lostheader = @{
            'message' ='Lost Mode - Script'
            'phoneNumber' = '5618537100'
            'footer'= 'Footer'
        }
        Invoke-MsGraphRequest -Url $uri -HttpMethod POST -Content $lostheader
        $Enable = "Success"
        Return $Enable

    }catch{
        $ex = $error[0].Exception
        #$errorResponse = $ex.Response.GetResponseStream()
        Write-Log FATAL -Message "Error enabling Locate Device to Device: $($SerialNumber)" -logfile $logs
        Return "Error: $ex"
    }
}

Function Locate-Device{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [string]
        $DeviceId,

        [Parameter(Mandatory = $True)]
        [string]
        $SerialNumber
    )
    Get-AccessToken
    try{
        $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices('$($DeviceId)')/locateDevice"
        $locateDeviceheader = @{}
        Invoke-MsGraphRequest -Url $uri -HttpMethod POST -Content $locateDeviceheader
        $Locate = "Success"
        Return $Locate

    }catch{
        $ex = $error[0].Exception
        #$errorResponse = $ex.Response.GetResponseStream()
        Write-Log FATAL -Message "Error enabling Locate Device to Device: $($SerialNumber)" -logfile $logs
        Return "Error: $ex"
    }
}

Function Get-Location{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [string]
        $DeviceId,

        [Parameter(Mandatory = $True)]
        [string]
        $SerialNumber
    )
    Get-AccessToken
    try{
        $uri = 'https://graph.microsoft.com/beta/deviceManagement/managedDevices/' + $DeviceId + '?$$select=deviceactionresults,managementstate,lostModeState,deviceRegistrationState,ownertype'
        $Graph = Invoke-MSGraphRequest -Url $uri #-ErrorAction Stop
        $location = ($Graph.deviceActionResults | ?{$_.actionName -eq 'locateDevice'}).devicelocation
        If($location){
            $result = 'Success'
            $longitude = $location.longitude
            $latitude = $location.latitude
            $altitude = $location.altitude
            Return $result, $longitude, $latitude, $altitude
        }else{
            throw "No Data"
        }
    }catch{
        $ex = $error[0].Exception
        #$errorResponse = $ex.Response.GetResponseStream()
        Write-Log FATAL -Message "Error enabling Locate Device to Device: $($SerialNumber)" -logfile $logs
        Return "Error: $ex"
    }
}

Function Disable-LostMode{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [string]
        $DeviceId,

        [Parameter(Mandatory = $True)]
        [string]
        $SerialNumber
    )
    Get-AccessToken
    try{
        $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices('$($DeviceId)')/disableLostMode"
        $lostheader = @{}
        Invoke-MsGraphRequest -Url $uri -HttpMethod POST -Content $lostheader
        $Disable = "Success"
        Return $Disable

    }catch{
        $ex = $error[0].Exception
        #$errorResponse = $ex.Response.GetResponseStream()
        Write-Log FATAL -Message "Error enabling Locate Device to Device: $($SerialNumber)" -logfile $logs
        Return "Error: $ex"
    }
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
            # The access token has expired. You can refresh it here.
            #Write-Host "Access token has expired."
            Update-MSGraphEnvironment -AppId $AppId -Quiet
            Update-MSGraphEnvironment -AuthUrl $authority -Quiet
            $global:token = Connect-MSGraph -ClientSecret $client_secret -PassThru -Verbose
        }else {
            # The access token is still valid.
            #Write-Host "Access token is still valid."
            #Return
            $global:token = $token
        }
    }else{
        # No Access Token, Creating a new one.
        #Write-Host "New Access Token."
        Update-MSGraphEnvironment -AppId $AppId -Quiet
        Update-MSGraphEnvironment -AuthUrl $authority -Quiet
        $global:token = Connect-MSGraph -ClientSecret $client_secret -PassThru -Verbose
    }

}

Function Disable-LostModedueToError{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [string]
        $DeviceId,

        [Parameter(Mandatory = $True)]
        [string]
        $SerialNumber,

        [Parameter(Mandatory = $True)]
        [int]
        $Stage,

        [Parameter(Mandatory = $True)]
        [string]
        $Note
    )

    $disable = Disable-LostMode -DeviceId $DeviceId -SerialNumber $SerialNumber
            If($disable -eq 'Success'){
                $global:DevicesBatchTemp | ?{$_.id -eq "$($DeviceId)"} | ForEach-Object{$_.Status = "$($Stage)-$($Note)-DisabledLostModedueToErrors"}
                Write-Log DEBUG -Message "We disabled Lost Mode due to the command failed to Device: $($device2.serialNumber)" -logfile $logs
            }else{
                $global:DevicesBatchTemp | ?{$_.id -eq "$($device2.id)"} | ForEach-Object{$_.Status = "$($Stage)-ErrorDisblingLostMode"}
                Write-Log ERROR -Message "Error to disable Lost Mode in Stage 2 to Device: $($device2.serialNumber)" -logfile $logs
            }
}
clear

##############################
#  Connection and Variables  #
##############################
#Install-Module Microsoft.Graph.Intune
#Import-Module Microsoft.Graph.Intune
#Install-Module get-JWTDetails -> You don't have to install this module

$AppId = "fa9a8af1-5f19-45b6-b957-744255ea9cc0"
$client_secret = "5Fs8Q~AILt5JwMW4KtWR3DQmjKrzRpAUrKqx4bQS"
$Tenant = "alexusapcus.onmicrosoft.com"
$authority = "https://login.windows.net/$tenant"

###############
#  Variables  #
###############
$OutputFolder = "C:\Alex\LostMode"
$logs = $OutputFolder + "\logs.csv"
$CSVOutput = $OutputFolder + "\AlliOSSupervise.csv"
$finalResult = $OutputFolder + "\FinalResults.csv"
$LostModeStuckedOutput = $OutputFolder + "\LostModeStuck.csv"
$listOfDevices = $OutputFolder + "\listOfDevices.csv"


###################################
#  Get all iOS Supervise Devices  #
###################################
Get-AccessToken

##$alliOSSupervise = Get-IntuneManagedDevice -Filter ("operatingSystem eq 'iOS'") -Select id,azureADDeviceId,deviceName,manufacturer,Model,isSupervised,imei,serialNumber,managedDeviceOwnerType,phoneNumber,operatingSystem,lastSyncDateTime | Where-Object {($_.AzureADDeviceId -ne '00000000-0000-0000-0000-000000000000') -and ($_.isSupervised -eq 'true')} | Get-MSGraphAllPages

$alliOSSupervise = Import-Csv -Path $listOfDevices

$alliOSSupervise | select *,
    @{n='Status';e={""}},
    @{n='longitude';e={""}},
    @{n='latitude';e={""}},
    @{n='altitude';e={""}}| Export-Csv -Path $CSVOutput -NoTypeInformation -UseCulture

#######################################
#  Import Devices to enable LockMode  #
#######################################
$Devices = @()
[array]$Devices = import-csv -Path $CSVOutput
clear
$CountDevices = @($Devices.count)
Write-Log INFO -Message "Started - Devices $($CountDevices)" -logfile $logs

$global:DevicesBatchTemp = @()
$DevicesLockTemp = @()
$LostModeStuckTemp = @()
$c = 0
#####################
#  Enable Lost Mode  #
######################
foreach($device in $Devices){
    $c++
    Write-Progress -Activity "$($device.serialNumber)" -Status "$c of $($CountDevices.count)" -PercentComplete $(($c/$($CountDevices.count))*100)
    Get-AccessToken
    $exist  = Get-IntuneManagedDevice -managedDeviceId $device.id -Select id,serialNumber,AzureADDeviceId,isSupervised,lastSyncDateTime | Where-Object {($_.AzureADDeviceId -ne '00000000-0000-0000-0000-000000000000') -and ($_.isSupervised -eq 'true')}

    #$exist = Get-IntuneManagedDevice -Filter ("serialNumber eq '$($device.serialNumber)'") -Select id,serialNumber,AzureADDeviceId,isSupervised,lastSyncDateTime | Where-Object {($_.AzureADDeviceId -ne '00000000-0000-0000-0000-000000000000') -and ($_.isSupervised -eq 'true')}
    If($exist){
        $existcount = @($exist).count
        IF($existcount -eq 1){
            $Date = (Get-Date).ToUniversalTime()
            $LastSyntTime = ($Date - ($exist.lastSyncDateTime))
            try {
                $LostModeEnable = Get-LostModeEnable -DeviceId $device.id -SerialNumber $device.serialNumber
                If($LostModeEnable -ne 'enabled'){
                    Enable-LostMode -DeviceId $device.id -SerialNumber $device.serialNumber
                    $c++
                    $device.Status = "EnabledLostMode"
                    $global:DevicesBatchTemp += $device
                    $DevicesLockTemp += $device
                    Write-Log DEBUG -Message "LostMode sent to the Device: $($exist.serialNumber) - LastSyncTime: $($LastSyntTime)" -logfile $logs
                }else{
                    $c++
                    $device.Status = "WasArreadyEnabledLostMode"
                    $global:DevicesBatchTemp += $device
                    $DevicesLockTemp += $device
                    Write-Log DEBUG -Message "LostMode was already enabled on the Device: $($exist.serialNumber) - LastSyncTime: $($LastSyntTime)" -logfile $logs
                }
            }
            catch {
                $err++
                $ex = $error[0].Exception
                $device.Status = "ErrorEnablingLostMode"
                $global:DevicesBatchTemp += $device
                $DevicesLockTemp += $device
                Write-Log FATAL -Message "Error enabling LostMode to Device: $($exist.serialNumber) Error: $($ex) - LastSyncTime: $($LastSyntTime)" -logfile $logs
            }
        }else{
            $ee++
            Write-Host "More than 1 active device with the same Id: $($device.id)"
            $device.Status = 'DuplicateIdNumer'
            $global:DevicesBatchTemp += $device
            $DevicesLockTemp += $device
            Write-Log ERROR -Message "There are more than one active device with the following Id Number: $($exist.id)" -logfile $logs
        }
    }else{
        $err++
        $device.Status = 'NoExist'
        $global:DevicesBatchTemp += $device
        $DevicesLockTemp += $device
        Write-Log ERROR -Message "There is not a device with the following Id number: $($device.id)" -logfile $logs
    }
}

$DevicesLockTemp | Export-Csv -Path $finalResult -NoTypeInformation


<#

Get-LostModeEnable -DeviceId '5de03504-9e6a-4a80-9a99-ae7bc3630603' -SerialNumber 'XR44Q0R6X9' #-> This will give us if the the command was sent or not.
Enable-LostMode -DeviceId '5de03504-9e6a-4a80-9a99-ae7bc3630603' -SerialNumber 'XR44Q0R6X9'
Get-LostModeStatus -DeviceId '5de03504-9e6a-4a80-9a99-ae7bc3630603' -SerialNumber 'XR44Q0R6X9' #-> This will give us the LockMode Status done for instance.
Locate-Device -DeviceId '5de03504-9e6a-4a80-9a99-ae7bc3630603' -SerialNumber 'XR44Q0R6X9'
Get-Location -DeviceId '5de03504-9e6a-4a80-9a99-ae7bc3630603' -SerialNumber 'XR44Q0R6X9'
Disable-LostMode -DeviceId '5de03504-9e6a-4a80-9a99-ae7bc3630603' -SerialNumber 'XR44Q0R6X9'
Get-DisabledLostModeStatus -DeviceId '5de03504-9e6a-4a80-9a99-ae7bc3630603' -SerialNumber 'XR44Q0R6X9'


https://graph.microsoft.com/beta/deviceManagement/manageddevices('5de03504-9e6a-4a80-9a99-ae7bc3630603')?$select=deviceactionresults,managementstate,lostModeState,deviceRegistrationState,ownertype

#>