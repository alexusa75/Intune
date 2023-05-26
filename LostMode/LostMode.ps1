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
    if (!$token.Contains(".") -or !$token.StartsWith("eyJ")) { Write-Error "Invalid token" -ErrorAction Stop }else{Write-Host "Good Token"}

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
            'phoneNumber' = ''
            'footer'= ''
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


##############################
#  Connection and Variables  #
##############################
#Install-Module Microsoft.Graph.Intune
#Import-Module Microsoft.Graph.Intune
#Install-Module get-JWTDetails

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


###################################
#  Get all iOS Supervise Devices  #
###################################
Get-AccessToken

$alliOSSupervise = Get-IntuneManagedDevice -Filter ("operatingSystem eq 'iOS'") -Select id,azureADDeviceId,deviceName,manufacturer,Model,isSupervised,imei,serialNumber,managedDeviceOwnerType,phoneNumber,operatingSystem,lastSyncDateTime | Where-Object {($_.AzureADDeviceId -ne '00000000-0000-0000-0000-000000000000') -and ($_.isSupervised -eq 'true')} | Get-MSGraphAllPages

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


$batchSize = 10
for ($i = 0; $i -lt $Devices.Length; $i += $batchSize){
    # Get the current batch of data
    $Devicesbatch = $Devices[$i..($i + $batchSize - 1)]
    $c = 0
    $err = 0
    $24 = 0
    Write-Host "Started the analysis of $($batchSize) devices from Batch $([int]($i/$batchSize))" -ForegroundColor Green
    ######################
    #  Enable Lost Mode  #
    ######################
    foreach($device in $Devicesbatch){
        Get-AccessToken
        $exist = Get-IntuneManagedDevice -Filter ("serialNumber eq '$($device.serialNumber)'") -Select id,serialNumber,AzureADDeviceId,isSupervised,lastSyncDateTime | Where-Object {($_.AzureADDeviceId -ne '00000000-0000-0000-0000-000000000000') -and ($_.isSupervised -eq 'true')}
        If($exist){
            $existcount = @($exist).count
            IF($existcount -eq 1){
                $Date = (Get-Date).ToUniversalTime()
                $LastSyntTime = ($Date - ($exist.lastSyncDateTime))
                IF($LastSyntTime.Hours -lt 24){
                    try {
                        $LostModeEnable = Get-LostModeEnable -DeviceId $device.id -SerialNumber $device.serialNumber
                        If($LostModeEnable -ne 'enabled'){
                            Enable-LostMode -DeviceId $device.id -SerialNumber $device.serialNumber
                            $c++
                            $device.Status = "1-EnabledLostMode"
                            $global:DevicesBatchTemp += $device
                            #$DevicesLockTemp += $device
                            Write-Log DEBUG -Message "LostMode sent to the Device: $($exist.serialNumber)" -logfile $logs
                        }else{
                            $c++
                            $device.Status = "1-WasArreadyEnabledLostMode"
                            $global:DevicesBatchTemp += $device
                            #$DevicesLockTemp += $device
                            Write-Log DEBUG -Message "LostMode was already enabled on the Device: $($exist.serialNumber)" -logfile $logs
                        }

                    }
                    catch {
                        $err++
                        $ex = $error[0].Exception
                        $device.Status = "1-ErrorEnablingLostMode"
                        $global:DevicesBatchTemp += $device
                        #$DevicesLockTemp += $device
                        Write-Log FATAL -Message "Error enabling LostMode to Device: $($exist.serialNumber) Error: $($ex) " -logfile $logs
                    }
                }Else{
                    $24++
                    $device.Status = "1-Morethan24hours"
                    $global:DevicesBatchTemp += $device
                    #$DevicesLockTemp += $device
                    Write-Log WARN -Message "Device more than 24 hours since last sync - Device: $($exist.serialNumber)" -logfile $logs
                }
            }else{
                $ee++
                Write-Host "More than 1 active device with the same serial: $($device.serialNumber)"
                $device.Status = '1-DuplicateSerialNumer'
                $global:DevicesBatchTemp += $device
                #$DevicesLockTemp += $device
                Write-Log ERROR -Message "There are more than one active device with the following Serial Number: $($exist.serialNumber)" -logfile $logs
            }
        }else{
            $err++
            $device.Status = '1-NoExist'
            $global:DevicesBatchTemp += $device
            #$DevicesLockTemp += $device
            Write-Log ERROR -Message "There is not a device with the following serial number: $($device.serialNumber)" -logfile $logs
        }
    }
    Write-Host "    Progress:
        Enabled Lost Mode: $c
        More than 24 hours since last sync: $24
        Errors: $err
    " -ForegroundColor Yellow

    ###############################################
    #  Send the Locate device command to devices  #
    ###############################################
    Write-Host "    Sending Locate Device commands to $($batchSize) devices from Batch $([int]($i/$batchSize))" -ForegroundColor Cyan
    $devicesEnabled = $global:DevicesBatchTemp | ?{($_.Status -eq '1-EnabledLostMode') -or ($_.Status -eq '1-WasArreadyEnabledLostMode')}
    ForEach($device1 in $devicesEnabled){
        #Start-Sleep -Seconds 60
        $LostStatus = Get-LostModeStatus -DeviceId $device1.id -SerialNumber $device1.serialNumber
        If($LostStatus -eq 'done'){
            $locate = Locate-Device -DeviceId $device1.id -SerialNumber $device1.serialNumber
            If($locate -eq 'Success'){
                $global:DevicesBatchTemp | ?{$_.id -eq "$($device1.id)"} |
                    ForEach-Object{
                                    $_.Status = '2-LocationReady'
                                    #$_.longitude = $longitude
                                    #$_.latitude = $latitude
                                    #$_.altitude = $altitude
                                }

            }else{
                #$global:DevicesBatchTemp | ?{$_.id -eq "$($device1.id)"} | ForEach-Object{$_.Status = "2-LoctionComandFailed-$($locate)"}
                Disable-LostModedueToError -DeviceId $device1.id -SerialNumber $device1.serialNumber -Stage 2 -Note "2-LoctionNoReady-$($locate)"
                Write-Log ERROR -Message "Locate command failed on Device: $($device1.serialNumber)" -logfile $logs
            }

        }else{
            #$global:DevicesBatchTemp | ?{$_.id -eq "$($device1.id)"} | ForEach-Object{$_.Status = "2-LocationNotReady-$($LostStatus)"}
            Disable-LostModedueToError -DeviceId $device1.id -SerialNumber $device1.serialNumber -Stage 2 -Note "2-LocationNotReady-$($LostStatus)"
            Write-Log ERROR -Message "The device Location information was not ready, we disabled Lost Mode, no more actions Device: $($device1.serialNumber)" -logfile $logs
        }
    }

    ##################################################
    #  Get the location iformation from the devices  #
    ##################################################
    $devicesLcation = $global:DevicesBatchTemp | ?{$_.Status -eq '2-LocationReady'}
    Write-Host "    Collecing Location information from $($batchSize) devices from Batch $([int]($i/$batchSize))" -ForegroundColor Cyan
    ForEach($device2 in $devicesLcation){
        #Write-Host "Device with Location Information $($device2.serialNumber)" -ForegroundColor Cyan
        Start-Sleep -Seconds 5
        $results,$longitude,$latitude,$altitude = Get-Location -DeviceId $device2.id -SerialNumber $device2.serialNumber
        If($results -eq 'Success'){
            $global:DevicesBatchTemp | ?{$_.id -eq "$($device2.id)"} |
                ForEach-Object{
                                $_.Status = '3-LocationCollected'
                                $_.longitude = $longitude
                                $_.latitude = $latitude
                                $_.altitude = $altitude
                            }
            $disable = Disable-LostMode -DeviceId $device2.id -SerialNumber $device2.serialNumber
            If($disable -eq 'Success'){
                $global:DevicesBatchTemp | ?{$_.id -eq "$($device2.id)"} | ForEach-Object{$_.Status = "3-LostModeDisabled-AllDone"}
                Write-Log DEBUG -Message "Lost Mode disabled to Device: $($device2.serialNumber)" -logfile $logs
            }else{
                $global:DevicesBatchTemp | ?{$_.id -eq "$($device2.id)"} | ForEach-Object{$_.Status = "3-ErrorDisblingLostMode"}
                Write-Log ERROR -Message "Error to disable Lost Mode to Device: $($device2.serialNumber)" -logfile $logs
            }
         }else{
            Disable-LostModedueToError -DeviceId $device2.id -SerialNumber $device2.serialNumber -Stage 3 -Note "3-NoLocationDataAvailabe-$($results)"
            #$global:DevicesBatchTemp | ?{$_.id -eq "$($device2.id)"} | ForEach-Object{$_.Status = "NoLocationDataAvailabe-$($results)"}
            Write-Log ERROR -Message "The device Location information was not ready, we disabled Lost Mode no more actions Device: $($device2.serialNumber)" -logfile $logs
         }
    }

    ###################################################################################
    #  Last Loop to triple check if there is any device with Lost Mode still Enabled  #
    ###################################################################################
    Write-Host "    Validating if the Lost Mode was disabled to $($batchSize) devices from Batch $([int]($i/$batchSize))" -ForegroundColor Cyan
    ForEach($device3 in $DevicesBatchTemp){
        $LostModeCheck = Get-LostModeEnable -DeviceId $device3.id -SerialNumber $device3.serialNumber
        If($LostModeCheck -eq 'enabled'){
            $LostModeStuckTemp += $device3
        }
    }

    ##############################################
    #  Exporting the information for each Batch  #
    ##############################################
    If($LostModeStuckTemp){
        $LostModeStuckTemp | Export-Csv -Path $LostModeStuckedOutput -NoTypeInformation -Append
        $LostModeStuckTemp = @()
    }
    $DevicesLockTemp += $global:DevicesBatchTemp
    $finalresultTemp = $finalResult.Split('.')[0] + "_Temp." + $finalResult.Split('.')[1]
    $global:DevicesBatchTemp | Export-Csv -Path $finalresultTemp -NoTypeInformation -Append
    $global:DevicesBatchTemp = @()
    Write-Host "Finished Batch Number -- $([int]($i/$batchSize)) - DateTime: $(Get-Date)`n" -ForegroundColor Magenta
}

$DevicesLockTemp | Export-Csv -Path $finalResult -NoTypeInformation

