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
Function Get-MsGraphData($Path) {
    Get-AccessToken
    $FullUri = "https://graph.microsoft.com/beta/$Path"
    $authHeader = @{
        'Content-Type'='application/json'
        'Authorization'="Bearer " + $token
    }
    [System.Collections.Generic.List[PSObject]]$Collection = @()
    $NextLink = $FullUri

    do {
        $Result = Invoke-RestMethod -Method Get -Uri $NextLink -Headers $AuthHeader
        if($Result.'@odata.count'){
            $Result.value | ForEach-Object{$Collection.Add($_)}
        } else {
            $Collection.Add($Result)
        }
        $NextLink = $Result.'@odata.nextLink'
    } while ($NextLink)

    return $Collection
}


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

$AppId = "fa9a8af1-5f19-45b6-b957-744255ea9cc0"
$client_secret = "5Fs8Q~AILt5JwMW4KtWR3DQmjKrzRpAUrKqx4bQS"
$Tenant = "alexusapcus.onmicrosoft.com"
$authority = "https://login.windows.net/$tenant"

$OutputFolder = "C:\temp"
$logs = $OutputFolder + "\logsSunlife.csv"

Get-AccessToken
$uri = "deviceManagement/managedDevices?" + '$select' + "=id,azureADDeviceId,azureADRegistered,deviceName,userPrincipalName,usersLoggedOn&" + '$filter' + "=operatingSystem eq 'Windows' and userPrincipalName eq 'alextech3@alextech.us'"
$uri = [System.Uri]::EscapeUriString($uri)
$allWindowsDevices = Get-MsGraphData -Path $uri
#$allWindowsDevices.Count
#$allWindowsDevices.usersLoggedOn.userId

### From here
ForEach($device in $allWindowsDevices){
    $deviceID = $device.id
    $userId = $device.usersLoggedOn.userId #Last logged On user
    If($userId){
        $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices('$($deviceID)')/users?" + '$select=id'
        Get-AccessToken
        $primary = (Invoke-MSGraphRequest -Url $uri -HttpMethod GET).value.id #Primary User
        If($userId -ne $primary){
            $uri ="https://graph.microsoft.com/beta/deviceManagement/managedDevices('$deviceID')/users/`$ref"
            $Body = @{"@odata.id" = "https://graph.microsoft.com/beta/users/$userId"}
            $Method = "POST"
            try{
                Write-Host "Success Device: $($device.deviceName)" -ForegroundColor Yellow
                Get-AccessToken
                Invoke-MSGraphRequest -HttpMethod $Method -Url $uri -Content $Body
                Write-Log DEBUG -Message "Primary user set to Device $($device.deviceName)" -logfile $logs
            }catch{
                Write-Host "Errors Device: $($device.deviceName)" -ForegroundColor Red
                $ex = $error[0].Exception
                Write-Log FATAL -Message "Error to set the Primary user to the device $($device.deviceName), Error: $($ex)" -logfile $logs
                #Write-Host "Error: $($ex)" -ForegroundColor red -BackgroundColor Yellow
            }
        }else{
            Write-Host "The last logged on user is the same than the Primary user on the Device: $($device.deviceName)" -ForegroundColor Yellow
            Write-Log -Message "The last logged on user is the same than the Primary user on the Device: $($device.deviceName)" -Level WARN -logfile $logs
        }
    }else{
        Write-Host "No user ID information in the usersLoggedOn attribute Device: $($device.deviceName)" -ForegroundColor Red
        Write-Log ERROR -Message "No user ID information in the usersLoggedOn attribute Device $($device.deviceName)" -logfile $logs
    }
}






<#



$userId = 'deb7498c-bb0b-4140-bdf7-b3323e42cc21'
$deviceID = '8ea46109-f33f-45b4-a313-40f831e06735'


$DevicesCSV = Import-Csv C:\Alex\Customers\SunLife\PrimaryUserDelete_3_Test_Devices.csv

ForEach($device in $DevicesCSV){
    #Check if the device exist
    $checkDevice = Get-IntuneManagedDevice -Filter ("deviceName eq 'AUTOPILOT-06419'")
    #If device exist then check if the user exist
    $uri = 'https://graph.microsoft.com/beta/users?$select=id,displayName,userPrincipalName&$filter=displayName eq ' + "admin"
    $checkUser = Invoke-RestMethod -Method Get -Uri $uri

    If ($checkDevice){

    }

}



#remove Principal User
$graphApiVersion = "beta"
    $Resource = "deviceManagement/managedDevices('$IntuneDeviceId')/users/`$ref"
    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Delete
    }



$IntuneDeviceId = '8ea46109-f33f-45b4-a313-40f831e06735'
Invoke-MSGraphRequest -Url $Resource -HttpMethod DELETE



#Adding a Principal User
$MostFrequentUserid = 'deb7498c-bb0b-4140-bdf7-b3323e42cc21'
$IntuneDeviceID = '8ea46109-f33f-45b4-a313-40f831e06735'


$uri ="https://graph.microsoft.com/beta/deviceManagement/managedDevices('$IntuneDeviceID')/users/`$ref"
$Body = @{"@odata.id" = "https://graph.microsoft.com/beta/users/$MostFrequentUserid"}
$Method = "POST"

if ($ExecutionMode -ne "Test"){
    Invoke-MSGraphRequest -HttpMethod $Method -Url $uri -Content $Body
    #Invoke-MgGraphRequest -Method $Method -uri $uri -body $Body}
else{
    if (!$MostFrequentUserPrincipalname){
        write-Output "Device $($IntuneDevice.DeviceName) has no logins last 30 days"
    }
    else {
        write-Output "Device $($IntuneDevice.DeviceName) have correct Primary User"
    }
}

#>





