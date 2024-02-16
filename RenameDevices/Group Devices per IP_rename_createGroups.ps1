

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

function Check-IPInRange {
    param(
        [Parameter(Mandatory=$true)]
        [string]$IP,
        [Parameter(Mandatory=$true)]
        [string]$CIDR
    )

    function ConvertTo-BinaryIP {
        param(
            [string]$IP
        )
        $binaryIP = $IP -split "\." | ForEach-Object {
            [convert]::ToString($_, 2).PadLeft(8, '0')
        }
        return ($binaryIP -join '')
    }

    $cidrParts = $CIDR -split "\/"
    $baseIP = $cidrParts[0]
    $subnetLength = [int]$cidrParts[1]

    $binaryIP = ConvertTo-BinaryIP -IP $IP
    $binaryBaseIP = ConvertTo-BinaryIP -IP $baseIP

    $networkPortionIP = $binaryIP.Substring(0, $subnetLength)
    $networkPortionBaseIP = $binaryBaseIP.Substring(0, $subnetLength)

    return $networkPortionIP -eq $networkPortionBaseIP
}

function Check-CIDROverlap_No {
    param(
        [string]$CsvFilePath
    )

    # Function to convert CIDR to IP range represented as integers
    function Convert-CIDRToRange {
        param(
            [string]$CIDR
        )

        $split = $CIDR -split '/'
        $ip = $split[0]
        $subnetSize = $split[1]
        $ipAddress = [System.Net.IPAddress]::Parse($ip)
        $ipBytes = $ipAddress.GetAddressBytes()
        [Array]::Reverse($ipBytes)
        $ipUint = [System.BitConverter]::ToUInt32($ipBytes, 0)

        $maskUint = [uint32]::MaxValue - ([math]::Pow(2, (32 - $subnetSize)) - 1)
        $startUint = $ipUint -band $maskUint
        $endUint = $startUint + [math]::Pow(2, (32 - $subnetSize)) - 1

        return [PSCustomObject]@{
            StartUInt = $startUint
            EndUInt = $endUint
            CIDR = $CIDR
        }
    }

    # Read the CSV file
    $cidrRanges = Import-Csv -Path $CsvFilePath

    # Convert CIDR ranges to start and end IPs represented as integers
    $ipRanges = $cidrRanges.CIDR | ForEach-Object {
        Convert-CIDRToRange -CIDR $_
    }

    # Check for overlaps
    for ($i = 0; $i -lt $ipRanges.Count; $i++) {
        for ($j = $i + 1; $j -lt $ipRanges.Count; $j++) {
            $range1 = $ipRanges[$i]
            $range2 = $ipRanges[$j]

            if (($range1.StartUInt -le $range2.EndUInt) -and ($range2.StartUInt -le $range1.EndUInt)) {
                #Write-Host "Overlap found between ranges $i and $j"
                Write-Host "Overlap found between $($range1.CIDR) and $($range2.CIDR) " -ForegroundColor Yellow
            }
        }
    }
}

function Check-CIDROverlap {
    param(
        [array]$cvsarray
    )

    # Function to convert CIDR to IP range represented as integers
    function Convert-CIDRToRange {
        param(
            [string]$CIDR
        )

        $split = $CIDR -split '/'
        $ip = $split[0]
        $subnetSize = $split[1]
        $ipAddress = [System.Net.IPAddress]::Parse($ip)
        $ipBytes = $ipAddress.GetAddressBytes()
        [Array]::Reverse($ipBytes)
        $ipUint = [System.BitConverter]::ToUInt32($ipBytes, 0)

        $maskUint = [uint32]::MaxValue - ([math]::Pow(2, (32 - $subnetSize)) - 1)
        $startUint = $ipUint -band $maskUint
        $endUint = $startUint + [math]::Pow(2, (32 - $subnetSize)) - 1

        return [PSCustomObject]@{
            StartUInt = $startUint
            EndUInt = $endUint
            CIDR = $CIDR
        }
    }

    # Read the CSV file
    #$cidrRanges = Import-Csv -Path $CsvFilePath

    # Convert CIDR ranges to start and end IPs represented as integers
    $ipRanges = $cvsarray.CIDR | ForEach-Object {
        Convert-CIDRToRange -CIDR $_
    }

    $overlaps = @()
    # Check for overlaps
    for ($i = 0; $i -lt $ipRanges.Count; $i++) {
        for ($j = $i + 1; $j -lt $ipRanges.Count; $j++) {
            $range1 = $ipRanges[$i]
            $range2 = $ipRanges[$j]

            if (($range1.StartUInt -le $range2.EndUInt) -and ($range2.StartUInt -le $range1.EndUInt)) {
                #Write-Host "Overlap found between ranges $i and $j"
                Write-Host "Overlap found between $($range1.CIDR) and $($range2.CIDR) " -ForegroundColor Yellow
                $overlaps+=[PSCustomObject]@{
                    CIRD1 = $($range1.CIDR);
                    CIRD2 = $($range2.CIDR)
                }
            }
        }
    }
    Return $overlaps
}

function Change-DeviceCategory {
	param(
		[Parameter(Mandatory)]
		[string]$DeviceID,

		[Parameter(Mandatory)]
		[string]$DeviceCategoryID
	)

    $graphUri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$DeviceId/deviceCategory/`$ref"
    $body = @{ "@odata.id" = "https://graph.microsoft.com/beta/deviceManagement/deviceCategories/$DeviceCategoryID" }

    try {
        Invoke-GraphRequest -Method PUT -Uri $graphUri -Body $body
    }
    catch {
        Write-Error "Failed to update device category. Error: $_"
    }
}

function Check-IPInCIDRRangeAllCIRDatonece {
    param(
        [string]$IPAddress,
        [array]$csvarray
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
    foreach ($cidr in $csvarray) {
        $range = Convert-CIDRToRange $cidr.CIDR
        if ($ipUInt -ge $range.Start -and $ipUInt -le $range.End) {
            $ranges += [PSCustomObject]@{
                CIDR = $cidr.CIDR
                IP = $IPAddress
                Store = $cidr.Store
                Banner = $cidr.Banner
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
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }


}

##############################
#  Connection and Variables  #
##############################
#Install-Module Microsoft.Graph.Intune
#Import-Module Microsoft.Graph.Intune
#Install-Module get-JWTDetails


$AppId = "xxxxxxxxxxxxxxxx"
$client_secret = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
$Tenant = "tenantName.onmicrosoft.com"
$authority = "https://login.windows.net/$tenant"


#$RequiredScopes = ("DeviceManagementManagedDevices.Read.All", "DeviceManagementManagedDevices.ReadWrite.All", "AuditLog.Read.All", "User.Read.All")
#Connect-MgGraph -Scope $RequiredScopes


###################################
#     Get all Android Devices     #
###################################
Get-AccessToken

$csvPath = "C:\temp\devicesGroupIPRange.csv"
$csvIPRanges = Import-Csv -Path $csvPath
$logfile = "C:\temp\Rename_Devices_Log" + [DateTime]::Now.ToString("yyyy_MM_dd_HH_mm_ss") + ".csv"


## First validate that IP addresse Rages don't overlap:

$overlap = Check-CIDROverlap -cvsarray $csvIPRanges

If(@($overlap).Count -gt 0){
    Write-Host "There are CIRD address that are overlapping, please fix this issue before continuing, you will find all the CIDR that are overlapping on this location: $(Split-Path $csvPath)\CIRDOverlaps.csv" -ForegroundColor Red -BackgroundColor Yellow
    $overlap | Export-Csv -Path "$(Split-Path $csvPath)\CIRDOverlaps.csv" -Delimiter "," -NoTypeInformation
    #exit
    Write-Log -Level INFO -Message "No overlap CIDR" -logfile $logfile
}

$allAndroid = Get-MgDeviceManagementManagedDevice -Filter ("operatingSystem eq 'Android'") -Select id,azureADDeviceId,deviceName,deviceCategoryDisplayName, manufacturer,Model,imei,serialNumber,managedDeviceOwnerType,phoneNumber,operatingSystem,lastSyncDateTime,deviceEnrollmentType,operatingSystem -All

Write-Host "Total device to review: $($allAndroid.Count)" -ForegroundColor DarkMagenta

If(@($allAndroid).Count){
    Write-Log -Level INFO -Message "Total of devices to go through $(@($allAndroid).Count)" -logfile $logfile
}else{
    Write-Log -Level FATAL -Message "No devices were found" -logfile $logfile
    #Exit
}


$devicesHarwareinfo = @()
$c = 0
$startTime = Get-Date
ForEach($Android in $allAndroid){
    # Get Access Token every 5 min
    $currentTime = Get-Date
    $elapsedTime = $currentTime - $startTime
    If($elapsedTime.TotalMinutes -gt 5){
        Get-AccessToken
    }
    $c++
    #Write-Host "Device $c" -ForegroundColor Yellow
    #Getting the Hardware information
    $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($Android.id)?`$select=hardwareInformation"
    $deviceinfo = Invoke-GraphApiRequest -Uri $uri -Method GET -AccessToken $token
    $tempOject = New-Object PSObject -Property @{
        DeviceName = $Android.deviceName
        DeviceID = $Android.Id
        AzureDeviceID = $Android.azureADDeviceId
        Category = $Android.deviceCategoryDisplayName
        IP = $deviceinfo.hardwareInformation.ipAddressV4
        imei = $Android.imei
        Serial = $Android.serialNumber
        Model = $Android.Model
        EnrollmentType = $Android.deviceEnrollmentType
        OS = $Android.operatingSystem
    }
    $devicesHarwareinfo += $tempOject
    If($tempOject.IP){
        $y=0
        <# This Loop will go over every IP range every time which could consume too much time <--
        ForEach($iprange in $csvIPRanges){
                $validateIP = Check-IPInRange -CIDR $iprange.CIDR -IP $tempOject.IP
                If($validateIP){
                    Write-Host "The device $($Android.DeviceName) has the IP: $($tempOject.IP) that belongs to the CIDR $($iprange.IPRange) and the Category: $($iprange.Category)" -ForegroundColor Green
                }
            }
        #>
        $checkIPvsCIDR = Check-IPInCIDRRangeAllCIRDatonece -IPAddress $tempOject.IP -csvarray $csvIPRanges

        switch (@($checkIPvsCIDR).Count) {
            {$_ -eq 1}{
                Write-Host "We found a CIRD: $($checkIPvsCIDR.CIDR) that contains the IP address: $($checkIPvsCIDR.IP) Store: $($checkIPvsCIDR.Store)" -ForegroundColor Green
                try {
                    ## Set the Device Name
                        #$tempName = "$($tempOject.OS)-$($checkIPvsCIDR.Banner)-$($checkIPvsCIDR.Store)-$($tempOject.Model)-$($tempOject.Serial)-$($tempOject.EnrollmentType)"
                        $tempName = "$($tempOject.OS)-$($tempOject.Model)-$($tempOject.EnrollmentType)"
                        $devicNameTemp = "$($tempName -replace ' ','')"
                        If($tempOject.DeviceName -ne $devicNameTemp){
                            If($devicNameTemp.Length -gt 62){
                                Write-Host "The device name $($devicNameTemp) lenght is higher than 62 characters" -ForegroundColor Red
                                Write-Log -Level ERROR -Message "The device name $($devicNameTemp) lenght is higher than 62 characters" -logfile $logfile
                            }else{
                                Set-DeviceName -deviceID $tempOject.DeviceID -deviceName $devicNameTemp -ManagedName $devicNameTemp
                                Write-Log -Level INFO -Message "The devices Name was change from $($tempOject.DeviceName) to $($devicNameTemp)" -logfile $logfile
                            }
                        }else{
                            Write-Host "The device $($tempOject.DeviceID) was already names as $($tempOject.DeviceName)" -ForegroundColor Red
                            Write-Log -Level WARN -Message "The device $($tempOject.DeviceID) was already names as $($tempOject.DeviceName)" -logfile $logfile
                        }

                    ## Set the Azure Extention Attribute
                        $azureDevice = Get-MgDevice -Filter ("DeviceId eq '$($tempOject.AzureDeviceID)'")
                        If($azureDevice){
                            Set-ExtAttribute -extentionAttribute ExtensionAttribute10 -deviceID $tempOject.AzureDeviceID -value $checkIPvsCIDR.Store
                            Write-Log -Level INFO -Message "Attribute ExtensionAttribute10 was set properlly to the device $($tempOject.Serial) Name: $($devicNameTemp)" -logfile $logfile
                        }else{
                            Write-Host "There are no Azure device with the id $($tempOject.AzureDeviceID)" -f Red
                            Write-Log -Level WARN -Message "There are no Azure device with the id $($tempOject.AzureDeviceID)" -logfile $logfile
                        }
                    }
                catch {
                    Write-Host "Failed to get Device List with error: $($_.Exception.Message)" -f Red
                    Write-Log ERROR -Message "Failed to get Device List with error: $($_.Exception.Message)" -logfile $logfile
                }
            }
            {$_ -gt 1}{
                Write-Host "There are $(@($checkIPvsCIDR).Count) CIDR that are matching the IP address $($tempOject.IP) please fix this issue `n $($checkIPvsCIDR.CIDR)" -ForegroundColor Red
                Write-Log -Level WARN -Message "There are $(@($checkIPvsCIDR).Count) CIDR that are matching the IP address $($tempOject.IP) please fix this issue `n $($checkIPvsCIDR.CIDR)" -logfile $logfile
            }
            Default {
                Write-Host "There are no CIRD that contain the IP: $($checkIPvsCIDR.IP)" -ForegroundColor Red -BackgroundColor Yellow
                Write-Log -Level WARN -Message "There are no CIRD that contain the IP: $($checkIPvsCIDR.IP)" -logfile $logfile
            }
        }

    }else{
        Write-Host "Device $($Android.DeviceName) with no IP information" -ForegroundColor Red
        Write-Log -Level WARN -Message "Device $($Android.DeviceName) with no IP information" -logfile $logfile
    }
}


## Create the Dynamic Groups

## Create the Dynamic Group
$uniqueStores = $csvIPRanges.Store | Sort-Object | Get-Unique
ForEach($store in $uniqueStores){
    try {
        $groupName = "Store-$($store)-Graph"
        $checkGroup = Get-MgGroup -Filter ("displayName eq '$groupName'")
        If($checkGroup){
            Write-Host "There is already a group with the name $groupName" -ForegroundColor Yellow
            Write-Log -Level WARN "There is already a group with the name $groupName" -logfile $logfile
        }else{
            New-MgGroup -DisplayName $groupName `
                -Description "Thi is a Dynamic group created from Powershell group name $($groupName)" `
                -GroupTypes DynamicMembership `
                -MailEnabled:$False `
                -MailNickname "$($groupName -replace ' ','')" `
                -MembershipRule "(device.extensionAttribute10 eq `"$($store)`")" `
                -MembershipRuleProcessingState On `
                -SecurityEnabled
            Write-Log -Level INFO "New group was created with the Name $($groupName)" -logfile $logfile
        }
    }
    catch {
        Write-Host "Failed to update device category. Error: $_" -ForegroundColor Red
        Write-Log -Level ERROR -Message "Failed to update device category. Error: $_" -logfile $logfile
    }

}



