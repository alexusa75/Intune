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



# Script to rename Intune devices based on serial numbers and send sync action
# Requires Microsoft.Graph PowerShell modules

# Parameters
param (
    [Parameter(Mandatory = $true)]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [string]$csvLogPath
)

# Install required modules if not already installed
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    Install-Module -Name Microsoft.Graph.Authentication -Force
}

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.DeviceManagement)) {
    Install-Module -Name Microsoft.Graph.DeviceManagement -Force
}

# Import required modules
Import-Module Microsoft.Graph.Authentication
Import-Module Microsoft.Graph.DeviceManagement

# Define the path to the CSV file containing device information
# CSV format should be: SerialNumber,NewDeviceName
#$csvPath = "C:\Alex\deviveName\devices.csv"
#$csvLogPath = "C:\Alex\deviveName\devicesLog.csv"

# Function to write logs to a CSV file
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

# Function to check if the CSV file exists and has the correct format
function Test-CsvFile {
    param (
        [string]$FilePath
    )

    if (-not (Test-Path -Path $FilePath)) {
        Write-Error "CSV file not found at $FilePath"
        return $false
    }

    $csvContent = Import-Csv -Path $FilePath
    $headers = ($csvContent | Get-Member -MemberType NoteProperty).Name

    if (-not ($headers -contains "SerialNumber" -and $headers -contains "NewDeviceName")) {
        Write-Host "CSV file must contain 'SerialNumber' and 'NewDeviceName' columns" -ForegroundColor Red
        return $false
    }

    return $true
}

# Function to authenticate to Microsoft Graph
function Connect-ToGraph {
    try {
        # Connect to Microsoft Graph with interactive sign-in
        #Connect-MgGraph -Scopes "DeviceManagementManagedDevices.ReadWrite.All","DeviceManagementManagedDevices.Read.All" > $null
        Connect-MgGraph -NoWelcome
        # Check if the connection was successful
        $graphContext = Get-MgContext
        If ($graphContext -eq $null) {
            Write-Host "Failed to authenticate to Microsoft Graph." -ForegroundColor Red
            return $false
        }
        Write-Host "Successfully authenticated to Microsoft Graph." -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to authenticate to Microsoft Graph: $_"
        return $false
    }
}

# Function to get device by serial number
function Get-DeviceBySerialNumber {
    param (
        [string]$SerialNumber
    )

    try {
        # Filter for managed devices by serial number
        $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=serialNumber eq '$($serialNumber)'"
        $devices_temp = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        $devices = $devices_temp.Value | Select-Object -Property id, deviceName, serialNumber, azureAdRegistered | ?{ $_.AzureAdRegistered -eq $true }
        #$devices = Get-MgDeviceManagementManagedDevice -Filter "serialNumber eq '$SerialNumber'" | ?{$_.AzureAdRegistered -eq $true}
        return $devices
    }
    catch {
        Write-Host "Error retrieving device with serial number $SerialNumber`: $_"
        return $null
    }
}

# Function to rename a device using the correct Graph API endpoint
function Set-DeviceName {
    param (
        [string]$DeviceId,
        [string]$NewName,
        [string]$serialNumber
    )

    try {

        # First check if any device already has the requested name
        $existingDeviceUri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=deviceName eq '$NewName'"
        $existingDevice = Invoke-MgGraphRequest -Method GET -Uri $existingDeviceUri -ErrorAction Stop
        if ($existingDevice.Value.Count -gt 0) {
            # Create the request body
            $body = @{
                deviceName = $NewName
            } | ConvertTo-Json

            # Use the correct endpoint with the setDeviceName action
            $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices('$DeviceId')/setDeviceName"
            Invoke-MgGraphRequest -Method POST -Uri $uri -Body $body -ContentType "application/json" -ErrorAction Stop

            Write-Host "Device name updated to $NewName for device ID $DeviceId" -ForegroundColor Green
            Write-Log -Level INFO -Message "Renaming device ID $($intuneDevice.Id) from $($intuneDevice.DeviceName) to $($device.NewDeviceName)" -logfile $csvLogPath
            return $true
        }
        else {
            Write-Host "Device with name $NewName already exists. Skipping rename for device ID $DeviceId" -ForegroundColor Yellow
            Write-Log -Level WARN -Message "Device with name $NewName already exists. Skipping rename for device ID $DeviceId" -logfile $csvLogPath
            return $false
        }
    }
    catch {
        Write-Host "Failed to update device name for device ID $DeviceId SN: $serialNumber" -ForegroundColor Red
        Write-Log -Level ERROR -Message "Failed to update device name for device ID $DeviceId`: $_ with SN: $serialNumber" -logfile $csvLogPath
        return $false
    }
}

# Function to send sync action to device
function Send-DeviceSync {
    param (
        [string]$DeviceId
    )

    try {
        # Direct Graph API call to sync device
        $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices('$DeviceId')/syncDevice"
        Invoke-MgGraphRequest -Method POST -Uri $uri -ErrorAction Stop

        Write-Host "Sync action sent to device ID $DeviceId" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to send sync action to device ID $DeviceId`: $_"
        return $false
    }
}

## Main script execution

# Check if CSV file exists and has correct format
if (-not (Test-CsvFile -FilePath $csvPath)) {
    Write-Host "Please create a CSV file at $csvPath with 'SerialNumber' and 'NewDeviceName' columns." -ForegroundColor Yellow
    Write-Log -Level ERROR -Message "Please create a CSV file at $csvPath with 'SerialNumber' and 'NewDeviceName' columns." -logfile $csvLogPath
    exit
}
# Connect to Microsoft Graph
if (-not (Connect-ToGraph)) {
    Write-Host "Failed to connect to Microsoft Graph. Exiting script." -ForegroundColor Red
    Write-Log -Level ERROR -Message "Failed to connect to Microsoft Graph. Exiting script." -logfile $csvLogPath
    exit
}
# Import device information from CSV
$devices = Import-Csv -Path $csvPath
$deviceCount = $devices.Count
Write-Host "Found $deviceCount devices in the CSV file." -ForegroundColor Yellow
$c = 0
# Process each device
foreach ($device in $devices) {
    $c++
    Write-Progress -Activity "Processing devices" -Status "Processing device $c of $deviceCount" -PercentComplete (($c / $deviceCount) * 100)
    Write-Host "`nProcessing device with serial number: $($device.SerialNumber)" -ForegroundColor Cyan
    # Get the device by serial number
    $intuneDevice = Get-DeviceBySerialNumber -SerialNumber $device.SerialNumber
    if (-not $intuneDevice) {
        Write-Host "No device found with serial number $($device.SerialNumber)" -ForegroundColor Yellow
        Write-Log -Level WARN -Message "No device found with serial number $($device.SerialNumber)" -logfile $csvLogPath
        continue
    }
    if ($intuneDevice.Count -gt 1) {
        Write-Host "Multiple devices found with serial number $($device.SerialNumber), processing the first one" -ForegroundColor Yellow
        Write-Log -Level WARN -Message "Multiple devices found with serial number $($device.SerialNumber), processing the first one" -logfile $csvLogPath
        # Select the first device if multiple are found
        $intuneDevice = $intuneDevice[0]
    }
    Write-Host "Found device: $($intuneDevice.DeviceName) (ID: $($intuneDevice.Id))"
    # Rename the device using the correct Graph API endpoint
    # Check if the new name is different from the current name
    $renameSuccess = Set-DeviceName -DeviceId $intuneDevice.Id -NewName $device.NewDeviceName -serialNumber $device.SerialNumber
    if ($renameSuccess) {
        # Send sync action
        $syncSuccess = Send-DeviceSync -DeviceId $intuneDevice.Id
        if ($syncSuccess) {
            Write-Host "Successfully processed device: Serial Number $($device.SerialNumber), New Name $($device.NewDeviceName)" -ForegroundColor Green
            Write-Log -Level INFO -Message "Successfully processed device: Serial Number $($device.SerialNumber), New Name $($device.NewDeviceName)" -logfile $csvLogPath
        }
        else {
            Write-Host "Failed to send sync action for device ID $($intuneDevice.Id) SN: $device.SerialNumber" -ForegroundColor Red
            Write-Log -Level ERROR -Message "Failed to send sync action for device ID $($intuneDevice.Id) SN: $device.SerialNumber" -logfile $csvLogPath
        }
    }
}
# Disconnect from Microsoft Graph
Disconnect-MgGraph
Write-Host "`nScript execution completed." -ForegroundColor Green



<# Few helpful commands to test the script
get-mgcontext


$serialNumber = "R9AN612W7DJ"
$deviceName = "New Name123"
$deviceId = "22813004-a0fe-414a-b751-c68897a88f34"

$NewName = "TestingDeviceName123"




Connect-MgGraph -Scopes "DeviceManagementManagedDevices.ReadWrite.All","DeviceManagementManagedDevices.Read.All", "DeviceManagementManagedDevices.PrivilegedOperations.All" -NoWelcome

$testing2 = Get-MgDeviceManagementManagedDevice -Filter "serialNumber eq '$SerialNumber'" | ?{$_.AzureAdRegistered -eq $true}

$testing =
$testing = Get-DeviceBySerialNumber -SerialNumber $serialNumber
$testing.getType()

Set-DeviceName -DeviceId $deviceId -NewName $deviceName -serialNumber $serialNumber

Send-DeviceSync -DeviceId $deviceId


# Example usage of the Graph API to set device name
$body = @{
    deviceName = $deviceName
} | ConvertTo-Json
$uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices('$DeviceId')/setDeviceName"
Invoke-MgGraphRequest -Method POST -Uri $uri -Body $body -ContentType "application/json" -ErrorAction Stop


# Direct Graph API call to sync device
$uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices('$DeviceId')/syncDevice"
Invoke-MgGraphRequest -Method POST -Uri $uri -ErrorAction Stop


# Example usage of the Graph API to get device by serial number
$uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=serialNumber eq '$($serialNumber)'"
$testing = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop

$testing3 = $testing.Value | Select-Object -Property id, deviceName, serialNumber, azureAdRegistered | ?{$_.AzureAdRegistered -eq $true} #| Format-Table -AutoSize

($testing.value).Count


$testing3 | get-member


$testing3.id

#>