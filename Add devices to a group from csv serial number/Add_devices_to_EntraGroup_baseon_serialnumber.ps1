<#
.SYNOPSIS
    Adds Intune devices to Entra groups based on serial numbers from a CSV file.

.DESCRIPTION
    This script reads a CSV file containing SerialNumber and GroupId columns, finds matching devices in Intune,
    gets their corresponding Entra devices, and adds them to specified Entra groups. Supports two modes:
    1. Use GroupId from CSV for each device
    2. Use a single GroupId variable for all devices

.PARAMETER CsvPath
    Path to the CSV file containing SerialNumber and GroupId columns

.PARAMETER SingleGroupId
    Optional. If specified, all devices will be added to this group instead of using CSV GroupId values

.PARAMETER WhatIf
    Shows what would happen without making actual changes

.EXAMPLE
    .\Add-DevicesToGroups.ps1 -CsvPath "C:\devices.csv"

.EXAMPLE
    .\Add-DevicesToGroups.ps1 -CsvPath "C:\devices.csv" -SingleGroupId "12345678-1234-1234-1234-123456789abc"

.Requirements
    - Microsoft Graph PowerShell SDK: Install-Module Microsoft.Graph -Scope CurrentUser
    - Permissions: Device.ReadWrite.All, Group.ReadWrite.All, GroupMember.ReadWrite.All, DeviceManagementManagedDevices.Read.All
#>

#param(
#    [Parameter(Mandatory = $true)]
#    [string]$CsvPath,
#
#    [Parameter(Mandatory = $false)]
#    [string]$SingleGroupId,
#
#    [Parameter(Mandatory = $false)]
#    [switch]$WhatIf
#)

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




$CsvPath = "C:\temp\SerialNumbers.csv"
$SingleGroupId = "18cc3227-6342-40d4-b73d-3c33feb1096d"
$WhatIf = $false

# Function to connect to Microsoft Graph
function Connect-ToMSGraph {
    try {
        # Check if already connected
        $context = Get-MgContext
        if ($null -eq $context) {
            Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
            # Connect with required permissions for both Intune and Entra
            Connect-MgGraph -Scopes "Device.ReadWrite.All", "Group.ReadWrite.All", "GroupMember.ReadWrite.All", "DeviceManagementManagedDevices.Read.All"
        }
        Write-Host "Connected to Microsoft Graph successfully" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
        exit 1
    }
}

# Function to get Intune device by serial number
function Get-DeviceBySerialNumber {
    param([string]$SerialNumber)

    try {
        Write-Host "Searching for Intune device with serial number: $SerialNumber" -ForegroundColor Gray

        # Search for device in Intune using the deviceManagement endpoint
        # Method 1: Direct filter by serialNumber
        $device = Get-MgDeviceManagementManagedDevice -Filter "serialNumber eq '$SerialNumber'" -ErrorAction SilentlyContinue

        if ($null -eq $device -or $device.Count -eq 0) {
            Write-Host "Direct filter search failed, trying alternative search..." -ForegroundColor Gray

            # Method 2: Get all devices and filter (use carefully with large environments)
            # You might want to add pagination or additional filters here
            $allDevices = Get-MgDeviceManagementManagedDevice -All -ErrorAction SilentlyContinue
            $device = $allDevices | Where-Object { $_.SerialNumber -eq $SerialNumber }
        }

        if ($null -eq $device -or $device.Count -eq 0) {
            Write-Host "Device with serial number $SerialNumber not found in Intune" -ForegroundColor Yellow
            return $null
        }

        # If multiple devices found (shouldn't happen with serial numbers, but just in case)
        if ($device -is [array] -and $device.Count -gt 1) {
            Write-Warning "Multiple devices found with serial number $SerialNumber. Using first match."
            $device = $device[0]
        }

        Write-Host "Found Intune device: $($device.DeviceName) (ID: $($device.Id), Azure AD Device ID: $($device.AzureAdDeviceId))" -ForegroundColor Green
        return $device

    }
    catch {
        Write-Warning "Error searching for Intune device with serial number $SerialNumber : $($_.Exception.Message)"
        return $null
    }
}

# Function to get corresponding Entra device from Intune device
function Get-EntraDeviceFromIntuneDevice {
    param([object]$IntuneDevice)

    try {
        if ([string]::IsNullOrWhiteSpace($IntuneDevice.AzureAdDeviceId)) {
            Write-Warning "Intune device $($IntuneDevice.DeviceName) does not have an Azure AD Device ID"
            return $null
        }

        # Get the corresponding Entra device using the Azure AD Device ID
        $_deviceID = $IntuneDevice.AzureAdDeviceId
        $entraDevice = Get-MgDevice -Filter "DeviceId eq '$($_deviceID)'" -ErrorAction SilentlyContinue

        if ($null -eq $entraDevice) {
            Write-Warning "Could not find Entra device with ID $($_deviceID) for Intune device $($IntuneDevice.DeviceName)"
            return $null
        }

        Write-Host "Found corresponding Entra device: $($entraDevice.DisplayName) (ID: $($entraDevice.Id))" -ForegroundColor Green
        return $entraDevice

    }
    catch {
        Write-Warning "Error getting Entra device for Intune device $($IntuneDevice.DeviceName): $($_.Exception.Message)"
        return $null
    }
}

# Function to add device to group
function Add-DeviceToGroup {
    param(
        [string]$DeviceId,
        [string]$GroupId,
        [string]$SerialNumber,
        [bool]$WhatIfPreference
    )

    try {
        # Check if device is already in the group
        $existingMember = Get-MgGroupMember -GroupId $GroupId | Where-Object { $_.Id -eq $DeviceId }

        if ($existingMember) {
            Write-Host "Device $SerialNumber is already a member of group $GroupId" -ForegroundColor Yellow
            return $true
        }

        if ($WhatIfPreference) {
            Write-Host "WHATIF: Would add device $SerialNumber (ID: $DeviceId) to group $GroupId" -ForegroundColor Cyan
            return $true
        }

        # Add device to group
        $body = @{
            "@odata.id" = "https://graph.microsoft.com/v1.0/devices/$DeviceId"
        }

        New-MgGroupMember -GroupId $GroupId -BodyParameter $body
        Write-Host "Successfully added device $SerialNumber to group $GroupId" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to add device $SerialNumber to group $GroupId : $($_.Exception.Message)"
        return $false
    }
}

# Function to validate group exists
function Test-GroupExists {
    param([string]$GroupId)

    try {
        $group = Get-MgGroup -GroupId $GroupId -ErrorAction SilentlyContinue
        return $null -ne $group
    }
    catch {
        return $false
    }
}

# Main script execution
try {
    Write-Host "Starting device group assignment script..." -ForegroundColor Cyan

    # Validate CSV file exists
    if (-not (Test-Path $CsvPath)) {
        Write-Error "CSV file not found: $CsvPath"
        exit 1
    }

    # Connect to Microsoft Graph
    Connect-ToMSGraph

    # Read CSV file
    Write-Host "Reading CSV file: $CsvPath" -ForegroundColor Yellow
    $csvData = Import-Csv -Path $CsvPath

    # Validate CSV structure
    if (-not ($csvData | Get-Member -Name "SerialNumber" -MemberType NoteProperty)) {
        Write-Error "CSV file must contain a 'SerialNumber' column"
        exit 1
    }

    if (-not $SingleGroupId -and -not ($csvData | Get-Member -Name "GroupId" -MemberType NoteProperty)) {
        Write-Error "CSV file must contain a 'GroupId' column when not using -SingleGroupId parameter"
        exit 1
    }

    # Validate single group if specified
    if ($SingleGroupId) {
        Write-Host "Validating single group ID: $SingleGroupId" -ForegroundColor Yellow
        if (-not (Test-GroupExists -GroupId $SingleGroupId)) {
            Write-Error "Group with ID $SingleGroupId not found"
            exit 1
        }
        Write-Host "Single group validated successfully" -ForegroundColor Green
    }

    # Initialize counters
    $processedCount = 0
    $successCount = 0
    $deviceNotFoundCount = 0
    $entraDeviceNotFoundCount = 0
    $errorCount = 0

    # Process each row in CSV
    foreach ($row in $csvData) {
        $processedCount++
        $serialNumber = $row.SerialNumber.Trim()
        $groupId = if ($SingleGroupId) { $SingleGroupId } else { $row.GroupId.Trim() }

        Write-Host "`nProcessing device $processedCount of $($csvData.Count): $serialNumber" -ForegroundColor Cyan

        # Skip if serial number is empty
        if ([string]::IsNullOrWhiteSpace($serialNumber)) {
            Write-Warning "Skipping empty serial number in row $processedCount"
            continue
        }

        # Validate group ID if using CSV values
        if (-not $SingleGroupId) {
            if ([string]::IsNullOrWhiteSpace($groupId)) {
                Write-Warning "Skipping device $serialNumber - empty GroupId"
                continue
            }

            if (-not (Test-GroupExists -GroupId $groupId)) {
                Write-Warning "Group $groupId not found for device $serialNumber"
                $errorCount++
                continue
            }
        }

        # Find Intune device by serial number
        $intuneDevice = Get-DeviceBySerialNumber -SerialNumber $serialNumber

        if ($null -eq $intuneDevice) {
            Write-Warning "Device with serial number $serialNumber not found in Intune"
            $deviceNotFoundCount++
            continue
        }

        # Get corresponding Entra device
        $entraDevice = Get-EntraDeviceFromIntuneDevice -IntuneDevice $intuneDevice

        if ($null -eq $entraDevice) {
            Write-Warning "Could not find corresponding Entra device for Intune device $($intuneDevice.DeviceName)"
            $entraDeviceNotFoundCount++
            continue
        }

        # Add Entra device to group
        $success = Add-DeviceToGroup -DeviceId $entraDevice.Id -GroupId $groupId -SerialNumber $serialNumber -WhatIfPreference $WhatIf

        if ($success) {
            $successCount++
        }
        else {
            $errorCount++
        }
    }

    # Summary
    Write-Host "`n$('='*50)`nSUMMARY`n$('='*50)" -ForegroundColor Cyan
    Write-Host "Total devices processed: $processedCount" -ForegroundColor White
    Write-Host "Successfully added to groups: $successCount" -ForegroundColor Green
    Write-Host "Intune devices not found: $deviceNotFoundCount" -ForegroundColor Yellow
    Write-Host "Entra devices not found: $entraDeviceNotFoundCount" -ForegroundColor Yellow
    Write-Host "Errors encountered: $errorCount" -ForegroundColor Red

    if ($WhatIf) {
        Write-Host "`nNote: This was a WhatIf run - no actual changes were made." -ForegroundColor Yellow
    }
}
catch {
    Write-Error "Script execution failed: $($_.Exception.Message)"
    exit 1
}
finally {
    # Disconnect from Microsoft Graph
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        Write-Host "`nDisconnected from Microsoft Graph" -ForegroundColor Yellow
    }
    catch {
        # Ignore disconnect errors
    }
}