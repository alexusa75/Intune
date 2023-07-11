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

Connect-MgGraph -ContextScope Process -ForceRefresh
#Get-MgContext | Select-Object -ExpandProperty Scopes
Select-MgProfile Beta

Function Get-Members {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [string]
        $GroupID
    )
    $Members = Get-MgGroupMember -GroupId $GroupID
    $userMembers = @()
    ForEach($Member in $Members){
        $users = ""|select id,DisplayName,userPrincipalName
        $users.id = $Member.Id
        $users.DisplayName = $Member.AdditionalProperties.displayName
        $users.userPrincipalName = $Member.AdditionalProperties.userPrincipalName
        $userMembers += $users
    }
    Return $userMembers
}

$Members = Get-Members -GroupID 'aca90564-bb47-4293-b0c9-4649c9c1961f'  ## <---

$Alldevices = Get-MgDeviceManagementManagedDevice -Property id,azureADDeviceId,azureADRegistered,userId,userPrincipalName,deviceName,manufacturer,imei,serialNumber,managedDeviceOwnerType,phoneNumber,operatingSystem,lastSyncDateTime -All |?{($_.operatingSystem -eq "Windows") -and ($_.azureADRegistered -ne 0)}

ForEach($Member in $Members){
    $userDevices = $Alldevices | ?{$_.userId -eq "$($Member.id)"}
    If($userDevices){
        ForEach($userDevice in $userDevices){
            $hash = @{}
            $hash["ExtensionAttribute10"] = "IT"  # <---
            $_azuredeviceId = (Get-MgDevice -Filter "DeviceId eq '$($userDevice.azureADDeviceId)'" -ErrorAction SilentlyContinue).id
            If($_azuredeviceId){
                try{
                    #$uri = "https://graph.microsoft.com/beta/devices/$()"
                    Update-MgDevice -DeviceId $_azuredeviceId -ExtensionAttributes $hash
                }
                catch{
                    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
                }

            }
        }
    }
}
