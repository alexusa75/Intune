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


#For deatails about the installation of Microsoft Graph SDK please review the following article:
# https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation?view=graph-powershell-1.0

#Install-Module Microsoft.Graph -Scope CurrentUser

####################
#  Authentication  #
####################
#In this case you should use an Intune administrator
#Connect-MgGraph -ForceRefresh -Scopes "DeviceManagementManagedDevices.Read.All", "DeviceManagementManagedDevices.ReadWrite.All", "DeviceManagementApps.Read.All", "DeviceManagementApps.ReadWrite.All"
Connect-MgGraph -ForceRefresh -Scopes "DeviceManagementApps.Read.All"

###############
#  Functions  #
###############
Function Get-httprequest(){
    [cmdletbinding()]
    param(
        $NextPage
    )
    try{
        $graphApiVersion = "Beta"
        $Resource = "/deviceAppManagement/managedAppStatuses('appregistrationsummary')?fetch=6000&policyMode=0&columns=AccountId,UserId,DisplayName,UserEmail,IntuneLicensed,ApplicationId,ApplicationVersion,SdkVersion,ApplicationName,ApplicationInstanceId,CreatedDate,LastCheckInDate,Platform,PlatformVersion,DeviceId,DeviceType,DeviceName,DeviceHealth,DeviceModel,DeviceManufacturer,AndroidPatchVersion,AzureADDeviceId,MDMDeviceID,ManagementLevel,PolicySource,PolicyId,PolicyName,PolicyDescription,ComplianceState"
        if ($NextPage -ne "" -and $NextPage -ne $null) {
            $Resource += "&seek=$NextPage"
        }
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-GraphRequest -Method GET -Uri $uri
    }
    catch{
        write-host $_.Exception.Message -f Red
        write-host $_.Exception.ItemName -f Red
        write-host
        break
    }

}

#################
#  Output file  #
#################
$ExportPath = "c:\Alex\AppRegistrationSummary_" + [DateTime]::Now.ToString("yyyy_MM_dd_HH_mm_ss") + ".csv"


######################
#  Http GET request  #
######################
Select-MgProfile Beta
$httprequest = Get-httprequest
$stream = [System.IO.StreamWriter]::new("$ExportPath", $false, [System.Text.Encoding]::UTF8)
$stream.WriteLine([string]($httprequest.content.header | % {$_.columnName + "," } ))
do {
    $MoreItem = $httprequest.content.skipToken -ne "" -and $httprequest.content.skipToken -ne $null
    foreach ($http in $httprequest.content.body) {
        $stream.WriteLine([string]($http.values | %{($_ -replace ",",".")+","}))
    }
        if ($MoreItem){
        $httprequest = Get-httprequest -NextPage ($httprequest.content.skipToken)
    }
} while ($MoreItem)
$stream.close()