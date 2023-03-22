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

[CmdletBinding()]
param (
    [Parameter()]
    [ValidateNotNullorEmpty()]
    [string]$CSVOutput = [Environment]::GetFolderPath("Desktop") + "\gpopoliciesanalysis.csv"
)


##############################
#  Connection and Variables  #
##############################
#Install-Module Microsoft.Graph.Intune
#Import-Module Microsoft.Graph.Intune
Connect-MsGraph | out-null
#Disconnect-MgGraph


###############
#  Functions  #
###############

function Get-Token {
    param ()
    $clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
    $redirectUrl = [System.Uri]"urn:ietf:wg:oauth:2.0:oob" # This is the standard Redirect URI for Windows Azure PowerShell
    $tenant = "alexusapcus.onmicrosoft.com"
    $resource = "https://graph.microsoft.com/";
    $serviceRootURL = "https://graph.microsoft.com//$tenant"
    $authUrl = "https://login.microsoftonline.com/$tenant";

    $postParams = @{ resource = "$resource"; client_id = "$clientId" }
    $response = Invoke-RestMethod -Method POST -Uri "$authurl/oauth2/devicecode" -Body $postParams
    Write-Host $response.message


    #Copy the code to clipboard automatically
    $code = ($response.message -split "code " | Select-Object -Last 1) -split " to authenticate."
    Set-Clipboard -Value $code
    #Start-Process "https://microsoft.com/devicelogin"
    Add-Type -AssemblyName System.Windows.Forms

    $form = New-Object -TypeName System.Windows.Forms.Form -Property @{ Width = 440; Height = 640 }
    $web = New-Object -TypeName System.Windows.Forms.WebBrowser -Property @{ Width = 440; Height = 600; Url = "https://www.microsoft.com/devicelogin" }

    $web.Add_DocumentCompleted($DocComp)
    $web.DocumentText

    $form.Controls.Add($web)
    $form.Add_Shown({ $form.Activate() })
    $web.ScriptErrorsSuppressed = $true

    $form.AutoScaleMode = 'Dpi'
    $form.text = "Graph API Authentication, Ctr+V to paste the code"
    $form.ShowIcon = $False
    $form.AutoSizeMode = 'GrowAndShrink'
    $Form.StartPosition = 'CenterScreen'


    $form.ShowDialog() | Out-Null

    $tokenParams = @{ grant_type = "device_code"; resource = "$resource"; client_id = "$clientId"; code = "$($response.device_code)" }

    $tokenResponse = $null

    try
    {
        $tokenResponse = Invoke-RestMethod -Method POST -Uri "$authurl/oauth2/token" -Body $tokenParams
    }
    catch [System.Net.WebException]
    {
        if ($_.Exception.Response -eq $null)
        {
            throw
        }

        $result = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($result)
        $reader.BaseStream.Position = 0
        $errBody = ConvertFrom-Json $reader.ReadToEnd();

        if ($errBody.Error -ne "authorization_pending")
        {
            throw
        }
    }

    If ($null -eq $tokenResponse)
    {
        Write-Warning "Not Connected"
    }
    Else
    {
        Write-Host -ForegroundColor Green "Connected"
    }
    Return $tokenResponse | Out-Null
}


########################################
#  Get Intune Uploaded Group Policies  #
########################################
try{
    $uriAll = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyMigrationReports"
    $AllPolicies = (Invoke-MSGraphRequest -Url $uriAll -HttpMethod GET).value
    Write-Host "We found the following GPO Migration Reports:" -ForegroundColor Yellow
    $AllPolicies.displayName
}
catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
}

##############################################################################################
#  Intune Group Policies Definitions (Administrative Template Configuration Profile options  #
##############################################################################################

$uridef = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions"
$defi = Invoke-MSGraphRequest -Url $uridef -HttpMethod GET | Get-MSGraphAllPages

If($AllPolicies){
    ########################################
    #  Get All GPO configuration settings  #
    ########################################

    $AllSettings = @()

    ForEach($policy in $AllPolicies){
        $PolId = $policy.id
        $PolId = [uri]::EscapeDataString($PolId)
        $uri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyMigrationReports/"+"$($PolId)"+"?expand=GroupPolicySettingMappings"
        $gpoSettings = Invoke-MSGraphRequest -Url $uri -HttpMethod GET
        $gpoPolicySettings = $gpoSettings.groupPolicySettingMappings

        ForEach($gpoPolicySetting in $gpoPolicySettings){
            $checkdefi = $defi | ?{$_.id -eq "$($gpoPolicySetting.admxSettingDefinitionId)"}
            If($checkdefi){$definition = $true}else{$definition = $false}

            $_intuneSettings = $gpoPolicySetting.intuneSettingUriList
            $_intuneSettings = ($_intuneSettings -join "-")
            if($_intuneSettings.Count -gt 0){
                #Write-Host "$($_intuneSettings) Count - $($_intuneSettings.Count)  Setting Name: $($gpoPolicySetting.settingName)" -ForegroundColor Yellow
            }
            $AllSettings += $gpoPolicySetting | Select-Object *,@{n="_IntuneSettings";e={"$($_intuneSettings)"}},@{n="PolicyName";e={"$($policy.displayName)"}},@{n="PolicyID";e={"$($policy.id)"}},@{n="Compare_Setting_Name_Value_ValueType_Category";e={"$($gpoPolicySetting.settingName)_$($gpoPolicySetting.settingValue)_$($gpoPolicySetting.settingValueType)_$($gpoPolicySetting.settingCategory)"}},@{n="DefinitionExist";e={"$($definition)"}}

        }

    }

    ###################################
    #  Find duplicates and conflicts  #
    ###################################


    $finalSettings = @()
    $conflict = ""
    $duplicate = $false
    $conf = $false
    ForEach($all in $AllSettings){
        $dupl = $AllSettings | ?{($_.settingName -eq $($all.settingName)) -AND ($_.PolicyID -ne $all.PolicyID)}
        $checkdup = $AllSettings | ?{$_.Compare_Setting_Name_Value_ValueType_Category -eq $all.Compare_Setting_Name_Value_ValueType_Category}
        If($checkdup.Count -gt 1){$duplicate = $true}else{$duplicate = $false}
        if($dupl){
            $conflict = ""
            $conf = $false
            ForEach($du in $dupl){
                If(("$($du.settingValue)-$($du.settingValueType)-$($du.settingCategory)") -ne ("$($all.settingValue)-$($all.settingValueType)-$($all.settingCategory)")){
                    $conflict = $conflict + "$($du.PolicyID),"# Value: $($du.settingValue) Type: $($du.settingValueType);"
                    $conf = $true
                }
            }
        }else{
            $conflict = ""
            $conf = $false
        }
        If($conflict.Length -gt 0){$conflict = $conflict.Substring(0,$conflict.length -1)}
        $finalSettings += $all | Select-Object *,@{n="Duplicate";e={"$($duplicate)"}},@{n="Conflict";e={"$($conf)"}},@{n="Conflict with";e={"$($conflict)"}}
    }


    ###################
    #  Export to CSV  #
    ###################

    $finalSettings | Export-Csv $CSVOutput -NoTypeInformation
}else{
    Write-Host "No policies were found in Intune" -ForegroundColor Red
}


