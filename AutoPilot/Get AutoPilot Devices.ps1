## Get AutoPilot Devices

Install-Module -Name WindowsAutoPilotIntune
Import-Module WindowsAutoPilotIntune

$AppId = "<ClientId information>"
$client_secret = "<secretinfo>"
$Tenant = "<tenantname>.onmicrosoft.com"
$authority = “https://login.windows.net/$tenant”

Update-MSGraphEnvironment -AppId $AppId -Quiet
Update-MSGraphEnvironment -AuthUrl $authority -Quiet
Connect-MSGraph -ClientSecret $client_secret -Quiet

Connect-MSGraph

Get-Command -module WindowsAutoPilotIntune

$autopilotDevices = Get-AutopilotDevice

$autopilotDevices = $autopilotDevices | select *,@{n="OpCo";e={$($_.groupTag.Split(' ')[0])}},@{n="Region";e={$($_.groupTag.Split(' ')[1])}}

$autopilotEvents = Get-AutopilotEvent



