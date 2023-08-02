# Intune Group Policy Analytics - Find duplicates and conflicts

With this script, you can export all Intune imported GPO to a csv file and get some fields to filter the **duplicates** and **conflicts** on all your GPO settings.

## If It is the first time running the script you should run the following commands:
```powershell
#Import Microsoft Graph Intune Module
Install-Module Microsoft.Graph.Intune

# Connect to MsGraph and provide admin consent
Connect-MSGraph -AdminConsent

````

## CSV file:

The file will have the following fields:
- All fields from the GroupPolicySettingMappings.
- `Policy Name` -> The GPO migration report name.
- `PolicyID` -> The GPO migration report ID.
- `Compare` -> This field will have the Setting Name + Setting Value + Value Type.
- `Definition` -> This is to let you know if there is any "Administrative Template" Windows 10 Configuration profile template.
- `Duplicate` -> If the setting has a duplicate with any other GPO.
- `Conflict` -> If the setting has any conflict with any other GPO.
- `Conflict with` -> What GPO has conflict with.

## Additionally I'm adding a Power BI report if you would like to analyze the GPO setting in a different way
![Alt text](Intune/GPO-Analytics/Image/Power%20BI_Image.png)