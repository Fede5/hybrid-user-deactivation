# Hybrid User Deactivation Script
# Requires: ActiveDirectory module (on-prem), AzureAD module (cloud)

# Parameters
param (
    [string]$Username
)

# Disable on-prem AD user
Import-Module ActiveDirectory
$adUser = Get-ADUser -Identity $Username
Disable-ADAccount -Identity $adUser
Set-ADAccountPassword -Identity $adUser -Reset -NewPassword (ConvertTo-SecureString "TempP@ss123" -AsPlainText -Force)
Get-ADUser $adUser | Get-ADGroupMembership | ForEach-Object { Remove-ADGroupMember -Identity $_ -Members $adUser -Confirm:$false }

# Connect to AzureAD
Connect-AzureAD
$cloudUser = Get-AzureADUser -ObjectId $Username
Set-AzureADUser -ObjectId $cloudUser.ObjectId -AccountEnabled $false

# Remove from all Entra groups
Get-AzureADUserMembership -ObjectId $cloudUser.ObjectId | ForEach-Object {
    Remove-AzureADGroupMember -ObjectId $_.ObjectId -MemberId $cloudUser.ObjectId
}

# Reset MFA (if enabled)
Reset-AzureADUserStrongAuthenticationMethods -ObjectId $cloudUser.ObjectId

# Remove MFA devices (via Graph if needed)