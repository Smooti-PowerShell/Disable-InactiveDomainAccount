#Requires –Modules ActiveDirectory
<#
    .Synopsis
        This script will disable accounts from Active Directory that have been inactive for 35 days
        and move them to an alternative location.
    .Notes
        Name: Disable-InactiveDomainAccount
        Author: Robert Owens
        Date: May 20, 2021
        Version: 1.2

        The requirement for disabling accounts after 35 days due to non-use is a Security
        Technical Implementation Guideline (STIG) requirement mandated by Defense
        Information Systems Agency (DISA). The STIG stipulates that all accounts are to be
        disabled after 35 days of inactivity/no access.
    .PARAMETER SearchBase
        Mandatory. Location to search within ActiveDirectory.
        Ex. "OU=Users,DC=lab,DC=local"
    .PARAMETER SearchScope
        How far to search within ActiveDirectory
        Ex. OneLevel
    .PARAMETER LogPath
        Optional. Path to place logs.
    .PARAMETER MaxIdle
        Optional. Max inactive time for an account.
		DEFAULT: 35
    .EXAMPLE
        Disable-InactiveDomainAccounts -SearchScope "OU=Users,DC=lab,DC=local"
    .EXAMPLE
        Disable-InactiveDomainAccounts -SearchScope "OU=Users,DC=lab,DC=local" -SearchBase OneLevel -LogPath "C:\MyLogs"
    .EXAMPLE
        Disable-InactiveDomainAccounts -SearchScope "OU=Users,DC=lab,DC=local" -LogPath "C:\MyLogs" -MaxIdle 75
#>

param (
	[Parameter (Mandatory = $true)]
	$SearchBase,

	[ValidateSet("SubTree", "OneLevel", "Base")]
	[String]
	$SearchScope = "SubTree",

	$LogPath = "$($PSScriptRoot)\Logs",

	$MaxIdle = "35"
)

Import-Module ActiveDirectory
# Confirm we have an elevated session.
If (-NOT([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
	Throw "You must run this from an elevated PowerShell session."
}

$searchArgs = @{
	AccountInactive = $true
	TimeSpan        = $MaxIdle
	SearchBase      = $SearchBase
	SearchScope     = $SearchScope
	UsersOnly       = $true
}

# Get all inactive accounts
$inactiveUsers = Search-ADAccount @searchArgs | Where-Object {
	$_.enabled -and $_.DistinguishedName -notmatch "Disabled|Inactive"
}

# Check if we have inactive accounts
if ($null -eq $inactiveUsers) {
	Write-Warning "No inactive accounts found!"
	Exit
}

# Disable accounts
foreach ($user in $inactiveUsers) {
	$userDescription = ($user | Get-ADUser -Properties Description).Description
	Disable-ADAccount $user
	Set-ADUser $user -Description "$userDescription - Disabled (Inactivity) - $(Get-Date -Format "dddd MM/dd/yyyy HH:mm")"
}
