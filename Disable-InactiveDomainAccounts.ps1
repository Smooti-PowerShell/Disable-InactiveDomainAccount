<#
    .Synopsis
        This script will disable accounts from Active Directory that have been inactive for 35 days
        and move them to an alternative location.
    .Notes
        Name: Disable-InactiveDomainAccounts
        Author: Robert Owens
        Date: May 20, 2021
        Version: 1.2

        The requirement for disabling accounts after 35 days due to non-use is a Security
        Technical Implementation Guideline (STIG) requirement mandated by Defense
        Information Systems Agency (DISA). The STIG stipulates that all accounts are to be
        disabled after 35 days of inactivity/no access.
    .PARAMETER Search
        Mandatory. Location to search within ActiveDirectory.
        Ex. "OU=Users,DC=lab,DC=local"
    .PARAMETER Destination
        Mandatory. Location to move accounts within ActiveDirectory.
        Ex. "OU=Inactive,OU=Users,DC=lab,DC=local"
    .PARAMETER LogPath
        Optional. Path to place logs.
    .PARAMETER MaxIdle
        Optional. Max inactive time for an account.
		DEFAULT: 35
    .EXAMPLE
        Disable-InactiveDomainAccounts -Search "OU=Users,DC=lab,DC=local" -Destination "OU=Inactive,OU=Users,DC=lab,DC=local"
    .EXAMPLE
        Disable-InactiveDomainAccounts -Search "OU=Users,DC=lab,DC=local" -Destination "OU=Inactive,OU=Users,DC=lab,DC=local" -LogPath "C:\MyLogs"
    .EXAMPLE
        Disable-InactiveDomainAccounts -Search "OU=Users,DC=lab,DC=local" -Destination "OU=Inactive,OU=Users,DC=lab,DC=local" -LogPath "C:\MyLogs" -MaxIdle 75
#>

param (
    [Parameter (Mandatory = $true)]
    $Search,

    [Parameter (Mandatory = $true)]
    $Destination,

    $LogPath = "$($PSScriptRoot)\Logs",

    $MaxIdle = "35"
)

# * Confirm ActiveDirectory module is able to be imported
if ((Get-Module -ListAvailable).Name -eq "ActiveDirectory") {
    Import-Module ActiveDirectory
}
else {
    Write-Warning "ActiveDirectory module not found!"
    Write-Warning "Please run on machine that has RSAT tools installed."
    exit
}

# * Confirm we have an elevated session.
If (-NOT([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Throw "You must run this from an elevated PowerShell session."
}

# * Gets all inactive accounts
$InactiveUsers = Search-ADAccount -AccountInactive -TimeSpan $MaxIdle -SearchBase $Search -SearchScope SubTree | Where-Object { $_.enabled -and $_.DistinguishedName -notmatch "Disabled|Inactive" }

if ($null -eq $InactiveUsers) {
    Write-Warning "No inactive accounts found!"
    Exit
}

# * Disables and Moves the accounts to a separate OU within AD
foreach ($User in $InactiveUsers) {
    $UserDescrition = ($User | Get-ADUser -Properties Description).Description
    Disable-ADAccount $User
    Set-ADUser $User -Description "$UserDescrition - Disabled (Inactivity) - $TodaysDate"
    Move-ADObject $User -DestinationPath $Destination
}
