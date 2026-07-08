# ==========================================================================================
# CONFIGURATION
# ==========================================================================================
$Date = Get-Date -Format MM.dd.yyyy
$KerberosOutputPath = "C:\Audit\Kerberos_Crypto_Focused_Audit_$Date.xlsx"

Write-Host "Starting Focused Kerberos Encryption Audit..." -ForegroundColor Green

$ADProperties = @("msDS-SupportedEncryptionTypes", "Enabled", "LastLogonDate", "OperatingSystem", "ServicePrincipalName")

# ==========================================================================================
# EXECUTION
# ==========================================================================================

# 1. Target ONLY User accounts that act as Service Accounts (Have an SPN populated)
Write-Host "Gathering SPN-enabled Service Accounts..." -ForegroundColor Cyan
$ServiceAccounts = Get-ADUser -Filter "ServicePrincipalName -like '*'" -Properties $ADProperties

# 2. Gather Computer/Server Accounts (excluding Domain Controllers if desired, but good to check all)
Write-Host "Gathering Computer/Server Accounts..." -ForegroundColor Cyan
$ComputerAccounts = Get-ADComputer -Filter * -Properties $ADProperties

# Combine targeted accounts
$AllTargetAccounts = $ServiceAccounts + $ComputerAccounts

$ProcessedKerberos = foreach ($Account in $AllTargetAccounts) {
    
    $Bitmask = $Account."msDS-SupportedEncryptionTypes"
    $EncTypes = [System.Collections.Generic.List[string]]::new()
    
    if ($Bitmask) {
        if ($Bitmask -band 0x1)  { [void]$EncTypes.Add("DES-CBC-CRC") }
        if ($Bitmask -band 0x2)  { [void]$EncTypes.Add("DES-CBC-MD5") }
        if ($Bitmask -band 0x4)  { [void]$EncTypes.Add("RC4-HMAC") }
        if ($Bitmask -band 0x8)  { [void]$EncTypes.Add("AES128-CTS-HMAC-SHA1-96") }
        if ($Bitmask -band 0x10) { [void]$EncTypes.Add("AES256-CTS-HMAC-SHA1-96") }
        $EncryptionSummary = $EncTypes -join ", "
    } else {
        # Blank attributes mean the account falls back to Domain/DC controller defaults
        $EncryptionSummary = "Unconfigured (Falls back to DC Default)"
    }

    # Determine if it's a Computer or a Service User Account
    $Type = if ($Account.ObjectClass -eq "computer") { "Computer/Server" } else { "Service Account (User w/ SPN)" }

    [PSCustomObject]@{
        Name               = $Account.Name
        SAMAccountName     = $Account.SamAccountName
        AccountType        = $Type
        Enabled            = $Account.Enabled            # Account status
        LastLogonDate      = $Account.LastLogonDate      # Last authentication timestamp
        OperatingSystem    = $Account.OperatingSystem    # OS (will be blank for Service Accounts)
        EncryptionBitmask  = $Bitmask
        SupportedEncTypes  = $EncryptionSummary
    }
}

# Export the targeted data
if ($ProcessedKerberos.Count -gt 0) {
    $ProcessedKerberos | Export-Excel -Path $KerberosOutputPath -WorksheetName "Kerberos Target Audit" -AutoSize
    Write-Host "Successfully exported $($ProcessedKerberos.Count) critical accounts to $KerberosOutputPath" -ForegroundColor Green
} else {
    Write-Warning "No target accounts found."
}