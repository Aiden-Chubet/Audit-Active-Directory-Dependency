# ==========================================================================================
# CONFIGURATION
# ==========================================================================================
$Date = Get-Date -Format 'MM.dd.yyyy'
$OutputPath = 'C:\Audit\AD_Protocol_Dependency_Map_7Days_' + $Date + '.xlsx'

# Dynamically gather all Domain Controllers in the current forest/domain
$DCs = (Get-ADDomainController -Filter *).HostName

# Calculate lookback time window (7 Days) safely
$DaysToLookBack = -7
$StartTime = (Get-Date).AddDays($DaysToLookBack)
$UniversalTimeString = $StartTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')

# Construct the XPath query using literal concatenation to prevent string parsing errors
$XPathQuery = '*[System[(EventID=4624 or EventID=4769) and TimeCreated[@SystemTime >= ' + "'" + $UniversalTimeString + "'" + ']]]'

Write-Host 'Compiling Big-Picture AD Dependency Map (Streaming Mode)...' -ForegroundColor Green
$MasterDependencyList = [System.Collections.Generic.List[PSCustomObject]]::new()

# Encryption Type Translation Table
$CryptoTable = @{
    '0x1'  = 'DES-CBC-CRC (Legacy)'
    '0x3'  = 'DES-CBC-MD5 (Legacy)'
    '0x17' = 'RC4-HMAC (Weak)'
    '0x12' = 'AES128-CTS-HMAC-SHA1-96 (Secure)'
    '0x11' = 'AES256-CTS-HMAC-SHA1-96 (Secure)'
}

# ==========================================================================================
# LOG AGGREGATION & REAL-TIME STREAMING
# ==========================================================================================
foreach ($DC in $DCs) {
    $StatusMessage = 'Opening stream to ' + $DC + '...'
    Write-Host $StatusMessage -ForegroundColor Cyan
    
    try {
        # Initialize the streaming counter
        $Counter = 0

        # Piping Get-WinEvent directly into ForEach-Object processes logs in real-time
        Get-WinEvent -ComputerName $DC -LogName 'Security' -FilterXPath $XPathQuery -ErrorAction SilentlyContinue | ForEach-Object {
            $Counter++

            # Update progress bar UI every 500 events processed
            if ($Counter % 500 -eq 0) {
                Write-Progress `
                    -Activity ('Streaming and parsing events from ' + $DC) `
                    -Status ('Total events intercepted so far: ' + $Counter) `
                    -PercentComplete -1 # Stream mode uses -1 since total size is calculated dynamically
            }

            $EventXML = [xml]$_.ToXml()
            $Data = $EventXML.Event.EventData.Data

            # ------------------------------------------------------------------------------
            # INTERCEPT NTLM TRACKING (Event ID 4624)
            # ------------------------------------------------------------------------------
            if ($_.Id -eq 4624) {
                $AuthPackage = ($Data | Where-Object { $_.Name -eq 'AuthenticationPackageName' }).'#text'
                
                if ($AuthPackage -eq 'NTLM') {
                    $ClientIP   = ($Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
                    $TargetUser = ($Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                    $Workstation = ($Data | Where-Object { $_.Name -eq 'WorkstationName' }).'#text'

                    $MasterDependencyList.Add([PSCustomObject]@{
                        DCName         = $DC
                        Protocol       = 'NTLM'
                        CipherSuite    = ($Data | Where-Object { $_.Name -eq 'LmPackageName' }).'#text' 
                        ClientIP       = $ClientIP
                        ClientName     = $Workstation
                        TargetService  = 'Local Authentication / SMB Share'
                        UserAccount    = $TargetUser
                    })
                }
            }
            # ------------------------------------------------------------------------------
            # INTERCEPT KERBEROS TRACKING (Event ID 4769)
            # ------------------------------------------------------------------------------
            elseif ($_.Id -eq 4769) {
                $TargetService = ($Data | Where-Object { $_.Name -eq 'ServiceName' }).'#text'
                
                if ($TargetService -and $TargetService -notlike '*$') {
                    $RawIP      = ($Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
                    $ClientIP   = $RawIP -replace '::ffff:', ''
                    $TicketHex  = ($Data | Where-Object { $_.Name -eq 'TicketEncryptionType' }).'#text'
                    $User       = ($Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                    
                    $Cipher = if ($CryptoTable.ContainsKey($TicketHex)) { $CryptoTable[$TicketHex] } else { "Unknown ($TicketHex)" }

                    $MasterDependencyList.Add([PSCustomObject]@{
                        DCName         = $DC
                        Protocol       = 'Kerberos'
                        CipherSuite    = $Cipher
                        ClientIP       = $ClientIP
                        ClientName     = 'N/A (Derived from IP)'
                        TargetService  = $TargetService  
                        UserAccount    = $User
                    })
                }
            }
        }
        
        # Clear the progress bar for this specific DC
        Write-Progress -Activity ('Streaming and parsing events from ' + $DC) -Completed
        Write-Host ('Finished streaming ' + $Counter + ' events from ' + $DC + '.') -ForegroundColor Green
        
    } catch {
        $ErrorMessage = 'Could not process stream on ' + $DC + '. Error: ' + $_.Exception.Message
        Write-Warning $ErrorMessage
    }
}

# ==========================================================================================
# THE UNIQUE DEDUPLICATION CALCULATION
# ==========================================================================================
Write-Host 'Calculating unique dependencies across aggregated logs...' -ForegroundColor Cyan

$UniqueDependencies = $MasterDependencyList | 
    Group-Object Protocol, ClientIP, TargetService, CipherSuite | 
    ForEach-Object {
        $Sample = $_.Group[0]
        [PSCustomObject]@{
            Protocol          = $Sample.Protocol
            CipherSuite       = $Sample.CipherSuite
            ClientIP          = $Sample.ClientIP
            ClientName        = $Sample.ClientName
            TargetService     = $Sample.TargetService
            ImpactedUserCount = ($_.Group.UserAccount | Select-Object -Unique).Count
            TotalHitCount     = $_.Count 
        }
    } | Sort-Object Protocol, TotalHitCount -Descending

# ==========================================================================================
# EXPORT TO EXCEL
# ==========================================================================================
if ($UniqueDependencies) {
    # Ensure local directory path exists before saving
    $TargetFolder = Split-Path -Path $OutputPath -Parent
    if (-not (Test-Path $TargetFolder)) { New-Item -ItemType Directory -Path $TargetFolder -Force | Out-Null }

    $UniqueDependencies | Export-Excel -Path $OutputPath -WorksheetName 'AD Dependency Map' -AutoSize
    Write-Host "Dependency map built successfully! File saved to: $OutputPath" -ForegroundColor Green
} else {
    Write-Warning 'No NTLM or Kerberos dependencies found in the audited time window.'
}
