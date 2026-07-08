Install-Module -Name ImportExcel -Force -Scope CurrentUser

# ==========================================================================================
# CONFIGURATION
# ==========================================================================================
# Define where you want the final Excel workbook saved
$Date = Get-Date -Format MM.dd.yyyy
$OutputPath = "C:\Audit\Kerberos_Audit_Report_$Date.xlsx"

# Dynamically gather all Domain Controllers in your current Active Directory domain
$DCs = (Get-ADDomainController -Filter *).HostName

# Build a high-performance XPath query to isolate Kerberos failure/auth events
# 4768 = TGT Request | 4771 = Pre-Auth Failure | 4769 = TGS Service Ticket Request
$XPathQuery = "*[System[(EventID=4768 or EventID=4771 or EventID=4769)]]"

# ==========================================================================================
# EXECUTION
# ==========================================================================================
Write-Host "Starting Multi-DC Kerberos Failure & Tracking Audit..." -ForegroundColor Green
Write-Host "Target Output: $OutputPath" -ForegroundColor Cyan
Write-Host "--------------------------------------------------"

foreach ($DC in $DCs) {
    Write-Host "Processing $DC..." -ForegroundColor Cyan
    
    try {
        # Fetch remote Kerberos security events (capped per DC for rapid parsing)
        $Events = Get-WinEvent -ComputerName $DC -LogName Security -FilterXPath $XPathQuery -MaxEvents 500 -ErrorAction Stop
        
        if ($Events) {
            $ProcessedEvents = [System.Collections.Generic.List[PSCustomObject]]::new()

            foreach ($LogEvent in $Events) {
                # Determine event layout structures dynamically based on Event ID
                $EventId = $LogEvent.Id
                
                # Setup generic index references based on standard Microsoft schemas
                $User           = $LogEvent.Properties[0].Value
                $Service        = if ($EventId -eq 4769) { $LogEvent.Properties[2].Value } else { $LogEvent.Properties[1].Value }
                $ResultCode     = if ($EventId -eq 4771) { $LogEvent.Properties[2].Value } else { $LogEvent.Properties[6].Value }
                $Encryption     = if ($EventId -eq 4771) { "N/A" } elseif ($EventId -eq 4769) { $LogEvent.Properties[4].Value } else { $LogEvent.Properties[3].Value }
                $PreAuth        = if ($EventId -eq 4768) { $LogEvent.Properties[4].Value } else { "N/A" }
                $ClientIP       = if ($EventId -eq 4769) { $LogEvent.Properties[6].Value } else { $LogEvent.Properties[7].Value }
                $ClientPort     = if ($EventId -eq 4769) { $LogEvent.Properties[7].Value } else { $LogEvent.Properties[8].Value }

                # Sanitize IPv6 formatting wrappers if present
                if ($ClientIP) { $ClientIP = $ClientIP -replace "::ffff:", "" }

                # Deep-dive translations for Excel readability
                $FailureReason = switch ($ResultCode) {
                    "0x0"   { "Success / Authorized" }
                    "0x6"   { "KDC_ERR_C_PRINCIPAL_UNKNOWN (Bad Username / No Account)" }
                    "0x7"   { "KDC_ERR_S_PRINCIPAL_UNKNOWN (Server/SPN Not Found)" }
                    "0x12"  { "KDC_ERR_CLIENT_REVOKED (Locked, Disabled, or Expired)" }
                    "0x17"  { "KDC_ERR_KEY_EXPIRED (Password Expired)" }
                    "0x18"  { "KDC_ERR_PREAUTH_FAILED (Wrong Password / Bad Credential)" }
                    "0x25"  { "KDC_ERR_SVC_UNAVAILABLE (Clock Skew / Time Out of Sync)" }
                    "0x1B"  { "KDC_ERR_MUST_USE_USER2USER (SPN / AppPool Misconfiguration)" }
                    "0xF"   { "KDC_ERR_ENCTYPE_NOSUPP (Encryption Type Mismatch/Hardening)" }
                    default { "Status Code: $ResultCode" }
                }

                $EncryptionType = switch ($Encryption) {
                    "0x11"  { "AES128-CTS-HMAC-SHA1-96" }
                    "0x12"  { "AES256-CTS-HMAC-SHA1-96" }
                    "0x17"  { "RC4-HMAC (Legacy/Insecure)" }
                    "0x3"   { "DES-CBC-MD5 (Legacy/Deprecated)" }
                    "-1"    { "None / Failed during negotiation" }
                    "N/A"   { "N/A (Pre-Auth Phase)" }
                    default { "Type: $Encryption" }
                }

                $PreAuthType = switch ($PreAuth) {
                    "2"     { "Encrypted Timestamp (Standard Password)" }
                    "11"    { "RENEW-TGT / Validation" }
                    "15"    { "Smart Card / PKINIT (X.509 Certificate)" }
                    "16"    { "Smart Card / PKINIT Key Exchange" }
                    "N/A"   { "N/A" }
                    default { "Type: $PreAuth" }
                }

                # Construct optimized row object
                $ProcessedEvents.Add([PSCustomObject]@{
                    'TimeStamp'        = $LogEvent.TimeCreated
                    'EventId'          = $EventId
                    'EventDescription' = if ($EventId -eq 4768) { "TGT Request" } elseif ($EventId -eq 4771) { "Pre-Auth Failure" } else { "TGS Ticket Request" }
                    'User'             = $User
                    'ClientIP'         = $ClientIP
                    'ClientPort'       = $ClientPort
                    'RequestedService' = $Service
                    'ResultHexCode'    = $ResultCode
                    'FailureReason'    = $FailureReason
                    'PreAuthMethod'    = $PreAuthType
                    'EncryptionType'   = $EncryptionType
                })
            }

            # Export data into a dedicated tab named after the current DC
            $ProcessedEvents | Export-Excel -Path $OutputPath -WorksheetName $DC -AutoSize
            Write-Host "Successfully exported Kerberos events for $DC" -ForegroundColor Green
        } else {
            Write-Host "No Kerberos tracking events found on $DC" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Warning "Failed to query or export data from $DC. Error: $_"
    }
    
    Write-Host "--------------------------------------------------"
}

Write-Host "Audit complete! Centralized Kerberos Report saved to: $OutputPath" -ForegroundColor Green