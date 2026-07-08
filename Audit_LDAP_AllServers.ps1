Install-Module -Name ImportExcel -Force -Scope CurrentUser
# ==========================================================================================
# CONFIGURATION
# ==========================================================================================
# Define where you want the final Excel workbook saved
$Date = Get-Date -Format MM.dd.yyyy
$OutputPath = "C:\Audit\LDAP_Central_Audit_Report_$Date.xlsx"

# Dynamically gather all Domain Controllers in your current Active Directory domain
$DCs = (Get-ADDomainController -Filter *).HostName

# Define the XPath query to isolate LDAP Unsigned (2889) and missing Channel Binding (3035) events
$XPathQuery = "*[System[(EventID=2889 or EventID=3035)]]"

# ==========================================================================================
# EXECUTION
# ==========================================================================================
Write-Host "Starting Centralized LDAP & Channel Binding Audit..." -ForegroundColor Green
Write-Host "Target Output: $OutputPath" -ForegroundColor Cyan
Write-Host "--------------------------------------------------"

foreach ($DC in $DCs) {
    Write-Host "Processing $DC..." -ForegroundColor Cyan
    
    try {
        # Fetch remote Directory Service events
        $Events = Get-WinEvent -ComputerName $DC -LogName "Directory Service" -FilterXPath $XPathQuery -MaxEvents 500 -ErrorAction Stop
        
        # If events exist, map them out
        $ProcessedEvents = foreach ($Entry in $Events) {
            if ($Entry.Id -eq 2889) {
                $AuditType   = "Unsigned LDAP Connection"
                $BindingType = if ($Entry.Properties[2].Value -eq 1) { "1 (SASL)" } else { "0 (Simple)" }
            } else {
                $AuditType   = "Missing Channel Binding (CBT)"
                $BindingType = "N/A"
            }

            [PSCustomObject]@{
                Timestamp   = $Entry.TimeCreated
                EventID     = $Entry.Id
                AuditType   = $AuditType
                ClientIP    = $Entry.Properties[0].Value
                UserAccount = $Entry.Properties[1].Value
                BindingType = $BindingType
                DCName      = $DC
            }
        }

        # Export data into a dedicated tab named after the current DC
        $ProcessedEvents | Export-Excel -Path $OutputPath -WorksheetName $DC -AutoSize
        
        Write-Host "Successfully exported $($ProcessedEvents.Count) events for $DC" -ForegroundColor Green
    }
    catch {
        # Catch the specific exception where no logs matched the query
        if ($_.Exception.Message -match "No events were found that match the specified selection criteria") {
            Write-Host "No insecure LDAP events found on $DC (Clean Log)." -ForegroundColor Yellow
        } else {
            # This handles real errors like RPC offline, Access Denied, etc.
            Write-Warning "Failed to query $DC. Error: $($_.Exception.Message)"
        }
    }
    
    Write-Host "--------------------------------------------------"
}

Write-Host "Audit complete! Centralized report saved to: $OutputPath" -ForegroundColor Green