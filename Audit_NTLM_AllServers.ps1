Install-Module -Name ImportExcel -Force -Scope CurrentUser
# ==========================================================================================
# CONFIGURATION
# ==========================================================================================
# Define where you want the final Excel workbook saved
$Date = Get-Date -Format MM.dd.yyyy
$OutputPath = "C:\Audit\NTLM_Audit_Report_$Date.xlsx"

# Dynamically gather all Domain Controllers in your current Active Directory domain
$DCs = (Get-ADDomainController -Filter *).HostName

# Define the XPath query to isolate strictly NTLM authentication events (Event ID 4624)
$XPathQuery = "*[System[(EventID=4624)]] and *[EventData[Data[@Name='AuthenticationPackageName'] = 'NTLM']]"

# ==========================================================================================
# EXECUTION
# ==========================================================================================
Write-Host "Starting NTLM Audit across all DCs..." -ForegroundColor Green
Write-Host "Target Output: $OutputPath" -ForegroundColor Cyan
Write-Host "--------------------------------------------------"

foreach ($DC in $DCs) {
    Write-Host "Processing $DC..." -ForegroundColor Cyan
    
    try {
        # Fetch the remote security events (capped at 1000 per DC for performance)
        $Events = Get-WinEvent -ComputerName $DC -LogName Security -FilterXPath $XPathQuery -MaxEvents 200 -ErrorAction Stop
        
        if ($Events) {
            # Extract and map properties from the event log XML data
            $ProcessedEvents = $Events | Select-Object TimeCreated, 
                @{N='UserName';            E={$_.Properties[5].Value}}, 
                @{N='TargetDomainName';    E={$_.Properties[6].Value}},
                @{N='LogonType';           E={$_.Properties[8].Value}},
                @{N='LogonProcessName';    E={$_.Properties[9].Value}},
                @{N='AuthPackageName';     E={$_.Properties[10].Value}},
                @{N='WorkstationName';     E={$_.Properties[11].Value}},
                @{N='IpAddress';           E={$_.Properties[18].Value}}

            # Export data into a dedicated tab named after the current DC
            $ProcessedEvents | Export-Excel -Path $OutputPath -WorksheetName $DC -AutoSize
            
            Write-Host "Successfully exported events for $DC" -ForegroundColor Green
        } else {
            Write-Host "No NTLM events found on $DC" -ForegroundColor Yellow
        }
    }
    catch {
        # Captures networking blocks, permissions errors, or offline DCs
        Write-Warning "Failed to query or export data from $DC. Error: $_"
    }
    
    Write-Host "--------------------------------------------------"
}

Write-Host "Audit complete! Report saved to: $OutputPath" -ForegroundColor Green