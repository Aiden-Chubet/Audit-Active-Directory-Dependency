# Ensure the Excel module is loaded
Import-Module -Name ImportExcel -ErrorAction SilentlyContinue

# ==========================================================================================
# CONFIGURATION
# ==========================================================================================
$Date = Get-Date -Format MM.dd.yyyy
$OutputPath = "C:\Audit\NTLM_Domain_Validation_Audit_$Date.xlsx"
$DCs = (Get-ADDomainController -Filter *).HostName

# ==========================================================================================
# EXECUTION
# ==========================================================================================
Write-Host "Starting Centralized NTLM Domain Validation Log Audit (Event 8004)..." -ForegroundColor Green
Write-Host "Target Output: $OutputPath" -ForegroundColor Cyan
Write-Host "--------------------------------------------------"

foreach ($DC in $DCs) {
    Write-Host "Processing $DC..." -ForegroundColor Cyan
    
    try {
        $Filter = @{
            LogName = 'Microsoft-Windows-NTLM/Operational'
            Id      = 8004
        }
        
        $Events = Get-WinEvent -ComputerName $DC -FilterHashtable $Filter -MaxEvents 2000 -ErrorAction SilentlyContinue
        
        if ($Events) {
            $ProcessedEvents = foreach ($NtlmEvent in $Events) {
                # Convert to XML to parse the flat EventData array elements cleanly
                $Xml = [xml]$NtlmEvent.ToXml()
                $DataArray = $Xml.Event.EventData.Data
                
                # Match the exact "Name" attributes found in your XML structure
                $SChannelName    = ($DataArray | Where-Object { $_.Name -eq 'SChannelName' }).'#text'
                $UserName        = ($DataArray | Where-Object { $_.Name -eq 'UserName' }).'#text'
                $DomainName      = ($DataArray | Where-Object { $_.Name -eq 'DomainName' }).'#text'
                $WorkstationName = ($DataArray | Where-Object { $_.Name -eq 'WorkstationName' }).'#text'
                
                [PSCustomObject]@{
                    Timestamp       = $NtlmEvent.TimeCreated
                    UserName        = $UserName
                    DomainName      = $DomainName
                    WorkstationName = $WorkstationName
                    SecureChannel   = $SChannelName
                }
            }

            # Export data into a dedicated tab named after the current DC
            $ProcessedEvents | Export-Excel -Path $OutputPath -WorksheetName $DC -AutoSize
            Write-Host "[+] Successfully exported $($ProcessedEvents.Count) NTLM validation events for $DC" -ForegroundColor Green
        } else {
            Write-Host "[*] No NTLM ID 8004 events found on $DC." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Warning "[-] Critical error reaching $DC. Error: $($_.Exception.Message)"
    }
    
    Write-Host "--------------------------------------------------"
}

Write-Host "Audit complete! Report saved to: $OutputPath" -ForegroundColor Green