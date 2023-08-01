
Set-StrictMode -Version 3 

# Logons: 4624
# SubjectUserName 5
# SubjectDomainName 6
# LogonType 8 
# LogonProcessName 9

Write-Host "[1] View Logons"

$cmd = Read-Host "Entry"

if ($cmd -eq 1) {
    Get-Winevent @{LogName="Security"; Id=4624} `
    | Where-Object {$_.Message -notmatch "Logon Type:\s+5"} `
    | Select-Object -First 10 `
    | Select-Object TimeCreated, Id, `
    @{Label='LogonType'; Expression={$_.Properties[8].Value}}, `
    @{Label='ProcessName'; Expression={$_.Properties[9].Value}}, `
    @{Label='UserName'; Expression={$_.Properties[5].Value}}, `
    @{Label='DomainName'; Expression={$_.Properties[6].Value}} `
    | Format-Table
}