
# LoadLog Module

Set-StrictMode -Version 3 

<# 

.SYNOPSIS

Query Windows event logs from the command line.

#>


function Invoke-LogonLog {
    param (
        [string]$local:a1,  # System/File
        [string]$local:a3,  # Detail/Stats
        [string]$local:a4   # Count
    )    

    [string] $local:TypeKey = ""
    [string] $local:TypeVal = ""

    # Set System or File query
    if ($a1 -eq 1){
        $local:TypeKey = "LogName"
        $local:TypeVal = "Security"
    } elseif ($a1 -eq 2) {
        $local:TypeKey = "Path"
        $local:TypeVal = "Security.evtx"
    } else {
        Write-Host "No go"
    }

    # Log Detail 
    if ($a3 -eq 1) {
        Get-Winevent @{ $TypeKey = "$TypeVal"; Id=4624} `
        | Where-Object {$_.Message -notmatch "Logon Type:\s+5"} `
        | Select-Object -First $a4 `
        | Select-Object TimeCreated, Id, `
        @{Label='LogonType'; Expression={$_.Properties[8].Value}}, `
        @{Label='ProcessName'; Expression={$_.Properties[9].Value}}, `
        @{Label='UserName'; Expression={$_.Properties[5].Value}}, `
        @{Label='DomainName'; Expression={$_.Properties[6].Value}} `
        | Format-Table      
    }        
    
    # Log Stats
    if ($a3 -eq 2) {
        Get-Winevent @{ $TypeKey = "$TypeVal"; Id=4624} `
        | Where-Object {$_.Message -notmatch "Logon Type:\s+5"} `
        | Select-Object -First $a4 `
        | Select-Object Id, `
        @{Label='LogonType'; Expression={$_.Properties[8].Value}} `
        | Group-Object -Property Id, LogonType -NoElement `
        | Sort-Object -Property Count -Descending    
        | Format-Table

        Write-Host "2 - User Logon      8 - Network ClearText"
        Write-Host "3 - Network Logon   9 - NewCredentials "
        Write-Host "4 - Batch Logon    10 - Remote Interactive "
        Write-Host "7 - Unlock         11 - Cached Interactive "
        Write-Host ""
    }
    
}

function Get-Menu1 {
    [string] $local:ans1 = ""
    [string] $local:ans2 = "" 

    Clear-Host

    Write-Host "[0] Quit"
    Write-Host "[1] System" 
    Write-Host "[2] File"

    $ans1 = Read-Host "Entry"

    if ( $ans1 -eq "0" ) { Clear-Host; Write-Host "Bye"; `
        Return "0", "0" }

    Clear-Host

    Write-Host "[0] Quit"
    Write-Host "[1] Logon"
    Write-Host "[2] Process"

    $ans2 = Read-Host "Entry"

    if ( $ans2 -eq "0" ) { Clear-Host; Write-Host "Bye"; `
        Return "0", "0" }            
    
    return $ans1, $ans2        
}

function Get-Menu2() {

    [string] $local:ans3 = "" 
    [string] $local:ans4 = ""

    Write-Host ""
    Write-Host "[0] Quit  [1] Detail  [2] Stats"

    $ans3 = Read-Host "Entry"

    if ( $ans3 -eq "0" ) { Clear-Host; Write-Host "Bye"; `
        Return "0", "0" }

    Write-Host ""
    $ans4 = Read-Host "How many"

    if ( $ans4 -eq "0" ) { Clear-Host; Write-Host "Bye"; `
        Return "0", "0" }

    return $ans3, $ans4        
}

function Get-Menu() {

    [string] $local:ans1 = ""
    [string] $local:ans2 = "" 
    [string] $local:ans3 = "" 
    [string] $local:ans4 = ""
    

    Clear-Host

    Write-Host "[0] Quit"
    Write-Host "[1] System" 
    Write-Host "[2] File"

    $ans1 = Read-Host "Entry"

    if ( $ans1 -eq "0" ) { Clear-Host; Write-Host "Bye"; `
        Return "0", "0", "0", "0" }

    Clear-Host

    Write-Host "[0] Quit"
    Write-Host "[1] Logon"
    Write-Host "[2] Process"

    $ans2 = Read-Host "Entry"

    if ( $ans2 -eq "0" ) { Clear-Host; Write-Host "Bye"; `
        Return "0", "0", "0", "0" }

    Clear-Host

    Write-Host "[0] Quit"
    Write-Host "[1] Detail"
    Write-Host "[2] Stats"

    $ans3 = Read-Host "Entry"

    if ( $ans3 -eq "0" ) { Clear-Host; Write-Host "Bye"; `
        Return "0", "0", "0", "0" }

    Clear-Host

    $ans4 = Read-Host "How many"

    if ( $ans4 -eq "0" ) { Clear-Host; Write-Host "Bye"; `
        Return "0", "0", "0", "0" }

    return $ans1, $ans2, $ans3, $ans4
}

# Write-Host "ANS1: " $ans1 # 1-System, 2-File
# Write-Host "ANS2: " $ans2 # 1-Logon, 2-Process 
# Write-Host "ANS3: " $ans3 # 1-Detail, 2-Stats
# Write-Host "ANS4: " $ans4 # Count  

function Get-LoadLog() {

    [string] $local:ans1 = ""
    [string] $local:ans2 = "" 
    [string] $local:ans3 = "" 
    [string] $local:ans4 = ""
    
    

    # $ans1, $ans2, $ans3, $ans4 = Get-Menu

    $ans1, $ans2 = Get-Menu1
    $ans3, $ans4 = Get-Menu2

    while ($ans3 -ne "0") {
        
        if ($ans2 -eq 1) {
            Invoke-LogonLog $ans1 $ans3 $ans4
        }

        $ans3, $ans4 = Get-Menu2
    }





}

Set-Alias ldl Get-LoadLog
Export-ModuleMember -Function Get-LoadLog 
Export-ModuleMember -Alias ldl