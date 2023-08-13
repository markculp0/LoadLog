
# LoadLog Module

Set-StrictMode -Version 3 

<# 

.SYNOPSIS

Query Windows event logs from the command line.

#>

function Set-SecurityLogType {
    param(
        [string]$local:a1,  # System/File
        [string]$local:a2   # Log Type
    )

    [string] $local:TypeKey = ""
    [string] $local:TypeVal = ""

    # Set TypeKey
    if ($a1 -eq 1){
        $local:TypeKey = "LogName"        
    } elseif ($a1 -eq 2) {
        $local:TypeKey = "Path"        
    } else {
        Write-Host "No go"
    }

    # Set TypeVal
    if ($a2 -in @(1,2,3,5) -and ($a1 -eq 1)) {
        $local:TypeVal = "Security"
    } elseif ($a2 -in @(1,2,3,5) -and ($a1 -eq 2)) {
        $local:TypeVal = "Security.evtx"
    } elseif ($a2 -in @(4) -and ($a1 -eq 1)) {
        $local:TypeVal = "System"
    } elseif ($a2 -in @(4) -and ($a1 -eq 2)) {
        $local:TypeVal = "System.evtx"
    } elseif ($a2 -in @(6) -and ($a1 -eq 1)) {
        $local:TypeVal = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
    } elseif ($a2 -in @(6) -and ($a1 -eq 2)) {
        $local:TypeVal = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational.evtx"
    }

    return $TypeKey, $TypeVal
}

# 1. Logons
function Invoke-LogonLog {
    param (
        [string]$local:a1,  # System/File
        [string]$local:a2,  # Log Type
        [string]$local:a3,  # Detail/Stats
        [string]$local:a4   # Count
    )    

    [string] $local:TypeKey = ""
    [string] $local:TypeVal = ""

    # Set Security log type
    $TypeKey, $TypeVal = Set-SecurityLogType $a1 $a2

    # Log Detail 
    if ($a3 -eq 1) {
        Get-Winevent @{ $TypeKey = "$TypeVal"; Id=4624} `
        | Where-Object {$_.Message -notmatch "Logon Type:\s+5"} `
        | Select-Object -First $a4 `
        | Select-Object TimeCreated, Id, `
        @{Label='LogonType'; Expression={$_.Properties[8].Value}}, `
        @{Label='ProcessName'; Expression={$_.Properties[9].Value}}, `
        @{Label='UserName'; Expression={$_.Properties[5].Value}}, `
        @{Label='DomainName'; Expression={$_.Properties[6].Value}}, `
        @{Label='LogonId'; Expression={$_.Properties[7].Value}} `
        | Format-Table    
                
    }        
    
    # Log Stats
    if ($a3 -eq 2) {
        Get-Winevent @{ $TypeKey = "$TypeVal"; Id=4624} `
        | Where-Object {$_.Message -notmatch "Logon Type:\s+5"} `
        | Select-Object -First $a4 `
        | Select-Object Id, `
        @{Label='LogonType'; Expression={$_.Properties[8].Value}}, `
        @{Label='ProcessName'; Expression={$_.Properties[9].Value}}, `
        @{Label='UserName'; Expression={$_.Properties[5].Value}} `
        | Group-Object -Property Id, LogonType, ProcessName, UserName -NoElement `
        | Sort-Object -Property Count -Descending    
        | Format-Table -AutoSize
 
    }

    Write-Host "2 - User Logon      4 - Batch Logon    9 - NewCredentials       11 - Cached Interactive"
    Write-Host "3 - Network Logon   7 - Unlock        10 - Remote Interactive"
    Write-Host ""
    Write-Host "Get-Winevent @{$TypeKey =""$TypeVal""; Id=4624}"           
    
}

# 2. Logons/Logoffs
function Invoke-LogonOthLog {
    param (
        [string]$local:a1,  # System/File
        [string]$local:a2,  # Log Type
        [string]$local:a3,  # Detail/Stats
        [string]$local:a4   # Count
    )    

    [string] $local:TypeKey = ""
    [string] $local:TypeVal = ""

    # Set Security log type
    $TypeKey, $TypeVal = Set-SecurityLogType $a1 $a2

    # Log Detail 
    if ($a3 -eq 1) {
        Get-Winevent @{ $TypeKey = "$TypeVal"; Id=4625,4634,4647,4672,4779} `
        | Where-Object {$_.Message -notmatch "Logon Type:\s+5"} `
        | Select-Object -First $a4 `
        | Select-Object TimeCreated, Id, TaskDisplayName, `
        @{Label='AccountName'; Expression={$_.Properties[1].Value}}, `
        @{Label='AccountDomain'; Expression={$_.Properties[2].Value}}, `
        @{Label='LogonId'; Expression={$_.Properties[3].Value}}, `
        @{Label='LogonType'; Expression={$_.Properties[4].Value}} `
        | Format-Table 
                
    }        

    # Log Stats
    if ($a3 -eq 2) {
        Get-Winevent @{ $TypeKey = "$TypeVal"; Id=4625,4634,4647,4672,4779} `
        | Select-Object -First $a4 `
        | Select-Object Id, `
        @{Label='AccountName'; Expression={$_.Properties[1].Value}}, `
        @{Label='LogonType'; Expression={$_.Properties[4].Value}} `
        | Group-Object -Property Id, AccountName, LogonType -NoElement `
        | Sort-Object -Property Count -Descending    
        | Format-Table -AutoSize
        
    }

    Write-Host "4625 - Failed Logon     4647 - User Logoff      4779 - RDP/FastSwitch Logoff"
    Write-Host "4634 - Account Logoff   4672 - SpecPriv Logon"
    Write-Host ""
    Write-Host "Get-Winevent @{$TypeKey =""$TypeVal""; Id=4625,4634,4647,4672,4779}"    
}

# 3. Process Logs
function Invoke-ProcLog {
    param (
        [string]$local:a1,  # System/File
        [string]$local:a2,  # Log Type
        [string]$local:a3,  # Detail/Stats
        [string]$local:a4   # Count
    )    

    [string] $local:TypeKey = ""
    [string] $local:TypeVal = ""

    # Set Security log type
    $TypeKey, $TypeVal = Set-SecurityLogType $a1 $a2
    
    # Log Detail 
    if ($a3 -eq 1) {
        Get-Winevent @{ $TypeKey = "$TypeVal"; Id=4688} `
        | Select-Object -First $a4 `
        | Select-Object TimeCreated, Id, ProcessId, TaskDisplayName , `
        @{Label='AccountName'; Expression={$_.Properties[1].Value}}, `
        @{Label='AccountDomain'; Expression={$_.Properties[2].Value}}, `
        @{Label='LogonId'; Expression={$_.Properties[3].Value}}, `
        @{Label='ProcessName'; Expression={$_.Properties[5].Value}}
        | Format-Table -AutoSize
        
    }    

        # Log Stats
        if ($a3 -eq 2) {
            Get-Winevent @{ $TypeKey = "$TypeVal"; Id=4688} `
            | Select-Object -First $a4 `
            | Select-Object Id, `
            @{Label='ProcessName'; Expression={$_.Properties[5].Value}} `
            | Group-Object -Property Id, ProcessName -NoElement `
            | Sort-Object -Property Count -Descending    
            | Format-Table -AutoSize

        }
        
        Write-Host "4688 - Process Created   4689 - Process Exited"        
        Write-Host ""
        Write-Host "Get-Winevent @{$TypeKey =""$TypeVal""; Id=4688,4689}"        
}

# 4. Service Logs 
function Invoke-SrvcLog {
    param (
        [string]$local:a1,  # System/File
        [string]$local:a2,  # Log Type
        [string]$local:a3,  # Detail/Stats
        [string]$local:a4   # Count
    )    

    [string] $local:TypeKey = ""
    [string] $local:TypeVal = ""

    $TypeKey, $TypeVal = Set-SecurityLogType $a1 $a2
    
    # Log Detail 
    if ($a3 -eq 1) {
        Get-Winevent @{ $TypeKey = "$TypeVal"; Id=7030,7045} `
        | Select-Object -First $a4 `
        | Select-Object TimeCreated, Id, ProcessId, Level, ProviderName, `
        @{Label='ServiceName'; Expression={$_.Properties[0].Value}}, `
        @{Label='ImagePath'; Expression={$_.Properties[1].Value}}
        | Format-Table -AutoSize
        
    }    

    # Log Stats
    if ($a3 -eq 2) {
        Get-Winevent @{ $TypeKey = "$TypeVal"; Id=7030,7045} `
        | Select-Object -First $a4 `
        | Select-Object Id, Level, ProviderName, @{Label='ServiceName'; Expression={$_.Properties[0].Value}} `
        | Group-Object -Property Id, Level, ProviderName, ServiceName -NoElement `
        | Sort-Object -Property Count -Descending `
        | Format-Table -AutoSize

    }    

    Write-Host "7030 - Service/Desktop Interaction    7045 - New Service Install"    
    Write-Host ""
    Write-Host "Get-Winevent @{$TypeKey=""$TypeVal""; Id=7030,7045}"    
}

# 5. Account Logs
function Invoke-AcctLog {
    param (
        [string]$local:a1,  # System/File
        [string]$local:a2,  # Log Type
        [string]$local:a3,  # Detail/Stats
        [string]$local:a4   # CountOptionalParameters
    )

    [string] $local:TypeKey = ""
    [string] $local:TypeVal = ""

    $TypeKey, $TypeVal = Set-SecurityLogType $a1 $a2

    # Log Detail 
    if ($a3 -eq 1) {
        Get-Winevent @{ $TypeKey = "$TypeVal"; Id=4720,4722, 4727, 4728, 4732, 4735, 4737, 4738, 4755} `
        | Select-Object -First $a4 `
        | Select-Object TimeCreated, Id
        | Format-Table -AutoSize
    }

    # Log Stats
    if ($a3 -eq 2) {
        Get-Winevent @{ $TypeKey = "$TypeVal"; Id=4720,4722, 4727, 4728, 4732, 4735, 4737, 4738, 4755} `
        | Select-Object -First $a4 `
        | Group-Object -Property Id
        | Sort-Object -Property Count -Descending `
        | Format-Table -AutoSize
    }

    Write-Host "4720 - UserAcctCreated  4728 - MemAddGlobSecGrp  4737 - SecEnabledGlobGrpChg"
    Write-Host "4722 - UsrAcctEnable    4732 - MemAddLocSecGrp   4738 - UsrAcctChg"
    Write-Host "4727 - ResetPasswd      4735 - SecLocGrpChg      4755 - SecUnivGrpChg"
    Write-Host ""
    Write-Host "Get-Winevent @{$TypeKey=""$TypeVal""; Id=4720,4722, 4727, 4728, 4732, 4735, 4737, 4738, 4755}"        
}

function Invoke-Rdp {
    param (
        [string]$local:a1,  # System/File
        [string]$local:a2,  # Log Type
        [string]$local:a3,  # Detail/Stats
        [string]$local:a4   # CountOptionalParameters
    )

    [string] $local:TypeKey = ""
    [string] $local:TypeVal = ""

    $TypeKey, $TypeVal = Set-SecurityLogType $a1 $a2

        # Log Detail 
        if ($a3 -eq 1) {
            Get-Winevent @{ $TypeKey = "$TypeVal"; Id=21,22,23,24} `
            | Select-Object -First $a4 `
            | Select-Object TimeCreated, Id, MachineName,  UserId, `
            @{Label='Address'; Expression={$_.Properties[2].Value}}, `
            @{Label='User'; Expression={$_.Properties[0].Value}} `
            | Format-Table -AutoSize
        }
    
        # Log Stats
        if ($a3 -eq 2) {
            Get-Winevent @{ $TypeKey = "$TypeVal"; Id=21,22,23,24} `
            | Select-Object -First $a4 `
            | Group-Object -Property Id, MachineName, UserId -NoElement `
            | Sort-Object -Property Count -Descending `
            | Format-Table -AutoSize
        }

        Write-Host "21 - RDP Logon   22 - RDP ShellStart   23 - RDP Logoff   24 - RDP SessionDisconnect"
        Write-Host ""
        Write-Host "Get-Winevent @{$TypeKey=""$TypeVal""; Id=21, 22, 23, 24}"
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
    elseif ($ans1 -notin @(1,2)) {
        while ($ans1 -notin @(1,2)) {
            Clear-Host
            Write-Host "Not a correct choice:"
            Write-Host "[1] System [2] File"
            $ans1 = Read-Host "Entry"
        }
    }

    Clear-Host

    Write-Host "[0] Quit            [4] Service Created"
    Write-Host "[1] Logon           [5] Account Change"
    Write-Host "[2] Logon/Logoff    [6] Remote Desktop"
    Write-Host "[3] Process"

    $ans2 = Read-Host "Entry"

    if ( $ans2 -eq "0" ) { Clear-Host; Write-Host "Bye"; `
        Return "0", "0" }        
    elseif ($ans2 -notin @(1,2,3,4,5,6)) {
        while ($ans2 -notin @(1,2,3,4,5,6)) {
            Clear-Host
            Write-Host "Not a correct choice:"
            Write-Host "[1] Logon [2] Logon/Logoff [3] Process [4] Service Created"
            Write-Host "[5] Account Change [5] Remote Desktop"
            $ans2 = Read-Host "Entry"
        }
    }                
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
    elseif ($ans3 -notin @(1,2)) {
        while ($ans3 -notin @(1,2)) {
            Clear-Host
            Write-Host "Not a correct choice:"
            Write-Host "[1] Detail  [2] Stats"
            $ans3 = Read-Host "Entry"
        }
    } 


    Write-Host ""
    $ans4 = Read-Host "How many"

    if ( $ans4 -eq "0" ) { Clear-Host; Write-Host "Bye"; `
        Return "0", "0" }

    return $ans3, $ans4        
}

# Write-Host "ANS1: " $ans1 # 1-System, 2-File
# Write-Host "ANS2: " $ans2 # 1-Logon, 2-Process ..
# Write-Host "ANS3: " $ans3 # 1-Detail, 2-Stats
# Write-Host "ANS4: " $ans4 # Count  

function Get-LoadLog() {

    [string] $local:ans1 = ""
    [string] $local:ans2 = "" 
    [string] $local:ans3 = "" 
    [string] $local:ans4 = ""        

    $ans1, $ans2 = Get-Menu1

    if (($ans1 -eq 0) -or ($ans2 -eq 0)) {
        return
    } else{
        $ans3, $ans4 = Get-Menu2
    }

    while ($ans3 -ne "0") {
        
        if ($ans2 -eq 1) {
            Invoke-LogonLog $ans1 $ans2 $ans3 $ans4
        }

        if ($ans2 -eq 2) {
            Invoke-LogonOthLog $ans1 $ans2 $ans3 $ans4
        }

        if ($ans2 -eq 3) {
            Invoke-ProcLog $ans1 $ans2 $ans3 $ans4
        }

        if ($ans2 -eq 4) {
            Invoke-SrvcLog $ans1 $ans2 $ans3 $ans4
        }

        if ($ans2 -eq 5) {            
            Invoke-AcctLog $ans1 $ans2 $ans3 $ans4
        }

        if ($ans2 -eq 6) {
            Invoke-Rdp $ans1 $ans2 $ans3 $ans4
        }

        $ans3, $ans4 = Get-Menu2
    }


}

Set-Alias ldl Get-LoadLog
Export-ModuleMember -Function Get-LoadLog 
Export-ModuleMember -Alias ldl