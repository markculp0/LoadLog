
***

### LoadLog Module 

***

A command line, menu-driven Powershell script for searching Windows Event Logs.

***

* LoadLog.psm1 - This module contains the app's command line menu and log querying capability. Must be run as an administrator on the system to query certain system logs such as the "Security" log.  If querying .evtx file, the script assumes the file exists in the current directory. 

* ldl.ps1 - Script to import module.

* cpmod.ps1 - Script to install/copy the module to its own module folder.  This would be C:\Program Files\PowerShell\7\Modules\LoadLog for system-wide use.  The script assumes a "LoadLog" directory has already been created in this location.

***
***

