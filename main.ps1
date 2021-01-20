# This script MUST be run as administrator in order to read the Bitlocker data from AD
# This script also requires the RSAT AD module. 

# Get RSAT from here:
# https://www.microsoft.com/en-us/download/details.aspx?id=45520

####	Self Elevating Code	####

# Get the ID and security principal of the current user account
$myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
 
# Get the security principal for the Administrator role
$adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
 
# Check to see if we are currently running "as Administrator"
if ($myWindowsPrincipal.IsInRole($adminRole))
   {
   # We are running "as Administrator" - so change the title and background color to indicate this
   $Host.UI.RawUI.WindowTitle = $myInvocation.MyCommand.Definition + "(Elevated)"
   $Host.UI.RawUI.BackgroundColor = "DarkBlue"
   clear-host
   }
else
   {
   # We are not running "as Administrator" - so relaunch as administrator
   
   # Create a new process object that starts PowerShell
   $newProcess = new-object System.Diagnostics.ProcessStartInfo "PowerShell";
   
   # Specify the current script path and name as a parameter
   $newProcess.Arguments = $myInvocation.MyCommand.Definition;
   
   # Indicate that the process should be elevated
   $newProcess.Verb = "runas";
   
   # Start the new process
   [System.Diagnostics.Process]::Start($newProcess);
   
   # Exit from the current, unelevated, process
   exit
   }
 

####	Main Code	####

# Create a timestamp for one year ago
$d = [DateTime]::Today.AddDays(-365);

# Set the OU to look in
$VenOU = ""

# Grab all computers from that OU that have logged in sometime in the last year
# To change this to show ALL computers in the CFE OU, change $VenPCs on line 59 to $VenPCs_All
$VenPCs = Get-ADComputer -Filter 'LastLogonDate -ge $d' -SearchBase $VenOU -Properties * 
# $VenPCs_all = Get-ADComputer -Filter * -SearchBase $VenOU -Properties * 

# Create an array of Powershell Objects, comprised of the Hostname, last login date, and encryption date
$Results = ForEach ($Computer in $VenPCs)
{
  # Creating the object for each computer
	New-Object PSObject -Property @{
		ComputerName = $Computer.Name
		LastLogon = $Computer.LastLogonDate
		Encryption_Date = Get-ADObject -Filter {objectclass -eq 'msFVE-RecoveryInformation'} -SearchBase $Computer.DistinguishedName -Properties 'msFVE-RecoveryPassword'
	}
}

# Clean up the Encryption_Date string, so it just shows the date.
foreach ($computer in $Results) 
{ 
	# Returns True if the string is empty, False if not empty.
	# This is used to catch computers without keys
	$keyExists = [string]::IsNullOrEmpty($computer.Encryption_Date)
	if(-not $keyExists) {
		$name = $computer.Encryption_Date
    # Have to turn the Encryption Date into a string so we can use the Substring function to trim it
		$date =  Out-String -InputObject $name
		$new = $date.Substring(32,10)
	}elseif($keyExists) {$new = "Key not found!"}
	$computer.Encryption_Date = $new
}

# Set the full path of the file to export to
$OutFile = $env:USERPROFILE+"\desktop\Bitlocker_Report.txt"

# Sort the results by Encryption Date, thereby grouping the troubled ones together
$Results = $Results | sort Encryption_Date

# Dump the results to a file
$Results | Out-File $OutFile

# Alert the user
Write-Host The Bitlocker report has been saved to your desktop.

# Open the report
notepad.exe $OutFile 

# Leave console open to review any errors that may have occured
pause
