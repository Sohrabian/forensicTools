function Get-SysmonLogsProcessStarts {
	<#
		This cmd-let will make it possible to get the logs from sysmon which you can filter and 
		search for malicious activity.
		.EXAMPLE
		Get-SysmonLogs
		.EXAMPLE
		get-sysmonlogs | where {($_.parentImage -like "*office*") -and ($_.CommandLine -like "*powershell*")}
	#>
	<#
		PowerShell Profile, to Use regularly in your interactive PowerShell Sessions
		##Nothing
	#>
	
	<#
	#Listing Available Logs with "Get-WinEvent"
	Get-WinEvent -ListLog * | Select-Object LogName, RecordCount, IsClassicLog, IsEnabled, LogMode, LogType | Format-Table -AutoSize
	
	#Listing Event Log Providers
	Get-WinEvent -ListProvider * | Format-Table -Autosize
	
	#some Example based on Provider
	Get-WinEvent -Path 'C:\Users\h.sohrabian\Desktop\new-case\Exir.bm\Logs SQL Server\SQL Logs\Application.evtx' | Where-Object {$_.ProviderName -eq 'MSSQLSERVER'}
	
	Get-WinEvent -Path 'C:\path\*.evtx' | Where-Object {$_.ProviderName -eq 'MSSQLSERVER'}
	#>
	<#
	#Some Example in Live Forensic
	#requires Sysmon and an admin Powershell:
	PS C:\> Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational"
	#Pull Sysmon Event ID 1 from the live Sysmon Event Log
	PS C:\> Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational"; id=1}
	#>
	
	<#
	#Some Example in Dead Forensic
	PS C:\> Get-WinEvent -FilterHashtable @{Path="system.evtx"; ID=7030,7045}
	PS C:\> Get-WinEvent -FilterHashtable @{Path="system.evtx"} | Where {$_.Message -like "*USB*"}
	
	#Search Based on TimeStamp in a Certian Time Range
	PS C:\> $EventID = 1
	PS C:\> $startTime = Get-Date -Date "Jan. 7, 2020 12:00:00 AM"
	PS C:\> $endTime = Get-Date -Date "Feb. 6, 2020 11:59:59 PM"
	ps C:\> Get-WinEvent -Path 'C:\\' | Where-Object {$_.id -eq $EventID -and $_.TimeCreated -ge $startTime -and $_.TimeCreated -le $endTime}
	#>
	
	param
	(
		[array]$Computers = $env:COMPUTERNAME
	)
	foreach ($ComputerName in $Computers){
		try {
			#get id - process start
			$events = Get-WinEvent -ComputerName $ComputerName -FilterHashtable @{logname = "Microsoft-Windows-Sysmon/Operational"; Id = 1;} -erroraction silentlycontinue
			
			foreach ($event in $events) {
				$eventXML = [xml]$Event.ToXml()
				#create object
				New-Object -Type psobject -Property @{
					UTCTime = $eventXML.Event.EventData.Data[1].'#text'
					CommandLine = $eventXML.Event.EventData.Data[10].'#text'
					CurrentDirectory = $eventXML.Event.EventData.Data[11].'#text'
					User = $eventXML.Event.EventData.Data[12].'#text'
					IntegrityLevel = $eventXML.Event.EventData.Data[16].'#text'
					Hashes = $eventXML.Event.EventData.Data[17].'#text'
					ParentImage = $eventXML.Event.EventData.Data[20].'#text'
				}
			}
		}
		catch {
			Write-Host "Something went wrong, Please Install Sysmon nHost: $ComputerName"
		}
	}
}