$ApiKey= Read-Host -prompt "Enter Your ViruslTotalAPIKey"
while ($true){
	$FilePath = Read-Host -prompt "Please Enter your Path"
	if (Test-Path -Path $FilePath) {break}
	Write-Host "Wrong Path. PLZ Try Again" -ForegroundColor Red
}
Invoke-RestMethod -Method 'POST' -Uri 'https://www.virustotal.com/vtapi/v2/file/report' -Body @{ resource =(Get-FileHash $FilePath | select -ExpandProperty Hash); apikey= $ApiKey}
