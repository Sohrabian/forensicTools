$HashString = Read-Host -Prompt "Enter Your Hash"
While ($true) {
    $Filepath = Read-Host -Prompt "Please enter a path of your add-on has downlaoded"
    if (Test-Path -Path $Filepath) {break}
    Write-Host "Wrong path. PLZ try again" -ForegroundColor Red
}
$Filepath=(Get-FileHash $Filepath -Algorithm SHA256).Hash
if ($HashString -eq $Filepath) {Write-Host "Your Hash Files is The Same" -ForegroundColor green "\n" }
Elseif ($HashString -ne $Filepath){Write-Host "your hash files are not in the same" -ForegroundColor Red "\n" }