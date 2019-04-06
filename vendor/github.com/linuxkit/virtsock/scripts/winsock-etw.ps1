# A quick and dirty script to run ETW tracing on Winsock and other
# relevant providers

# Use
# logman query providers
# to see all providers and:
# logman query providers "Windows Kernel Trace"
# to get details about the flags

param([string]$outFile = "winsock.etl")

$session = "MyWinSockTrace"

logman start -ets $session -o $outFile -p Microsoft-Windows-Winsock-AFD

# logman query -ets $session

Write-Host "Tracing. Press any key to stop..."
$x = [System.Console]::ReadKey().Key.ToString()

logman stop -ets $session
