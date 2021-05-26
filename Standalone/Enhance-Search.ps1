# Requirements: Run with elevated privileges (i.e., Administrator)

function Enhance-Search {

    # Remove Bing from search
    Write-Host "Removing Bing suggestions..." -ForegroundColor Yellow
    $BingSearch = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer'
    if (!(Test-Path $BingSearch)) { New-Item $BingSearch -Force | Out-Null }
    Set-ItemProperty -Path $BingSearch -Name DisableSearchBoxSuggestions -Value 1
    Write-Host "Done." -ForegroundColor Green


    # Set Windows Search to use 'Enhanced' Mode; Creates a Scheduled Task that runs as SYSTEM to change Registry Key and then deletes itself.
    Write-Host "Enabling 'Enhanced' mode..." -ForegroundColor Yellow
    $EnhancedSearch = "Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Search\Gather\Windows\SystemIndex' -Name 'EnableFindMyFiles' -Value 1"

    $PS = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-command `"$EnhancedSearch`""
    $Time = New-ScheduledTaskTrigger -At (Get-Date).AddSeconds(5) -Once
    $Time.EndBoundary = (Get-Date).AddSeconds(15).ToString('s')
    $Remove = New-ScheduledTaskSettingsSet -DeleteExpiredTaskAfter 00:00:01
    Register-ScheduledTask -TaskName 'Enhance Search' -Action $PS -Trigger $Time -Settings $Remove -User SYSTEM -Force | Out-Null
    
    Write-Host "Done." -ForegroundColor Green
}
Enhance-Search