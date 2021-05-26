# Requirements: Run with elevated privileges (i.e., Administrator)

function Enhance-Taskbar {

    # Remove Microsoft Edge and Microsoft Store from Taskbar
    Write-Host "Removing 'Microsoft Store' and 'Microsoft Edge'..." -ForegroundColor Yellow
    $Items = @('Microsoft Store', 'Microsoft Edge')

    $ObjectList = (New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items()
    foreach ($Item in $Items) { 
        $ObjectList | ? { $_.Name -eq $Item } | % {$_.Verbs()} | ? { $_.Name.Replace('&','') -eq 'Unpin from Taskbar' } | % { $_.DoIt() }
    }
    
    $ObjectList = $NULL
    Write-Host "Done." -ForegroundColor Green


    # Remove 'People' icon from Taskbar
    Write-Host "Removing 'People'..." -ForegroundColor Yellow
    $People = 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People'
    if (!(Test-Path $People)) { New-Item $People -Force | Out-Null }
    Set-ItemProperty -Path $People -Name 'PeopleBand' -Value 0
    Write-Host "Done." -ForegroundColor Green


    # Remove 'Meet Now' from the Taskbar
    Write-Host "Removing 'Meet Now'..." -ForegroundColor Yellow
    $MeetNow = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    if (!(Test-Path $MeetNow)) { New-Item $MeetNow -Force | Out-Null }
    Set-ItemProperty -Path $MeetNow -Name 'HideSCAMeetNow' -Value 1
    Write-Host "Done." -ForegroundColor Green


    # Remove 'TaskView' from the Taskbar
    Write-Host "Removing 'Task View'..." -ForegroundColor Yellow
    $TaskView = 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
    if (!(Test-Path $TaskView)) { New-Item $TaskView -Force | Out-Null }
    Set-ItemProperty -Path $TaskView -Name 'ShowTaskViewButton' -Value 0
    Write-Host "Done." -ForegroundColor Green


    # Hide Search Box on Taskbar
    Write-Host "Hiding the Search Box..." -ForegroundColor Yellow
    $SearchBox = 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search'
    if (!(Test-Path $SearchBox)) { New-Item $SearchBox -Force | Out-Null }
    Set-ItemProperty -Path $SearchBox -Name 'SearchboxTaskbarMode' -Value 0
    Write-Host "Done." -ForegroundColor Green
}
Enhance-Taskbar