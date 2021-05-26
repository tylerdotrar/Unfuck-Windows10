# Requirements: Run with elevated privileges (i.e., Administrator)

function Enhance-StartMenu {

    # Disable Live Tiles
    Write-Host "Disabling 'Live Tiles'..." -ForegroundColor Yellow
    $LiveTiles = 'Registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'
    if (!(Test-Path $LiveTiles)) { New-Item $LiveTiles -Force | Out-Null }
    Set-ItemProperty -Path $LiveTiles -Name 'NoTileApplicationNotification' -Value 1
    Write-Host "Done." -ForegroundColor Green


    ### Unpin all Items from Start Menu
    Write-Host "Removing remaining tiles..." -ForegroundColor Yellow

    $LayoutFile="C:\Windows\StartMenuLayout.xml"
    $StartMenuContents = @"
<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
<LayoutOptions StartTileGroupCellWidth="6" />
<DefaultLayoutOverride>
<StartLayoutCollection>
    <defaultlayout:StartLayout GroupCellWidth="6" />
</StartLayoutCollection>
</DefaultLayoutOverride>
</LayoutModificationTemplate>
"@

    # Create new empty layout file
    if (Test-Path $LayoutFile) { Remove-Item $LayoutFile }
    $StartMenuContents | Out-File $LayoutFile -Encoding ASCII

    # Assign the start layout and force it to apply with "LockedStartLayout" at both the machine and user level
    $HiveKeys = @('Registry::HKEY_LOCAL_MACHINE','Registry::HKEY_CURRENT_USER')
    
    foreach ($Hive in $HiveKeys) {
        $Parent = $Hive + "\SOFTWARE\Policies\Microsoft\Windows"
        $KeyPath = $Parent + "\Explorer" 
        if (!(Test-Path -Path $KeyPath)) { New-Item -Path $Parent -Name "Explorer" | Out-Null }
        Set-ItemProperty -Path $KeyPath -Name 'LockedStartLayout' -Value 1
        Set-ItemProperty -Path $KeyPath -Name 'StartLayoutFile' -Value $LayoutFile
    }

    # Restart Explorer, open the start menu (necessary to load the new layout), and give it a few seconds to process
    Get-Process -Name explorer | Stop-Process
    Start-Sleep 5

    $Shell = New-Object -ComObject wscript.shell
    $Shell.SendKeys('^{ESCAPE}')
    Start-Sleep 5

    # Enable the ability to pin items again by disabling "LockedStartLayout"
    foreach ($Hive in $HiveKeys){
        $Parent = $Hive + "\SOFTWARE\Policies\Microsoft\Windows"
        $KeyPath = $Parent + "\Explorer" 
        Set-ItemProperty -Path $KeyPath -Name 'LockedStartLayout' -Value 0
    }

    # Restart Explorer and delete the layout file
    Get-Process -Name explorer | Stop-Process
    Remove-Item $LayoutFile

    Write-Host "Done." -ForegroundColor Green
}
Enhance-StartMenu