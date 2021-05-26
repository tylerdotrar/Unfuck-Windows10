<#
Unfuck-Windows10.ps1 
Version 1.4.3
This script was tested on Windows 10 Pro (version 20H2) -- it has not been tested on Windows 10 Home.

Purpose:         Debloat Windows 10, improve performance, and enhance user privacy & experience.
Requirements:    Run with elevated privileges (i.e., Administrator)
Syntax:          iex ((New-Object System.Net.WebClient).DownloadString('https://git.io/JspIT'))

Links:
https://github.com/tylerdotrar/Unfuck-Windows10
https://git.io/JspIT
#>


# Exit if session doesn't have elevated privileges
$User = [Security.Principal.WindowsIdentity]::GetCurrent();
$isAdmin = (New-Object Security.Principal.WindowsPrincipal $User).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if (!$isAdmin) { return (Write-Host 'This script requires elevated privileges.' -ForegroundColor Red) }


function Remove-WindowsBloat {

    function Uninstall-OneDrive {

        # Move pre-existing user files and data before uninstalling 'OneDrive'
        Write-Host "Checking for files and folders in 'OneDrive'..." -ForegroundColor Yellow
        Start-Sleep 1
    
        if (Test-Path "$env:USERPROFILE\OneDrive\*") {
            Write-Host "Content found. Moving to 'OneDriveBackupFiles' on your desktop prior to 'OneDrive' removal."
            Start-Sleep 1
            
            if (!(Test-Path "$env:USERPROFILE\Desktop\OneDriveBackupFiles")) { 
                New-item -Path "$env:USERPROFILE\Desktop" -Name "OneDriveBackupFiles"-ItemType Directory -Force
            }
    
            Start-Sleep 1
            Move-Item -Path "$env:USERPROFILE\OneDrive\*" -Destination "$env:USERPROFILE\Desktop\OneDriveBackupFiles" -Force
            Start-Sleep 1
            Write-Host "Complete. Proceeding with the removal of OneDrive."
            Start-Sleep 1
        }
        else {
            Write-Host "No content found. Proceeding with removal of OneDrive."
            Start-Sleep 1
            
            # Enabling the Group Policy 'Prevent the usage of OneDrive for File Storage'
            $OneDriveKey = 'HKLM:Software\Policies\Microsoft\Windows\OneDrive'
            if (!(Test-Path $OneDriveKey)) { New-Item $OneDriveKey -Force | Out-Null }
            Set-ItemProperty $OneDriveKey -Name OneDrive -Value DisableFileSyncNGSC
        }
        Write-Host "Done." -ForegroundColor Green
        
    
        # Executing uninstaller
        Write-Host "Executing 'OneDrive' uninstaller..." -ForegroundColor Yellow
        Get-Process OneDrive | Stop-Process -Force
        Get-Process explorer | Stop-Process -Force
    
        $OneDrive64bit = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
        $OneDrive32bit = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
    
        if (Test-Path $OneDrive64bit) { & $OneDrive64bit /uninstall }
        if (Test-Path $OneDrive32bit) { & $OneDrive32bit /uninstall }
        Write-Host "Done." -ForegroundColor Green
    
    
        # Remove from Explorer sidebar
        Write-Host "Removing 'OneDrive' from Explorer sidebar..." -ForegroundColor Yellow
        New-Item "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Force | Out-Null
        Set-ItemProperty -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Value 0
        New-Item "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Force | Out-Null
        Set-ItemProperty -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Value 0
        Write-Host "Done." -ForegroundColor Green
    
    
        # Disable run option for New Users
        Write-Host "Removing run option for new users..." -ForegroundColor Yellow
        reg load "hku\Default" "C:\Users\Default\NTUSER.DAT"
        reg delete "HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
        reg unload "hku\Default"
        Write-Host "Done." -ForegroundColor Green
    
    
        # Cleaning up
        Write-Host "Removing 'OneDrive' leftovers..." -ForegroundColor Yellow
        Remove-Item -Recurse "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -ErrorAction SilentlyContinue
        Remove-Item -Recurse "$env:PROGRAMDATA\Microsoft OneDrive" -Force -ErrorAction SilentlyContinue
        Remove-Item -Recurse "$env:SYSTEMDRIVE\OneDriveTemp" -Force -ErrorAction SilentlyContinue
        Write-Host "Done." -ForegroundColor Green
    
        Write-Host "Removing StartMenu junk entry..." -ForegroundColor Yellow
        Remove-Item "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" -Force -ErrorAction SilentlyContinue
        Write-Host "Done." -ForegroundColor Green
    
        Write-Host "Restarting explorer.exe..." -ForegroundColor Yellow
        Start-Process "explorer.exe"
        Write-Host "Done." -ForegroundColor Green
    
        Write-Host "Waiting for Explorer to reload..." -ForegroundColor Yellow
        Start-Sleep -Seconds 15
        Write-Host "Done." -ForegroundColor Green
    }


    # Bloat apps and packages (Configure as Desired)
    $Bloatware = @(

        # Windows 10 AppX Apps
        "Microsoft.549981C3F5F10" # Cortana
        "Microsoft.BingNews"
        "Microsoft.GetHelp"
        "Microsoft.Getstarted"
        "Microsoft.Messaging"
        "Microsoft.Microsoft3DViewer"
        "Microsoft.MicrosoftOfficeHub"
        "Microsoft.MicrosoftSolitaireCollection"
        "Microsoft.Mixedreality.Portal"
        "Microsoft.NetworkSpeedTest"
        "Microsoft.News"
        "Microsoft.Office.Lens"
        "Microsoft.Office.OneNote"
        "Microsoft.Office.Sway"
        "Microsoft.OneConnect"
        "Microsoft.People"
        "Microsoft.Print3D"
        "Microsoft.RemoteDesktop"
        "Microsoft.SkypeApp"
        "Microsoft.StorePurchaseApp"
        "Microsoft.Office.Todo.List"
        "Microsoft.Whiteboard"
        "Microsoft.WindowsAlarms"
        "Microsoft.WindowsFeedbackHub"
        "Microsoft.WindowsMaps"
        "Microsoft.WindowsSoundRecorder"
        "Microsoft.ZuneMusic"
        "Microsoft.ZuneVideo"

        "*Microsoft.Advertising.Xaml_10.1712.5.0_x64__8wekyb3d8bbwe*"
        "*Microsoft.Advertising.Xaml_10.1712.5.0_x86__8wekyb3d8bbwe*"
        "*Microsoft.BingWeather*"
        "*Microsoft.MicrosoftStickyNotes*"
        
        #"microsoft.windowscommunicationsapps" # Mail/Calendar
        #"Microsoft.WindowsCamera"
        #"*Microsoft.MSPaint*"
        #"*Microsoft.Windows.Photos*"
        #"*Microsoft.WindowsCalculator*"
        #"*Microsoft.WindowsStore*"
        #"Microsoft.Xbox.TCUI"
        #"Microsoft.XboxApp"
        #"Microsoft.XboxGameOverlay"
        #"Microsoft.XboxIdentityProvider"
        #"Microsoft.XboxSpeechToTextOverlay"

        # Sponsored Windows 10 AppX Apps
        "*EclipseManager*"
        "*ActiproSoftwareLLC*"
        "*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
        "*Duolingo-LearnLanguagesforFree*"
        "*PandoraMediaInc*"
        "*CandyCrush*"
        "*BubbleWitch3Saga*"
        "*Wunderlist*"
        "*Flipboard*"
        "*Twitter*"
        "*Facebook*"
        "*Spotify*"
        "*Minecraft*"
        "*Royal Revolt*"
        "*Sway*"
        "*Speed Test*"
        "*Dolby*"
    )

    # Remove bloat apps and packages
    Write-Host "Attemping to remove bloatware..." -ForegroundColor Yellow
    foreach ($Bloat in $Bloatware) {

        $Package1 = (Get-AppxPackage -AllUsers -Name $Bloat)
        $Package2 = (Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat)

        if ($Package1 -or $Package2) {
            $Package1 | % { Remove-AppxPackage $_ }
            $Package2 | % { Remove-AppxProvisionedPackage -Online -AllUsers -PackageName $_.PackageName | Out-Null }
            Write-Host "- $Bloat"
        }
        else { Write-Host "- $Bloat" -ForegroundColor Red }
    }
    Write-Host "Done." -ForegroundColor Green

    # Remaining Xbox related bloat
    Write-Host "Removing all Xbox related bloat..." -ForegroundColor Yellow
    Get-ProvisionedAppxPackage -Online | ? { $_.PackageName -match "xbox" } | % { 
        Remove-ProvisionedAppxPackage -Online -AllUsers -PackageName $_.PackageName | Out-Null
        Write-Host "-" $_.DisplayName
    }
    Write-Host "Done." -ForegroundColor Green


    # Bloat Registry Keys
    $Keys = @(
            
        # Remove Background Tasks
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
            
        # Windows File
        "HKCR:\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
            
        # Registry keys to delete if they aren't uninstalled by RemoveAppXPackage/RemoveAppXProvisionedPackage
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
            
        # Scheduled Tasks to delete
        "HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
            
        # Windows Protocol Keys
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
            
        # Windows Share Target
        "HKCR:\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
    )
        
    # Remove Registry Keys if they Exist
    Write-Host "Attempting to remove keys from the Registry..." -ForegroundColor Yellow
    foreach ($Key in $Keys) { 
        if (Test-Path $Key) { Remove-Item $Key -Recurse -Force 2>$NULL ; "- $Key" }
        else { Write-Host "- $Key" -ForegroundColor Red }
    }
    Write-Host "Done." -ForegroundColor Green


    # Uninstall 'OneDrive'
    Write-Host "`nRemoving 'OneDrive':" -ForegroundColor Cyan
    Uninstall-OneDrive
    Write-Host "Complete." -ForegroundColor Cyan
}
function Protect-Privacy {
    
    function Disable-Cortana {

        # Disable Cortana data collection
        Write-Host "Stopping Cortana data collection..." -ForegroundColor Yellow
        $Cortana1 = 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Personalization\Settings'
        $Cortana2 = 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputPersonalization'
        $Cortana3 = 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore'
        if (!(Test-Path $Cortana1)) { New-Item $Cortana1 | Out-Null }
        Set-ItemProperty -Path $Cortana1 -Name AcceptedPrivacyPolicy -Value 0
    
        if (!(Test-Path $Cortana2)) { New-Item $Cortana2 | Out-Null }
        Set-ItemProperty -Path $Cortana2 -Name RestrictImplicitTextCollection -Value 1 
        Set-ItemProperty -Path $Cortana2 -Name RestrictImplicitInkCollection -Value 1
    
        if (!(Test-Path $Cortana3)) { New-Item $Cortana3 | Out-Null }
        Set-ItemProperty -Path $Cortana3 -Name HarvestContacts -Value 0
        Write-Host "Done." -ForegroundColor Green
        
        # Stops Cortana from being used as part of your Windows Search Function
        Write-Host "Stopping Cortana from being used as part of Windows Search..." -ForegroundColor Yellow
        $Search = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
        if (!(Test-Path $Search)) { New-Item $Search -Force | Out-Null }
        Set-ItemProperty -Path $Search -Name "AllowCortana" -Value 0 
    
        Write-Host "Done." -ForegroundColor Green
    }


    # Disables Windows Feedback Experience
    Write-Host "Disabling 'Windows Feedback Experience'..." -ForegroundColor Yellow
    $Advertising = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo'
    if (!(Test-Path $Advertising)) { New-Item $Advertising -Force | Out-Null }
    Set-ItemProperty -Path $Advertising -Name Enabled -Value 0 
    Write-Host "Done." -ForegroundColor Green


    # Stops the Windows Feedback Experience from sending anonymous data
    Write-Host "Stopping Windows Feedback Experience program from sending anonymous data..." -ForegroundColor Yellow
    $Period = 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Siuf\Rules'
    if (!(Test-Path $Period)) { New-Item $Period -Force | Out-Null }
    Set-ItemProperty -Path $Period -Name PeriodInNanoSeconds -Value 0
    Write-Host "Done." -ForegroundColor Green


    # Prevents bloatware applications from returning and removes Start Menu suggestions               
    Write-Host "Adding egistry key to prevent bloatware apps from returning..." -ForegroundColor Yellow
    $registryPath = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
    $registryOEM = 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'

    if (!(Test-Path $registryPath)) { New-Item $registryPath -Force | Out-Null }
    Set-ItemProperty -Path $registryPath -Name DisableWindowsConsumerFeatures -Value 1 

    if (!(Test-Path $registryOEM)) { New-Item $registryOEM -Force | Out-Null }
    Set-ItemProperty -Path $registryOEM  -Name ContentDeliveryAllowed -Value 0 
    Set-ItemProperty -Path $registryOEM  -Name OemPreInstalledAppsEnabled -Value 0 
    Set-ItemProperty -Path $registryOEM  -Name PreInstalledAppsEnabled -Value 0 
    Set-ItemProperty -Path $registryOEM  -Name PreInstalledAppsEverEnabled -Value 0 
    Set-ItemProperty -Path $registryOEM  -Name SilentInstalledAppsEnabled -Value 0 
    Set-ItemProperty -Path $registryOEM  -Name SystemPaneSuggestionsEnabled -Value 0
    Write-Host "Done." -ForegroundColor Green


    # Turns off Data Collection via the 'AllowTelemtry key' by changing it to 0
    Write-Host "Turning off Data Collection..." -ForegroundColor Yellow
    $DataCollection1 = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection'
    $DataCollection2 = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
    $DataCollection3 = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection' 
    if (Test-Path $DataCollection1) { Set-ItemProperty -Path $DataCollection1 -Name AllowTelemetry -Value 0 }
    if (Test-Path $DataCollection2) { Set-ItemProperty -Path $DataCollection2 -Name AllowTelemetry -Value 0 }
    if (Test-Path $DataCollection3) { Set-ItemProperty -Path $DataCollection3 -Name AllowTelemetry -Value 0 }
    Write-Host "Done." -ForegroundColor Green


    # Disable 'Cortana'
    Write-Host "`nDisabling 'Cortana':" -ForegroundColor Cyan
    Disable-Cortana
    Write-Host "Complete.`n" -ForegroundColor Cyan


    # Disable "Show me suggested content in the Settings app"
    Write-Host "Disabling suggested content in the Settings app..." -ForegroundColor Yellow
    $ShowSuggested = 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
    $Key1 = 'SubscribedContent-338393Enabled'
    $Key2 = 'SubscribedContent-353694Enabled'
    $Key3 = 'SubscribedContent-353696Enabled'
    Set-ItemProperty -Path $ShowSuggested -Name $Key1 -Value 0
    Set-ItemProperty -Path $ShowSuggested -Name $Key2 -Value 0
    Set-ItemProperty -Path $ShowSuggested -Name $Key3 -Value 0
    Write-Host "Done." -ForegroundColor Green


    # Disabling Location Tracking
    Write-Host "Disabling Location Tracking..." -ForegroundColor Yellow
    $SensorState = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}'
    $LocationConfig = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration'
    if (!(Test-Path $SensorState)) { New-Item $SensorState -Force | Out-Null }
    Set-ItemProperty $SensorState SensorPermissionState -Value 0 
    if (!(Test-Path $LocationConfig)) { New-Item $LocationConfig -Force | Out-Null }
    Set-ItemProperty $LocationConfig Status -Value 0
    Write-Host "Done." -ForegroundColor Green


    # Disables scheduled tasks that are considered unnecessary 
    Write-Host "Disabling Scheduled Tasks..." -ForegroundColor Yellow
    $SchedTasks = @(
        "XblGameSaveTask"
        "Consolidator"
        "UsbCeip"
        "DmClient"
        "DmClientOnScenarioDownload"
    )
    foreach ($Task in $SchedTasks) {
        
        $DisableMe = Get-ScheduledTask $Task -ErrorAction SilentlyContinue
        if ($DisableMe) {
            Disable-ScheduledTask $DisableMe | Out-Null
            Write-Host "- $Task"
        }
        else { Write-Host "- $Task" -ForegroundColor Red }
    }
    Write-Host "Done." -ForegroundColor Green


    # Disable the Diagnostics Tracking Service
    Write-Host "Stopping and disabling Diagnostics Tracking Service..." -ForegroundColor Yellow
    Stop-Service "DiagTrack"
    Set-Service "DiagTrack" -StartupType Disabled
    Write-Host "Done." -ForegroundColor Green
    

    # Remove CloudStore in the Registry
    Write-Host "Removing CloudStore from registry if it exists..." -ForegroundColor Yellow
    $CloudStore = 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore'
    if (Test-Path $CloudStore) {
        Get-Process explorer | Stop-Process -Force
        Remove-Item $CloudStore -Recurse -Force
        Start-Process Explorer.exe -Wait
    }
    Write-Host "Done." -ForegroundColor Green


    # Disable background application access
    Write-Host "Disabling background application access..." -ForegroundColor Yellow
    Get-ChildItem -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications' -Exclude "Microsoft.Windows.Cortana*" | % {
        Set-ItemProperty -Path $_.PsPath -Name "Disabled" -Type DWord -Value 1
        Set-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -Type DWord -Value 1
    }
    Write-Host "Done." -ForegroundColor Green
}
function Enhance-UserExperience {
    
    function Enhance-Explorer {

        # Show File Extensions in Explorer
        Write-Host "Enabling file name extensions..." -ForegroundColor Yellow
        $ExplorerPath = 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
        Set-ItemProperty -Path $ExplorerPath -Name HideFileExt -Value 0
        Write-Host "Done." -ForegroundColor Green
        

        # Remove Paint3D stuff from context menu
        Write-Host "Removing Paint3D context menu options..." -ForegroundColor Yellow
        $Paint3DKeys = @(
            "HKCR:\SystemFileAssociations\.3mf\Shell\3D Edit"
            "HKCR:\SystemFileAssociations\.bmp\Shell\3D Edit"
            "HKCR:\SystemFileAssociations\.fbx\Shell\3D Edit"
            "HKCR:\SystemFileAssociations\.gif\Shell\3D Edit"
            "HKCR:\SystemFileAssociations\.jfif\Shell\3D Edit"
            "HKCR:\SystemFileAssociations\.jpe\Shell\3D Edit"
            "HKCR:\SystemFileAssociations\.jpeg\Shell\3D Edit"
            "HKCR:\SystemFileAssociations\.jpg\Shell\3D Edit"
            "HKCR:\SystemFileAssociations\.png\Shell\3D Edit"
            "HKCR:\SystemFileAssociations\.tif\Shell\3D Edit"
            "HKCR:\SystemFileAssociations\.tiff\Shell\3D Edit"
        )

        # Rename registry key to remove it, so it's revertible
        foreach ($Paint3D in $Paint3DKeys) {

            if (Test-Path $Paint3D) {
                $RenamedKey = $Paint3D + "_"
                Set-Item $Paint3D $RenamedKey
            }
        }
        Write-Host "Done." -ForegroundColor Green


        # Removes 3D Objects from the 'My Computer' submenu in explorer
        Write-Host "Removing 3D Objects from 'My Computer' submenu..." -ForegroundColor Yellow
        $Objects32bit = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}'
        $Objects64bit = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}'
    
        if (Test-Path $Objects32bit) { Remove-Item $Objects32bit -Recurse }
        if (Test-Path $Objects64bit) { Remove-Item $Objects64bit -Recurse }
    
        Write-Host "Done." -ForegroundColor Green
    }
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
    function Enhance-StartMenu {

        # Disable Live Tiles
        Write-Host "Disabling 'Live Tiles'..." -ForegroundColor Yellow
        $LiveTiles = 'Registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'
        if (!(Test-Path $LiveTiles)) { New-Item $LiveTiles -Force | Out-Null }
        Set-ItemProperty -Path $LiveTiles -Name 'NoTileApplicationNotification' -Value 1
        Write-Host "Done." -ForegroundColor Green
    
    
        ### Unpin all Items from Start Menu
        Write-Host "Unpinning all items from Start..." -ForegroundColor Yellow
    
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


    # Improve File Explorer
    Write-Host "Enhancing 'Explorer':" -ForegroundColor Cyan
    Enhance-Explorer
    Write-Host "Complete.`n" -ForegroundColor Cyan


    # Remove all bloat from Taskbar
    Write-Host "Enhancing 'Taskbar':" -ForegroundColor Cyan
    Enhance-Taskbar
    Write-Host "Complete.`n" -ForegroundColor Cyan

 
    # Remove all bloat from StartMenu
    Write-Host "Enhancing 'Start Menu':" -ForegroundColor Cyan
    Enhance-StartMenu
    Write-Host "Complete.`n" -ForegroundColor Cyan


    # Improve Search
    Write-Host "Enhancing 'Search':" -ForegroundColor Cyan
    Enhance-Search
    Write-Host "Complete.`n" -ForegroundColor Cyan


    # Enable Windows Dark Mode
    Write-Host "Enabling Windows dark theme..." -ForegroundColor Yellow
    $DarkTheme = 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize'
    if (!(Test-Path $DarkTheme)) { New-Item $DarkTheme -Force | Out-Null }
    Set-ItemProperty -Path $DarkTheme -Name 'AppsUseLightTheme' -Value 0
    Write-Host "Done." -ForegroundColor Green


    # Unlock and Enable 'Ultimate Performance' Power Plan
    Write-Host "Unlocking and enabling the 'Ultimate Performance' power plan..." -ForegroundColor Yellow
    powercfg -DUPLICATESCHEME e9a42b02-d5df-448d-aa00-03f14749eb61 | Out-Null
    $PowerGUID = ((powercfg -LIST | Select-String 'Ultimate Performance') -split ' ')[3]
    powercfg -SETACTIVE $PowerGUID
    Write-Host "Done." -ForegroundColor Green


    # Remove Windows Update bandwidth limits
    Write-Host "Removing Windows Update bandwidth limitation..." -ForegroundColor Yellow
    $Bandwidth = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Psched'
    if (!(Test-Path $Bandwidth)) { New-Item $Bandwidth -Force | Out-Null }
    Set-ItemProperty -Path $Bandwidth -Name "NonBestEffortLimit" -Value 0
    Write-Host "Done." -ForegroundColor Green


    # Fixes the DMW service if it happens to be disabled or stopped.
    Write-Host "Potentially fixing the 'Device Management WAP Push' message routing service..." -ForegroundColor Yellow
    if (Get-Service -Name dmwappushservice | Where-Object {$_.StartType -eq "Disabled"}) {
        Set-Service -Name dmwappushservice -StartupType Automatic
    }
    if (Get-Service -Name dmwappushservice | Where-Object {$_.Status -eq "Stopped"}) {
        Start-Service -Name dmwappushservice
    }
    Write-Host "Done." -ForegroundColor Green


    # Cleanup TEMP directory
    Write-Host "Cleaning up the Temp directory..." -ForegroundColor Yellow
    Remove-Item -Path $env:TEMP -Recurse -Force -ErrorAction SilentlyContinue
    if (!(Test-Path $env:TEMP)) { New-Item $env:TEMP -Type Directory | Out-Null }
    Write-Host "Done." -ForegroundColor Green


    # Verify system files
    Write-Host "Verifying system integrity..." -ForegroundColor Yellow
    sfc /scannow
    Write-Host "Done." -ForegroundColor Green
}
function Get-TheBasics {

    # Disable IE first time run wizard (for Invoke-WebRequest support)
    Write-Host "Disabling IE first time run wizard for 'Invoke-WebRequest' support..." -ForegroundColor Yellow
    $IEwizard = 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main'
    if (!(Test-Path $IEwizard)) { New-Item $IEwizard -Force | Out-Null }
    Set-ItemProperty -Path $IEwizard -Name 'DisableFirstRunCustomize' -Value 1
    Write-Host "Done." -ForegroundColor Green


    # Update 'Get-Help'
    Write-Host "Updating PowerShell 'Get-Help' cmdlet..." -ForegroundColor Yellow
    Update-Help 2>$NULL
    Write-Host "Done." -ForegroundColor Green
    

    # Enable .NET Framework 3.5
    Write-Host "Installing .NET Framework 3.5..." -ForegroundColor Yellow
    if ((Get-WindowsOptionalFeature -Online -FeatureName NetFx3).State -ne 'Enabled') { 
        Write-Host "`n - NetFx3" -ForegroundColor Cyan
        DISM /Online /Enable-Feature /FeatureName:NetFx3 /All
    }
    Write-Host "Done." -ForegroundColor Green


    if ($ToolBool) {
        # Chocolatey
        Write-Host "Installing Chocolatey..." -ForegroundColor Yellow
        Set-ExecutionPolicy Bypass -Scope Process -Force; Invoke-Expression (Invoke-WebRequest https://chocolatey.org/install.ps1).content | Out-Null
        choco install chocolatey-core.extension -y | Out-Null
        Write-Host "Done." -ForegroundColor Green


        # The Basics
        Write-Host "Installing the basics..." -ForegroundColor Yellow
        choco install git --params "/GitOnlyOnPath /NoShellIntegration" -y | Out-Null ; "- git"
        choco install vim --params "'/NoContextmenu /NoDesktopShortcuts /InstallDir:C:\.Tools'" -y | Out-Null ; "- vim"
        choco install notepadplusplus -ia /D=C:\.Tools\Notepad++ -y | Out-Null ; "- notepadplusplus"
        choco install 7zip -ia /D=C:\.Tools\7-Zip+ -y | Out-Null ; "- 7zip"
        choco install powershell-core --install-arguments='"ADD_FILE_CONTEXT_MENU_RUNPOWERSHELL=1 ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1"' -y | Out-Null ; "- powershell-core"
        choco install microsoft-windows-terminal -y | Out-Null ; "- microsoft-windows-terminal"
        Write-Host "Done." -ForegroundColor Green
    }
}
function Install-WSL2 {
    
    ### Windows Subsystem for Linux (Part 1) -- Install Dependencies
    $NeedDependency1 = (Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux).State -ne 'Enabled'
    $NeedDependency2 = (Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform).State -ne 'Enabled'

    if ($NeedDependency1 -or $NeedDependency2) {
        Write-Host "Installing WSL dependencies..." -ForegroundColor Yellow
        Write-Host "`n - Microsoft-Windows-Subsystem-Linux" -ForegroundColor Cyan
        DISM /Online /Enable-Feature /FeatureName:Microsoft-Windows-Subsystem-Linux /All /NoRestart
        Write-Host "`n - VirtualMachinePlatform" -ForegroundColor Cyan
        DISM /Online /Enable-Feature /FeatureName:VirtualMachinePlatform /All /NoRestart
        Write-Host "Done." -ForegroundColor Green

        $Reboot = $TRUE
    }


    ### Windows Subsystem for Linux (Part 2) -- Download WSL2 Kernel Package
    Write-Host "Downloading WSL2 kernel package..." -ForegroundColor Yellow
    $WSL2Kernel = 'https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi'
    $WSL2Output = "$env:TEMP\WSL2_Update.msi"
    [System.Net.WebClient]::new().DownloadFile($WSL2Kernel, $WSL2Output)
    Write-Host "Done." -ForegroundColor Green


    ### Windows Subsystem for Linux (Part 3) -- Install WSL2 Kernel Package
    
    # Simple script added to RunOnce key to install/enable WSL2 after reboot.
    if ($Reboot) {

        Write-Host "Creating registry entry to finish WSL2 installation after reboot..." -ForegroundColor Yellow

        # Note: The RunOnce registry key has a value limit of 260 characters; exceeding this limit will cause the Key to not run.
        $Command = @(

            "msiexec /i `$env:TEMP\WSL2_Update.msi /passive;"
            "Write-Host 'Press any key to continue WSL2 installation.' -F y;"
            "`$NULL = `$Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');"
            "rm `$env:TEMP -R -Fo;"
            "wsl --set-default-version 2;"
            "Write-Host 'Done.' -F y; Sleep 5"

        ) -join ''

        Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -Name 'WSL2 Setup' -Value "powershell `"$Command`""
        Write-Host "Done." -ForegroundColor Green
        Start-Sleep -Seconds 1
    }

    # Install WSL2 Kernel without rebooting
    else {
        Write-Host "Installing the WSL2 kernel package..." -ForegroundColor Yellow
        msiexec /i $env:TEMP\WSL2_Update.msi /passive
        Start-Sleep -Seconds 3
        Remove-Item $WSL2Output -Force
        Write-Host "Done." -ForegroundColor Green

        Write-Host "Setting default version to WSL2..." -ForegroundColor Yellow
        wsl --set-default-version 2
        Write-Host "Done." -ForegroundColor Green
    }
}
function Get-UserInput ($Question) {

    $Underline = '─' * $Question.Length
    Write-Host "`n$Question" -ForegroundColor Yellow
    Write-Host "$Underline"

    Write-Host '['   -NoNewLine
    Write-Host 'yes' -NoNewLine -ForegroundColor Green
    Write-Host '/'   -NoNewLine
    write-host 'no'  -NoNewLine -ForegroundColor Red
    Write-Host ']: ' -NoNewLine

    $Answer = Read-Host
    if (($Answer -eq 'y') -or ($Answer -eq 'yes')) { $Boolean = $TRUE }
    else { $Boolean = $FALSE }

    return $Boolean
}


# Prompt installation options
$ToolBool = Get-UserInput -Question "Install 'Chocolatey' (and other common tools)?"
$WSL2Bool = Get-UserInput -Question "Install 'Windows Subsystem for Linux' (WSL2)?"


#Create a "Drive" to access the HKCR (HKEY_CLASSES_ROOT)
Write-Host "`n──────────────────────────────────────────────────────────────────────────────"
Write-Host "Creating PSDrive 'HKCR' (HKEY_CLASSES_ROOT).`n(This is necessary for the removal and modification of specific registry keys)"  -ForegroundColor Magenta
Write-Host "──────────────────────────────────────────────────────────────────────────────"
New-PSDrive HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
Start-Sleep 1


# Remove Bloatware
Write-Host "`n─────────────────────────────"
Write-Host "Removing Windows 10 Bloatware" -ForegroundColor Magenta
Write-Host "─────────────────────────────"
Remove-WindowsBloat
Start-Sleep 1


# Improve User Privacy
Write-Host "`n──────────────────────"
Write-Host "Hardening User Privacy" -ForegroundColor Magenta
Write-Host "──────────────────────"
Protect-Privacy
Start-Sleep 1


# Beautify, Repair, and Speed Up User Experience
Write-Host "`n─────────────────────────"
Write-Host "Enhancing User Experience" -ForegroundColor Magenta
Write-Host "─────────────────────────"
Enhance-UserExperience
Start-Sleep 1


# Install Commonly Downloaded Utilities; Update Existing Features
Write-Host "`n───────────────────────────"
Write-Host "Updating & Installing Tools" -ForegroundColor Magenta
Write-Host "───────────────────────────"
Get-TheBasics
Start-Sleep 1


# Install WSL2
if ($WSL2Bool) {
    Write-Host "`n──────────────────────────────────────"
    Write-Host "Installing Windows Subsystem for Linux" -ForegroundColor Magenta
    Write-Host "──────────────────────────────────────"
    Install-WSL2
    Start-Sleep 1
}


# Unload the Created "Drive" from the First Step
Write-Host "`n───────────────────────"
Write-Host "Removing PSDrive 'HKCR'" -ForegroundColor Magenta
Write-Host "───────────────────────"
Remove-PSDrive HKCR
Write-Host "Done." -ForegroundColor Green
Start-Sleep 1


# Remove Internet Explorer and/or Reboot System
if ((Get-WindowsOptionalFeature -Online -FeatureName NetFx3).State -eq 'Enabled') {
    Write-Host "`n───────────────────────"
    Write-Host "Removing IE & Rebooting" -ForegroundColor Magenta
    Write-Host "───────────────────────"
    Disable-WindowsOptionalFeature -FeatureName Internet-Explorer-Optional-amd64 -Online
}
else {
    Write-Host "`n─────────"
    Write-Host "Rebooting" -ForegroundColor Magenta
    Write-Host "─────────"
    $ReBool = Get-UserInput -Question 'Would you like to reboot your computer now?'
    if ($ReBool) { shutdown /r /t 5 }
}