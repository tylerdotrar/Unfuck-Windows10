# Requirements: Run with elevated privileges (i.e., Administrator)

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
Uninstall-OneDrive