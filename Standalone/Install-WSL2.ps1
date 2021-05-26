# Requirements: Run with elevated privileges (i.e., Administrator)

# WSL2 Installation:          https://docs.microsoft.com/en-us/windows/wsl/install-win10
# Linux Distro Installation:  https://docs.microsoft.com/en-us/windows/wsl/install-manual

# WSL2 Kernel Download:       https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi
# Ubuntu 20.04 Download:      https://aka.ms/wslubuntu2004

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

        # Restart
        Write-Host "`nRebooting." -ForegroundColor Red
        Start-Sleep -Seconds 1
        shutdown /r /t 3
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
Install-WSL2