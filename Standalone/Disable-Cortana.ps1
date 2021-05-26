# Requirements: Run with elevated privileges (i.e., Administrator)

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
Disable-Cortana