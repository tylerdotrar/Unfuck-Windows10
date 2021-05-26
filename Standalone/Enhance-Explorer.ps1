# Requirements: Run with elevated privileges (i.e., Administrator)

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
Enhance-Explorer