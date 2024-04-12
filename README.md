# Unfuck-Windows10
Script meant to debloat Windows 10, enhance privacy, and improve performance &amp; the overall user experience.

## Disclaimer
First, I am **NOT** liable for any potential damage or loss of data.  Use and modify this script at your own risk.

Second, thank you to `Sycnex` for the great work on his original [Windows 10 Debloater](https://github.com/Sycnex/Windows10Debloater) project, which heavily inspired this one.

## TL;DR

**Requirements:**
```
Run with elevated privileges (i.e., Administrator)
```

**One-Liner Syntax:**
```powershell
iex ([System.Net.WebClient]::new().DownloadString('https://git.io/JspIT'))
```

![Syntax](https://github.com/tylerdotrar/Unfuck-Windows10/assets/69973771/932c0a0d-7a6a-4a26-9151-fb54400caf30)


## Functionality

**Uninstalls Windows 10 Bloat**
```
- Windows 10 sponsored bloat games and sponsored apps (e.g., CandyCrush).
- Windows 10 junk no one uses (e.g., Xbox apps, Groove Music, Mixed Reality Portal, Feedback Hub).
- Even more integrated and annoying stuff like 'OneDrive'.
```

**Improves User Privacy**
```
- Disables Feedback Experience, anonymous data collection, suggested content, location tracking, etc.
- Disables specific scheduled tasks and services, including diagnostics tracking and CloudStore.
- Disables Cortana and included Cortana data collection.
- Disables background application access.
```

**Enhances Overall User Experience**
```
- Removes most junk from the taskbar (e.g., People, Meet Here, Taskview, Searchbar).
- Unpin 'Microsoft Edge' and 'Microsoft Store' from Taskbar.
- Removes live tiles and unpins all items from the Start Menu.
- Removes Bing suggestions from Search.
- Sets Windows Search to use 'Enhanced' mode instead of 'Classic'.
- Unlocks and enables the hidden 'Ultimate Performance' power plan.
- Removes the Windows Update bandwidth limitation.
- Enables 'Show File Extensions'.
- Removes Paint3D context menu options.
- Remove 3D Objects tab from Explorer submenu.
- Enables dark theme.
- Cleans up Temp directory.
- Verifies / fixes OS integrity.
- Uninstalls Internet Explorer (since Edge has an "Open in IE mode" feature).
```

**(OPTIONAL) Downloads & Updates Useful Utiilities**
```
- Enables .NET Framework 3.5 package.
- Updates the 'Get-Help' cmdlet (assuming you're using a fresh install of Windows 10).
- Downloads Chocolatey
  --> git
  --> PowerShell Core
  --> Windows Terminal
  --> Notepad++  (C:\.Tools\<name>)
  --> 7-Zip      (C:\.Tools\<name>)
  --> vim        (C:\.Tools\<name>)
```

**(OPTIONAL) Installs WSL2**
```
- Enables the 'Microsoft-Windows-Subsystem-Linux' dependency.
- Enables the 'VirtualMachinePlatform' dependency.
- Downloads the WSL2 kernel package.
- Installs the WSL2 package and sets WSL default version to 2.
    OR 
- Creates a small script in the 'RunOnce' registry key to finish install post-reboot.
```

## Gallery

- `Fresh install of Windows 10`

![FreshOS](https://github.com/tylerdotrar/Unfuck-Windows10/assets/69973771/9e386ac2-0db2-4ec7-b570-f02b0d47d1d2)

- `Example Verbosity`

![Verbosity](https://github.com/tylerdotrar/Unfuck-Windows10/assets/69973771/f4cd6790-440f-4385-8cbc-ae818221f34b)


- `Unfucked Windows 10`

![FinalResult](https://github.com/tylerdotrar/Unfuck-Windows10/assets/69973771/90b2020d-7e6d-49c8-893c-d0cbbd9b9aff)

