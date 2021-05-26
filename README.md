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

![Syntax](https://cdn.discordapp.com/attachments/620986290317426698/847198765147357184/unknown.png)

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

![FreshOS](https://cdn.discordapp.com/attachments/620986290317426698/846631197277683732/unknown.png)
```
Fresh Windows 10 Install
```


![FinalResult](https://cdn.discordapp.com/attachments/620986290317426698/846634838298591232/unknown.png)
```
Unfucked Windows 10
```


![Verbose1](https://cdn.discordapp.com/attachments/620986290317426698/847202229776941056/unknown.png)
```
(1) Example Verbosity
```


![Verbose2](https://cdn.discordapp.com/attachments/620986290317426698/847202243886579722/unknown.png)
```
(2) Example Verbosity
```
