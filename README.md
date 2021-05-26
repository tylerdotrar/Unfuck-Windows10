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
iex ([System.Net.WebClient].new().DownloadString('https://git.io/JspIT'))
```

![InstallSyntax](https://cdn.discordapp.com/attachments/620986290317426698/846631194303922176/unknown.png)

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
- Removes most junk from the taskbar (e.g., People, Meet Here, Taskview, Searchbar, 'Edge' and 'Microsoft Store').
- Removes live tiles and unpins all items from the Start Menu.
- Removes Bing suggestions from Search.
- Sets Windows Search to use 'Enhanced' mode instead of 'Classic'.
- Unlocks and enables the hidden 'Ultimate Performance' power plan.
- Removes the Windows Update bandwidth limitation.
- Enables 'Show File Extensions'.
- Removes Paint3D context menu options and 3D objects tab from Explorer.
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

**(OPTIONAL) Installs Windows Subsystem for Linux (WSL2)**
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
Start (Fresh Windows 10 Install)
```


![FinalResult](https://cdn.discordapp.com/attachments/620986290317426698/846634838298591232/unknown.png)
`Finish (Post-Reboot)`


![Script](https://cdn.discordapp.com/attachments/620986290317426698/846634822389596180/unknown.png)
`End of Script (Pre-Reboot)`
