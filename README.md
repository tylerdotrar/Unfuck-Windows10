# Unfuck-Windows10
Script meant to debloat Windows 10, enhance privacy, and improve performance &amp; the overall user experience.

## Disclaimer
First, I am **NOT** liable for any potential damage or loss of data.  Use and modify this script at your own risk.

Second, thank you to **Sycnex** for the great work on his original Windows 10 debloater project, which heavily inspired this one.
- https://github.com/Sycnex/Windows10Debloater

## Functionality

**Requirements:**
`Run with elevated privileges (i.e., Administrator)`

**One-Liner Syntax:**
`iex ((New-Object System.Net.WebClient).DownloadString('https://git.io/JspIT'))`

![InstallSyntax](https://cdn.discordapp.com/attachments/620986290317426698/846631194303922176/unknown.png)

**Uninstalls bloat**
- Including all the Windows 10 sponsored bloat (games and sponsored shit).
- Includes Windows 10 junk no one uses -- like the Xbox apps, Groove Music, Get Help, News, Feedback, etc.
- Even more integrated stuff like Cortana and OneDrive.

**Improves privacy**
- Disables Feedback Experience, data collection, suggested content, location tracking, etc.
- Disables specific scheduled task and services, including diagnostics tracking.

**Beautifies user experience**
- Removes most junk from the taskbar (People, Meet Here, Taskview, Searchbox).
- Enables dark theme.
- Removes live tiles from start menu.
- Removes Paint3D stuff from context menu and 3D objects tab from Explorer.
- Removes 'Microsoft Edge' and 'Microsoft Store' from Taskbar

**QOL improvements and update existing utiilities**
- Enables .NET 3.5 package.
- Enables 'Show File Extensions'.
- Updates 'Get-Help' (assuming this is a fresh install of Win10).
- Removes Bing from Search.
- Removes Windows Update bandwidth limitation.
- Unlocks and enables the hidden 'Ultimate Performance' power plan.
- Cleans up Temp directory.
- Verifies / fixes OS integrity. 
- Uninstalls Internet Exploer (since Edge has an "Open in IE mode" feature).

**(OPTIONAL / PROMPTED) Installs some common tools**
- Chocolatey
- git
- vim (`C:\.Tools`)
- Notepad++ (`C:\.Tools`)
- 7-Zip (`C:\.Tools`)
- PowerShell Core
- Windows Terminal
- Windows Subsystem for Linux (WSL2)

## Gallery

![FreshOS](https://cdn.discordapp.com/attachments/620986290317426698/846631197277683732/unknown.png)
`Start (Fresh Windows 10 Install)`


![FinalResult](https://cdn.discordapp.com/attachments/620986290317426698/846634838298591232/unknown.png)
`Finish (Post-Reboot)`


![Script](https://cdn.discordapp.com/attachments/620986290317426698/846634822389596180/unknown.png)
`End of Script (Pre-Reboot)`
