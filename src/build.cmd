@echo off
rem Builds SysmonChecker-<version>.exe (dotnet SDK, .NET Framework 4.8 target), copies it to the application folder and signs it.
rem The version comes from <Version> in SysmonChecker.csproj; older SysmonChecker*.exe copies in the application folder are removed.
rem Signing uses the certificate "CN=SysmonChecker Code Signing" from Cert:\CurrentUser\My (sign.ps1); skipped if it is not present.
setlocal
cd /d "%~dp0"
set VER=
for /f "usebackq delims=" %%v in (`powershell -NoProfile -Command "(Select-String -LiteralPath SysmonChecker.csproj -Pattern '<Version>([\d.]+)</Version>').Matches[0].Groups[1].Value"`) do set VER=%%v
if "%VER%"=="" (echo Version not found in SysmonChecker.csproj & exit /b 1)
set EXE=SysmonChecker-%VER%.exe
dotnet build SysmonChecker.csproj -c Release -nologo -v q
if errorlevel 1 (echo Build FAILED & exit /b 1)
copy /y bin\Release\SysmonChecker.exe "..\%EXE%" >nul
if errorlevel 1 (echo Copy FAILED - is %EXE% running? & exit /b 1)
copy /y bin\Release\SysmonChecker.exe.config "..\%EXE%.config" >nul
rem remove the exe of other versions (and the unversioned name used before 1.2.0) so only one copy is left
for %%f in ("..\SysmonChecker.exe" "..\SysmonChecker-*.exe") do if exist "%%~f" if /i not "%%~nxf"=="%EXE%" (
    del /q "%%~f" 2>nul
    if exist "%%~f" (echo Warning: %%~nxf could not be removed - is it running?) else (del /q "%%~f.config" 2>nul & echo Removed old %%~nxf)
)
echo Build OK: %EXE%
powershell -NoProfile -ExecutionPolicy Bypass -File sign.ps1 -Version %VER%
