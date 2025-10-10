@echo off
REM Desktop Configuration Deployment Script
REM Run this as Administrator to install the desktop configuration system

echo =============================================
echo Desktop Configuration Deployment
echo =============================================
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: This script requires Administrator privileges
    echo Right-click and select "Run as administrator"
    pause
    exit /b 1
)

REM Set script paths
set SCRIPT_DIR=C:\Scripts
set SCRIPT_NAME=DesktopConfig.ps1
set IMAGES_DIR=C:\Scripts\Images
set SCRIPT_PATH=%SCRIPT_DIR%\%SCRIPT_NAME%
set TASK_XML=%SCRIPT_DIR%\DesktopConfigTask.xml
set CURRENT_DIR=%~dp0

echo Creating script directory...
if not exist "%SCRIPT_DIR%" mkdir "%SCRIPT_DIR%"
if not exist "%IMAGES_DIR%" mkdir "%IMAGES_DIR%"
if %errorLevel% neq 0 (
    echo ERROR: Failed to create directory %SCRIPT_DIR%
    pause
    exit /b 1
)

echo Copying PowerShell script...
copy /Y "%CURRENT_DIR%%SCRIPT_NAME%" "%SCRIPT_PATH%" >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: Failed to copy PowerShell script from "%CURRENT_DIR%%SCRIPT_NAME%"
    echo Check if DesktopConfig.ps1 exists in the current directory
    pause
    exit /b 1
)


echo Copying Task Scheduler XML...
copy /Y "%CURRENT_DIR%DesktopConfigTask.xml" "%TASK_XML%" >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: Failed to copy Task XML from "%CURRENT_DIR%DesktopConfigTask.xml"
    echo Check if DesktopConfigTask.xml exists in the current directory
    pause
    exit /b 1
)

echo Copying images to local Scripts folder...
copy /Y "%CURRENT_DIR%wallpaper.jpg" "%IMAGES_DIR%\wallpaper.jpg" >nul 2>&1
if %errorLevel% neq 0 (
    echo WARNING: wallpaper.jpg not found in current directory
)

copy /Y "%CURRENT_DIR%lockscreen.jpg" "%IMAGES_DIR%\lockscreen.jpg" >nul 2>&1
if %errorLevel% neq 0 (
    echo WARNING: lockscreen.jpg not found in current directory
)

copy /Y "%CURRENT_DIR%screensaver.jpg" "%IMAGES_DIR%" >nul 2>&1
if %errorLevel% neq 0 (
    echo WARNING: screensaver.jpg not found in current directory
)

echo.
echo =============================================
echo ATTEMPTING INSTALLATION METHOD 1: PowerShell
echo =============================================
echo Installing scheduled task using PowerShell method...

REM Run PowerShell and capture both output and error code
powershell.exe -ExecutionPolicy Bypass -Command "& '%SCRIPT_PATH%' -Install"
set PS_ERROR=%errorLevel%

echo.
echo PowerShell method completed with exit code: %PS_ERROR%

if %PS_ERROR% equ 1 (
    echo ✅ SUCCESS: PowerShell installation completed successfully
    goto VERIFY_INSTALLATION
) else (
    echo  FAILED: PowerShell installation failed with exit code: %PS_ERROR%
    echo.
    echo Common PowerShell installation failures:
    echo - Script syntax errors or parsing issues
    echo - Insufficient administrator privileges  
    echo - PowerShell execution policy restrictions
    echo - Task scheduler service not running
    echo.
    echo =============================================
    echo ATTEMPTING INSTALLATION METHOD 2: XML Import
    echo =============================================
    echo Trying XML fallback method...
    
    REM First check if XML file exists and is valid
    if not exist "%TASK_XML%" (
        echo ERROR: XML file not found at %TASK_XML%
        goto INSTALLATION_FAILED
    )
    
    echo Validating XML file structure...
    powershell.exe -Command "try { [xml]$xml = Get-Content '%TASK_XML%'; Write-Host '✅ XML file is valid and well-formed' } catch { Write-Host '❌ ERROR: XML file is malformed -' $_.Exception.Message; exit 1 }"
    set XML_VALID=%errorLevel%
    
    if %XML_VALID% neq 0 (
        echo ERROR: XML file validation failed - file may be corrupted
        goto INSTALLATION_FAILED
    )
    
    echo Importing task from XML using schtasks command...
    schtasks /create /xml "%TASK_XML%" /tn "DesktopConfiguration" /f >temp_output.txt 2>temp_error.txt
    set XML_ERROR=%errorLevel%
    
    echo XML import completed with exit code: %XML_ERROR%
    
    if %XML_ERROR% equ 0 (
        echo  SUCCESS: XML installation completed successfully
        if exist temp_output.txt del temp_output.txt
        if exist temp_error.txt del temp_error.txt
        goto VERIFY_INSTALLATION
    ) else (
        echo  FAILED: XML installation failed with exit code: %XML_ERROR%
        echo.
        echo DETAILED ERROR OUTPUT:
        if exist temp_error.txt (
            echo --- Standard Error Output ---
            type temp_error.txt
            echo --- End Error Output ---
            del temp_error.txt
        )
        if exist temp_output.txt (
            echo --- Standard Output ---
            type temp_output.txt
            echo --- End Output ---
            del temp_output.txt
        )
        echo.
        echo Common XML import errors:
        echo - ERROR 0x80041318: Task already exists and /f flag not working
        echo - ERROR 0x80070005: Access denied - not running as administrator
        echo - ERROR 0x8004131F: Task XML malformed or contains invalid data
        echo - ERROR 0x80041309: Task contains unsupported features for this OS
        goto INSTALLATION_FAILED
    )
)

:VERIFY_INSTALLATION
echo.
echo =============================================
echo VERIFYING INSTALLATION
echo =============================================
echo Checking if scheduled task was created...

schtasks /query /tn "DesktopConfiguration" >nul 2>&1
if %errorLevel% equ 0 (
    echo  VERIFICATION SUCCESS: Scheduled task "DesktopConfiguration" found
    echo.
    echo Task Details:
    schtasks /query /tn "DesktopConfiguration" /v /fo list | findstr /i "TaskName Next State Author"
    echo.
    echo Testing PowerShell script execution...
    powershell.exe -ExecutionPolicy Bypass -Command "& '%SCRIPT_PATH%' -Configure" >nul 2>&1
    if %errorLevel% equ 0 (
        echo  SCRIPT TEST: PowerShell script executes without syntax errors
    ) else (
        echo   WARNING: PowerShell script has execution issues - check syntax
    )
) else (
    echo  VERIFICATION FAILED: Scheduled task was not created
    echo This indicates both PowerShell and XML methods failed
    goto INSTALLATION_FAILED
)

echo.
echo =============================================
echo INSTALLATION COMPLETED SUCCESSFULLY
echo =============================================
echo.
echo The desktop configuration will now run automatically
echo for all users at logon. Settings will be applied within
echo 30 seconds of login.
echo.
echo NEXT STEPS:
echo 1. Test by logging off and back on with a standard user account
echo 2. Check log files at: %%TEMP%%\DesktopConfig.log
echo 3. Verify desktop changes are applied
echo.
echo TROUBLESHOOTING:
echo - View task in Task Scheduler: taskschd.msc
echo - Manual test: %SCRIPT_PATH% -Configure
echo - Check task history for execution details
echo.
goto END

:INSTALLATION_FAILED
echo.
echo =============================================
echo INSTALLATION FAILED
echo =============================================
echo.
echo TROUBLESHOOTING STEPS:
echo.
echo 1. CHECK PREREQUISITES:
echo    - Running as Administrator? %USERNAME%
echo    - PowerShell 5.1+ installed? Run: powershell $PSVersionTable
echo    - Execution policy allows scripts? Run: Get-ExecutionPolicy
echo.
echo 2. CHECK FILES:
echo    - DesktopConfig.ps1 exists in current directory?
echo    - DesktopConfigTask.xml exists in current directory?
echo    - Files copied to C:\Scripts successfully?
echo.
echo 3. CHECK PERMISSIONS:
echo    - Can write to C:\Scripts directory?
echo    - Can create scheduled tasks?
echo    - Antivirus blocking PowerShell execution?
echo.
echo 4. MANUAL DIAGNOSTICS:
echo    - Test PowerShell syntax: powershell -File "%SCRIPT_PATH%"
echo    - Test XML import: schtasks /create /xml "%TASK_XML%" /tn "TestTask"
echo    - Check Windows Event Logs for errors
echo.
echo 5. ALTERNATIVE INSTALLATION:
echo    - Try Install.ps1 instead of Deploy.bat
echo    - Run: powershell -ExecutionPolicy Bypass .\Install.ps1
echo.
exit /b 1

:END
pause