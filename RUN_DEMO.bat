@echo off
setlocal
cd /d "%~dp0"

title SentinelLite - Classroom Demonstration
color 0B

set "AUTO_MODE=0"
if /I "%~1"=="--auto" set "AUTO_MODE=1"

if defined SENTINELLITE_PYTHON (
    set PYTHON_CMD="%SENTINELLITE_PYTHON%"
) else (
    where py >nul 2>nul
    if %errorlevel%==0 (
        set "PYTHON_CMD=py -3"
    ) else (
        where python >nul 2>nul
        if %errorlevel%==0 (
            set "PYTHON_CMD=python"
        ) else (
            color 0C
            echo Python was not found.
            echo Install Python 3.10 or newer, then run this file again.
            if not "%AUTO_MODE%"=="1" pause
            exit /b 1
        )
    )
)

cls
echo ================================================================
echo                      SENTINELLITE LIVE DEMO
echo ================================================================
echo.
echo SentinelLite performs static file-risk analysis.
echo It reads files without executing, modifying, or uploading them.
echo.
call :wait_for_presenter "Press any key to run the nine verification tests..."

echo.
echo [1/3] VERIFYING THE IMPLEMENTATION
echo ----------------------------------------------------------------
%PYTHON_CMD% -m unittest -v
if errorlevel 1 goto :failed
echo.
echo RESULT: All nine tests passed.
call :wait_for_presenter "Press any key to scan a normal classroom note..."

cls
echo ================================================================
echo [2/3] SAFE-LOOKING SAMPLE
echo ================================================================
echo Expected result: LOW, with no detected indicators.
echo.
%PYTHON_CMD% scanner.py samples\notes.txt
if errorlevel 1 goto :failed
echo.
echo This establishes a normal baseline for comparison.
call :wait_for_presenter "Press any key to scan the indicator demonstration..."

cls
echo ================================================================
echo [3/3] EXPLAINABLE HIGH-RISK RESULT
echo ================================================================
echo This is harmless text containing deliberately suspicious terms.
echo Expected result: HIGH, with four visible marker groups.
echo.
%PYTHON_CMD% scanner.py samples\indicator_demo.txt
if errorlevel 1 goto :failed
echo.
echo KEY LESSON:
echo A HIGH result means REVIEW REQUIRED - it does not prove malware.
echo The harmless sample demonstrates a realistic false positive.
echo.
echo ================================================================
echo                       DEMONSTRATION COMPLETE
echo ================================================================
echo.
call :wait_for_presenter "Press any key to close..."
exit /b 0

:wait_for_presenter
if "%AUTO_MODE%"=="1" exit /b 0
echo.
echo %~1
pause >nul
exit /b 0

:failed
color 0C
echo.
echo The demonstration stopped because a command failed.
echo Check that this file is inside the SentinelLite project folder.
if not "%AUTO_MODE%"=="1" pause
exit /b 1
