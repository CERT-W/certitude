@echo off
SETLOCAL ENABLEDELAYEDEXPANSION

if "%2"=="" (
	echo Usage: launch.bat ^<program^> ^[action^] ^<outfile^>
	exit /b 1
)

if "%1"=="collector" (
    %1 %2 > "%3" 2> "%3".err
) else (
    %1 > "%2" 2> "%2".err
)