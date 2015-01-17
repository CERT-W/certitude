@echo off
SETLOCAL ENABLEDELAYEDEXPANSION

if "%1"=="" (
	echo Usage: getport.bat ^<outfile^>
	exit /b 1
)

set "outfile=%1"
set UID=1


del "%outfile%" 2>NUL

for /F "tokens=* delims=" %%a in ('dir /s /b C:\WINDOWS\Prefetch ^| findstr /E /C:".pf"') do (
	
	.\PrefetchParse.exe "%%a" > prefetch.tmp
	.\strings.exe /accepteula -u -q "%%a" > prefetch2.tmp
	
	
	for /F "skip=1 tokens=* delims=" %%b in ('type prefetch.tmp') do (
		set "LINE=!UID!	%%b"
	)
	
	for /F "skip=1 tokens=3 delims=	" %%b in ('type prefetch.tmp') do (
		set "FN=%%b"
	)
	
	set CNT=0
	for /F "tokens=* delims=" %%b in ('type prefetch2.tmp') do (
		if "!CNT!" == "0" (
			set "FN=%%b"
			set CNT=1
		)
	)
		
	for /F "tokens=* delims=" %%b in ('type prefetch2.tmp ^| findstr /E /C:"!FN!" ^| findstr /B "\\"') do (
		set "FFP=%%b"
	)
	
	set "LINE=!LINE!	!FFP!"	
	
	echo !LINE!>> "%outfile%"
	set /A UID+=1
) 

del prefetch*.tmp
