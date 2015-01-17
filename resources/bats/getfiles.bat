@echo off
SETLOCAL ENABLEDELAYEDEXPANSION

if "%1"=="" (
	echo Usage: getfiles.bat ^<outfile^>
	exit /b 1
)

set "outfile=%1"

del "%outfile%.tmp" 2>NUL

REM List volumes
for /F "delims=" %%v in ('echo list volume ^| diskpart ^| findstr Partition') do (
	
	for /F "tokens=1,2,3 delims= " %%a in ('echo %%v') do (
		dir /s /b /A:-D "%%c:\" >> "%outfile%.tmp"
	)
	
)

REM List target volume files
(
	set FID=1
	for /F "delims=" %%a in (%outfile%.tmp) do (
		REM		FID		Path	FullPath	Name	Extension
		echo !FID!	%%a	0	0	0
		set /A FID+=1
	)
)> "%outfile%"

del "%outfile%.tmp"