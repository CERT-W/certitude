@echo off

if -%1-==-- (
	echo Usage: rmtar.bat ^<tarfile^>
	exit /b 1
)

REM Lists contents of TAR target
for /f "delims=" %%a in ('tar tf %1') do (
	del "%%a"
	REM Deletes target file
)

REM Deletes the TAR file
del %1