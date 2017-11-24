@echo off

if -%1-==-- (
	echo Usage: getresults.bat ^<identifier^>
	exit /b 1
)

REM Groups results from SQL queries
tar.exe cf %1.tar %1.*.res

REM Compresses it
gzip.exe %1.tar

REM Deletes the remaining files
del %1.*.res %1.*.sql