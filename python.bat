@echo off
REM Portable Puthon 2.7.6 wrapper

if "%1"=="--root-dir" (
	set "root=%2"
	for /f "tokens=1,2,* delims= " %%a in ("%*") do set "ALLARGS=%%c"
) else (
	set "root=."
	set "ALLARGS=%*"
)

if not exist %root%\.python\python.exe (
	
	set ERROR=0
	echo [-] Portable Python is not installed ==^> unzipping
	
	if not exist %root%\utils\7z.dll (
		echo [X] Missing file %root%\utils\7z.dll
		exit /B 2
	)
	
	if not exist %root%\utils\7z.exe (
		echo [X] Missing file %root%\utils\7z.exe
		exit /B 2
	)
	
	if not exist %root%\utils\python_win.zip (
		echo [X] Missing file %root%\utils\python_win.zip
		exit /B 2
	)
	
	%root%\utils\7z.exe x -o"%root%" %root%\utils\python_win.zip
	
	echo [+] Python is now installed, running it to get version:
	%root%\.python\python.exe --version
	
)

REM Python is now installed
%root%\.python\python.exe %ALLARGS%

