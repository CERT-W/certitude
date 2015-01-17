@echo off
SETLOCAL ENABLEDELAYEDEXPANSION

if "%1"=="" (
	echo Usage: getport.bat ^<outfile^>
	exit /b 1
)

set "outfile=%1"
set UID=1

del "%outfile%" 2>NUL

for /F "skip=4 tokens=1,2,3,4,5 delims= " %%a in ('netstat -ano') do (
	
	set "Protocol=%%a"
	
	set "tmp=%%b"
	if "!tmp:~0,1!" == "[" (
	
		set "tmp2=!tmp:~1!"
		
		for /F "tokens=1,2 delims=]" %%t in ('echo !tmp2!') do (
			
			set "LocalIP=%%t"
			set "LocalPort=%%u"
			set "LocalPort=!LocalPort:~1!"
			
		)
	
	) else (
	
		for /F "tokens=1,2 delims=:" %%t in ('echo %%b') do (
			
			set "LocalIP=%%t"
			set "LocalPort=%%u"
			
		)
	)
	
	
	
	set "tmp=%%c"
	if "!tmp:~0,1!" == "[" (
	
		set "tmp2=!tmp:~1!"
		
		for /F "tokens=1,2 delims=]" %%t in ('echo !tmp2!') do (
			
			set "RemoteIP=%%t"
			set "RemotePort=%%u"
			set "RemotePort=!RemotePort:~1!"
			
		)
	
	) else (
	
		for /F "tokens=1,2 delims=:" %%t in ('echo %%c') do (
			
			set "RemoteIP=%%t"
			set "RemotePort=%%u"
			
		)
	)
	
	if "!Protocol!" == "UDP" ( 
		set "State=UNKNOWN"
		set "PID=%%d"
	) else (
		set "State=%%d"
		set "PID=%%e"
	)
	
	echo !UID!	!Protocol!	!LocalIP!	!LocalPort!	!RemoteIP!	!RemotePort!	!State!	!PID!>> "%outfile%"
	set /A UID+=1
) 