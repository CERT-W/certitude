@echo off
SETLOCAL ENABLEDELAYEDEXPANSION

if "%1"=="" (
	echo Usage: getarp.bat ^<outfile^>
	exit /b 1
)

set "outfile=%1"

del "%outfile%" 2>NUL

set ACTIVE_INTERFACE=NULL
set AID=1

for /F "delims=" %%v in ('arp -a ^| findstr /V "ress" ^') do (
	
	set "ligne=%%v"
	if "!ligne:~0,9!"=="Interface" (
	
		for /F "tokens=2 delims= " %%a in ('echo %%v') do (
			set "ACTIVE_INTERFACE=%%a"
		)
	
	) else (
		if "!ACTIVE_INTERFACE!"=="NULL" (
			exit /b 1
		)
		
		for /F "tokens=1,2,3 delims= " %%a in ('echo %%v') do (
			set ARP_IPV4=%%a
			set ARP_PHYSICAL=%%b
			set ARP_CACHETYPE_TMP=%%c
			
			if "!ARP_CACHETYPE_TMP:~0,4!"=="dyna" (
				set ARP_CACHETYPE=dynamic
			) else (
				set ARP_CACHETYPE=static
			)
			
			REM : 	INTERFACE	IPV4	PHYSICAL	CACHETYPE
			
			echo !AID!	!ACTIVE_INTERFACE!	!ARP_IPV4!	!ARP_PHYSICAL!	!ARP_CACHETYPE!>>"%outfile%"
			set /A AID+=1
		)
	)
	
)