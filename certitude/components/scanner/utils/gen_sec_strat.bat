@echo off

REM CONSTANTS
set OUT_ANALYST=analyst_rules.ipsec
set OUT_TARGETS=targets_rules.ipsec

echo.
echo 		Generateur de strategies de securite IPSec pour CERTitude
echo.
echo 	Ce generateur utilise le magasin local de strategies IPSec afin 
echo 	de creer les strategies utilisees par l'analyste et les cibles.
echo 	Le comportement normal de cet outil est de sauvegarder puis
echo 	restorer les strategies preexistantes. Cependendant, aucune 
echo 	garantie ne saurait etre apportee quant a leur integrite.
echo.


:while_00
set /P "test=	Souhaitez vous continuer ? (O/N) "

if "%test%"=="O" ( goto while_00_exit )
if "%test%"=="o" ( goto while_00_exit )
if "%test%"=="N" ( goto while_00_exit )
if "%test%"=="n" ( goto while_00_exit )

goto while_00
:while_00_exit

if "%test%"=="N" ( set test=false)
if "%test%"=="n" ( set test=false)

if "%test%"=="false" ( exit /B 1 )

echo.
echo.
echo -------------------------------------------------------
echo.
set /P IP_ANALYST="> Adresse IP de l'analyste : "

:while_01
echo.
echo ^> Est-il possible de definir le reseau cible
set /P "test=	par une adresse et un masque de reseau ? (O/N) "

if "%test%"=="O" ( goto while_01_exit )
if "%test%"=="o" ( goto while_01_exit )
if "%test%"=="N" ( goto while_01_exit )
if "%test%"=="n" ( goto while_01_exit )

goto while_01
:while_01_exit

if "%test%"=="O" ( set test=true)
if "%test%"=="o" ( set test=true)

if "%test%"=="true" (
	echo.
	set /P IP_SUBNET="> Adresse du reseau cible : "
	echo.
	set /P MASK_SUBNET="> Masque du reseau cible : "
	set IP_CIBLES=%IP_SUBNET%/%MASK_SUBNET%
) else (
	set IP_CIBLES=*
)

echo.
set /P PSK="> Cle pre-partagee : "

echo.
echo [-] Generation des strategies
echo [-] Sauvegarde des strategies existantes
ipsec export REG oldrules.ipsec > NUL

echo [-] Suppression des strategies existantes
for /f "tokens=1 delims=" %%a in ('reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\ ^| findstr ipsecPolicy') do (

	for /f "tokens=3 delims=	" %%b in ('reg query %%a ^| findstr ipsecName') do (
		echo 	^> %%b
		ipsec -w REG -p "%%b" -o > NUL
	)
)

echo [-] Creation d'une strategie pour l'analyste
ipsec -f "0+%IP_CIBLES%:445:TCP" "0+%IP_CIBLES%:139:TCP" -n "esp[3des,sha] 3600S/100000K" -a p:"%PSK%" -1s 3DES-SHA-2  -r "CERTitude-analyst-rule" -w REG -p CERTitude-analyst > NUL

echo [-] Exportation de la strategie ^> %OUT_ANALYST%
ipsec export REG %OUT_ANALYST% > NUL

echo [-] Suppresion de la strategie
ipsec -w REG -p CERTitude-analyst -o > NUL

echo [-] Creation d'une strategie pour les cibles
ipsec -f "%IP_ANALYST%+0:445:TCP" "%IP_ANALYST%+0:139:TCP" -n "esp[3des,sha] 3600S/100000K" -a p:"%PSK%" -1s 3DES-SHA-2  -r "CERTitude-targets-rule" -w REG -p CERTitude-targets > NUL

echo [-] Exportation de la strategie ^> %OUT_TARGETS%
ipsec export REG %OUT_TARGETS% > NUL

echo [-] Suppresion de la strategie
ipsec -w REG -p CERTitude-targets -o > NUL

echo [-] Restauration des strategies d'origine
ipsec import REG oldrules.ipsec > NUL

del oldrules.ipsec

pause
exit /B 0