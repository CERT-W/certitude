REM CERTitude: the seeker of IOC
REM Copyright (c) 2016 CERT-W

REM Contact: cert@wavestone.com
REM Contributors: @iansus, @nervous, @fschwebel

REM CERTitude is under licence GPL-2.0:
REM This program is free software; you can redistribute it and/or
REM modify it under the terms of the GNU General Public License
REM as published by the Free Software Foundation; either version 2
REM of the License, or (at your option) any later version.

REM This program is distributed in the hope that it will be useful,
REM but WITHOUT ANY WARRANTY; without even the implied warranty of
REM MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
REM GNU General Public License for more details.

REM You should have received a copy of the GNU General Public License
REM along with this program; if not, write to the Free Software
REM Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

@echo off

set "KEY_FILE=server.pem.key"
set "CSR_FILE=server.pem.csr"
set "CER_FILE=server.pem.cer"

openssl genrsa -f4 -out "%KEY_FILE%" 4096
openssl req -new -key "%KEY_FILE%" -out "%CSR_FILE%" -sha256
openssl x509 -req -signkey "%KEY_FILE%" -in "%CSR_FILE%" -days 365 -out "%CER_FILE%" -sha256
del "%CSR_FILE%"