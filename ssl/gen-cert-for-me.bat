@echo off

set "KEY_FILE=server.pem.key"
set "CSR_FILE=server.pem.csr"
set "CER_FILE=server.pem.cer"

openssl genrsa -f4 -out "%KEY_FILE%" 4096
openssl req -new -key "%KEY_FILE%" -out "%CSR_FILE%" -sha256
openssl x509 -req -signkey "%KEY_FILE%" -in "%CSR_FILE%" -days 365 -out "%CER_FILE%" -sha256
del "%CSR_FILE%"