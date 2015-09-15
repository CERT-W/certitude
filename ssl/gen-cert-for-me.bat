@echo off

openssl genrsa -f4 -out server.pem.key
openssl req -new -key server.pem.key -out server.csr
openssl x509 -req -signkey server.pem.key -in server.csr -days 365 -out server.pem.cer
del server.csr