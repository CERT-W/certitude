@echo off

PsList.exe | .\sort.exe -n | .\uniq.exe > "%1"