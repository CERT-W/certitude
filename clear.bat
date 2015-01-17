@echo off

del /Q db\*.db 2> NUL 1>&2
del /Q static\data\*.csv 2> NUL 1>&2
del /Q results\*.* 2> NUL 1>&2
del /Q results\processed\*.* 2> NUL 1>&2