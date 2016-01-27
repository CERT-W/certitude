#!/usr/bin/python

import os, re, win32api, win32file, sys, base64, hashlib

def hashfile(afile, hasher, blocksize=65536):
    buf = afile.read(blocksize)
    while len(buf) > 0:
        hasher.update(buf)
        buf = afile.read(blocksize)
    return hasher.digest()

def getFiles():

	ret = []
	
	# Authorize Strings
	os.popen('reg.exe ADD "HKCU\Software\Sysinternals\Strings" /v EulaAccepted /t REG_DWORD /d 1 /f')

    # List logical drives
	drives = win32api.GetLogicalDriveStrings().split('\x00')
	drives.pop()
	
    # Only get local dries
	drives = [ d for d in drives if win32file.GetDriveType(d)==win32file.DRIVE_FIXED ]
	
	files = ""

    # List files
	for drive in drives:
		files += os.popen('dir /s /b '+drive).read()

	files = files.split("\n")

	for tfile in files:
		if not "C:\Windows\CERTitude-active" in tfile:
			resultline = ""
			resultline = tfile + "|"
			resultline += os.popen('md5 -n "' + tfile + '"').read()
			if resultline[-1] == "|":
				resultline = resultline + "|"
			else:
				resultline = resultline[:-1] + "|"
			resultline += base64.b64encode(os.popen('strings -q "' + tfile + '"').read())
			print resultline
	
def main():

	getFiles()

if __name__=='__main__':
    main()