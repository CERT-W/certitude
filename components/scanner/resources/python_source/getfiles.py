#!/usr/bin/python

import os, re, win32api, win32file, sys

def getFiles():

	ret = []
	
    # List logical drives
	drives = win32api.GetLogicalDriveStrings().split('\x00')
	drives.pop()
	
    # Only get local dries
	drives = [ d for d in drives if win32file.GetDriveType(d)==win32file.DRIVE_FIXED ]
	
    # List files
	for drive in drives:
		print os.popen('dir /s /b '+drive).read()
	
def main():

	getFiles()

if __name__=='__main__':
    main()