#!/usr/bin/python

import os, re, win32api, win32file, sys

def getFiles():

	ret = []
	
	drives = win32api.GetLogicalDriveStrings().split('\x00')
	drives.pop()
	
	drives = [ d for d in drives if win32file.GetDriveType(d)==win32file.DRIVE_FIXED ]
	
	for drive in drives:
		print os.popen('dir /s /b '+drive).read()
	
def main():

	getFiles()
    
if __name__=='__main__':
    main()