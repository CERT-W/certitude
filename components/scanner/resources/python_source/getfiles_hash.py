#!/usr/bin/python

import os, re, hashlib, win32api, win32file, sys

try:
    config = open('hash.cfg', 'r')
except Exception, e:
    sys.stderr.write('No hash.cfg file found !')
    sys.stderr.flush()
    sys.exit(0)
    
hashConfig = config.read().replace('\r\n', '\n').split('\n')
config.close()

MAX_HASH_SIZE = int(hashConfig[0], 0)
EXT_HASH_FILTER = hashConfig[1].split(' ') if len(hashConfig[1])>0 else []

EXT_HASH_FILTER = [e.lower() for e in EXT_HASH_FILTER]
HASH_EXT_HASH_FILTER = (len(EXT_HASH_FILTER)>0)

def hashRec(dir):

    for (dirpath, dirnames, filenames) in os.walk(dir):
        fnames = [os.path.join(dirpath, e) for e in filenames]
        
        for file in fnames:
            if os.path.getsize(file) > MAX_HASH_SIZE:
                continue
                
            if HASH_EXT_HASH_FILTER:
                nameIdx = file.rfind('\\')
                if nameIdx != -1:
                    name = file[nameIdx:]
                    extIdx = name.rfind('.')
                    if extIdx != -1:
                        ext = name[extIdx:]
                        if ext not in EXT_HASH_FILTER:
                            continue
                    else:
                        continue
                else:
                    continue
            
            md5 = '0'*32
            sha1 = '0'*40
            sha256 = '0'*64
            
            try:
                f = open(file, 'rb')
            
                md5 = hashlib.md5(f.read()).hexdigest()
                f.seek(0)
                
                sha1 = hashlib.sha1(f.read()).hexdigest()
                f.seek(0)
                
                sha256 = hashlib.sha256(f.read()).hexdigest()
                f.seek(0)
            except Exception, e:
                pass
                
            try:
                f.close()
            except Exception, e:
                pass
                
            print '%s\t%s\t%s\t%s' % (file, md5, sha1, sha256)

def getFilesHash():

	ret = []
	
    # List logical drives
	drives = win32api.GetLogicalDriveStrings().split('\x00')
	drives.pop()
	
    # Only get local dries
	drives = [ d for d in drives if win32file.GetDriveType(d)==win32file.DRIVE_FIXED ]
	
    # List files
	for drive in drives:
		hashRec(drive)
	
def main():

	getFilesHash()

if __name__=='__main__':
    #main()
    hashRec('C:\\')