#!/usr/bin/env python
# -*- coding: UTF-8 -*-
'''
    CERTitude: the seeker of IOC
    Copyright (c) 2016 CERT-W
    
    Contact: cert@wavestone.com
    Contributors: @iansus, @nervous, @fschwebel
    
    CERTitude is under licence GPL-2.0:
    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
'''

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
            try:
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
                
                f = open(file, 'rb')
            
                md5 = hashlib.md5(f.read()).hexdigest()
                f.seek(0)
                
                sha1 = hashlib.sha1(f.read()).hexdigest()
                f.seek(0)
                
                sha256 = hashlib.sha256(f.read()).hexdigest()
                f.seek(0)
                f.close()
                    
                print '%s\t%s\t%s\t%s' % (file, md5, sha1, sha256)
            except Exception, e:
                pass


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