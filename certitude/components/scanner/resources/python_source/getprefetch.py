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

import os, re, struct, string

# Strings in python
def strings(content, min=4):
	
	result = ""
	ret = []
	for i in range(0, len(content)):
		c = content[i]
		if c in string.printable:
			result += c
			continue
		if len(result) >= min:
			ret.append(result)
		result = ""
	
	return ret

def getPrefetch():

    # List .pf files in \WINDOWS\Prefect (admin rights often needed)
	ret = []
	commandOutput = os.popen('dir /b C:\\WINDOWS\\Prefetch\\*.pf').read()

	lines = commandOutput.split('\n')
	ID=1

	for file in lines:
		
		if file=='':
			continue
		
		filename = os.path.join('C:\\WINDOWS\\Prefetch', file)
		f = open(filename, 'rb')
		c = f.read()
		
        # http://www.forensicswiki.org/wiki/Windows_Prefetch_File_Format
        #
		# 	0			4			8			C			F
		# 0	VERSION		SIGNATURE	N/A			SIZE
		# 1 [ ORIG_FN ......................................
		# 2 ................................................
		# 3 ................................................
		# 4 ...................................]HASH
		
		VERSION = struct.unpack('I', c[:4])[0]
		SIG = c[4:8]
		SIZE = struct.unpack('I', c[0xC:0x10])[0]
		FILENAME = c[0x10:0x4C].split('\x00\x00')[0].replace('\x00','')
		HASH = struct.unpack('I', c[0x4C:0x50])[0]
		HASH = hex(HASH)[2:].replace('L','').zfill(8).upper()
		
		if VERSION==0x11:
			RUN_COUNT = struct.unpack('I', c[0x90:0x94])[0]
			
		if VERSION==0x17:
			RUN_COUNT = struct.unpack('I', c[0x98:0x9C])[0]
			
		if VERSION==0x1A:
			RUN_COUNT = struct.unpack('I', c[0xD0:0xD4])[0]
			
		REAL_SIZE = len(c)
		
		c_0 = ''.join([c[i] for i in range(0, len(c), 2)])
		c_1 = ''.join([c[i+1] for i in range(0, len(c), 2)])
		
		for s in strings(c_0)+strings(c_1):
			if '\\' in s and FILENAME.lower() in s.lower():

                # Not an exact science, but works more that doing nothing :D
				ORIG_PATH = s.replace('\\DEVICE\\HARDDISKVOLUME1','C:')
				ORIG_PATH = ORIG_PATH.replace('\\DEVICE\\HARDDISKVOLUME2','D:')
		
		f.close()
		
		ret.append([ ID, HASH, FILENAME, SIZE, REAL_SIZE, RUN_COUNT, ORIG_PATH])
		ID += 1
			
	return ret
	
def main():

	entries = getPrefetch()
	
	print '\n'.join(['\t'.join([str(f) for f in e]) for e in entries])

if __name__=='__main__':
    main()