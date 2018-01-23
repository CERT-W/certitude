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

import os, re

def getARPTable():

    # Command is arp -a
	ret = []
	commandOutput = os.popen('arp -a').read()

	lines = commandOutput.split('\n')
	lines = [e for e in lines if (not 'ress' in e)]

	ACTIVE_IFACE = None
	ID=1

    # Parse output
	for line in lines:
		
		if line=='':
			continue

		if line[:9]=='Interface':
			ACTIVE_IFACE = line.split(' ')[1]
			
		else:
			if ACTIVE_IFACE is None:
				continue
				
			line = re.sub(r' +', r' ', line).strip()
			IPV4, PHYSICAL, CACHE_TYPE = line.split(' ')

            # Lnaguage trick
            # French is "dynamique" and English is "dynamic"
			CACHE_TYPE = 'dynamic' if CACHE_TYPE[:4]=='dyna' else 'static'
			
			ret.append([ID, ACTIVE_IFACE, IPV4, PHYSICAL, CACHE_TYPE])
			ID += 1
			
	return ret
	
def main():

	ARPEntries = getARPTable()
	
	print '\n'.join(['\t'.join([str(f) for f in e]) for e in ARPEntries])

if __name__=='__main__':
    main()