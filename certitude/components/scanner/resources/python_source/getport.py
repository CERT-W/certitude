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

def getConnections():

    # Command netstat -ano
	ret = []
	commandOutput = os.popen('netstat -ano').read()
	
	lines = commandOutput.split('\n')
	for i in range(0,4):
		lines.pop(0)
	lines.pop()
		
    # MSFT, please use tabs...
	lines = [re.sub(r' +', r' ', e).strip() for e in lines]
	ID=1
	
    # Parse output
	for line in lines:
		PROTOCOL = line.split(' ')[0]
		
		if PROTOCOL=='TCP':
			PROTOCOL, LOCAL_COMB, REMOTE_COMB, STATUS, PID = line.split(' ')
		else:
			PROTOCOL, LOCAL_COMB, REMOTE_COMB, PID = line.split(' ')
			STATUS = 'UNKNOWN'
			
		LOCAL_PORT = LOCAL_COMB.split(':')[-1]
		REMOTE_PORT = REMOTE_COMB.split(':')[-1]
		
        # IPv4/IPv6 trick
		LOCAL_IP = LOCAL_COMB.split(']')[0][1:] if LOCAL_COMB[0] == '[' else LOCAL_COMB.split(':')[0]
		REMOTE_IP = REMOTE_COMB.split(']')[0][1:] if REMOTE_COMB[0] == '[' else REMOTE_COMB.split(':')[0]
		
		ret.append( [ ID, PROTOCOL, LOCAL_IP, LOCAL_PORT, REMOTE_IP, REMOTE_PORT, STATUS, PID ] )
		ID += 1
				
	return ret
	
def main():

	connexions = getConnections()
	
	print '\n'.join(['\t'.join([str(f) for f in e]) for e in connexions])

if __name__=='__main__':
    main()