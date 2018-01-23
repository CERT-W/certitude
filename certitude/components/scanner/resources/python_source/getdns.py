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

IP_PATTERN = r'^((25[0-5]|2[0-4][0-9]|[1-9][0-9]{2}|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[1-9][0-9]{2}|[1-9][0-9]|[0-9])$'

def getDNSEntries():

    # Command is ipconfig /displaydns (space may be omitted)
    ret = []
    commandOutput = os.popen('ipconfig/displaydns').read()
    
    lines = commandOutput.split('\n')
    for i in range(0,3):
        lines.pop(0)
    
    lines = [re.sub(r' +', r' ', e).strip() for e in lines]
    ID=1
    
    previous, c = '', 0
    RNAME, RTYPE, TTL, DATALEN, RD_HOST, RD_IPV4 = None, None, None, None, None, None
    
    # Parse output
    for line in lines:
        
        if line=='':
            continue
        
        if line=='----------------------------------------':
            DOMAIN = previous
            c=0
            
        else:
        
            if c==6:
                ret.append( [ ID, RNAME, RTYPE, TTL, DATALEN, RD_HOST, RD_IPV4 ] )
                ID += 1
                continue
                
            if not ':' in line:
                continue
            
            value = line.split(':')[1].strip()
            
            if c==0:
                RNAME = value
                
            if c==1:
                RTYPE = value
                
            if c==2:
                TTL = value
                
            if c==3:
                DATALEN = value
            
            # May return a hostname or an IPv4 address
            if c==5:
                test = re.search(IP_PATTERN, value)
                RD_HOST, RD_IPV4 = ['-', value] if test is not None else [value, '-']
            
            c+=1
        
        
        previous = line
        
    return ret
    
def main():

    dnsentries = getDNSEntries()
    
    print '\n'.join(['\t'.join([str(f) for f in e]) for e in dnsentries])

if __name__=='__main__':
    main()