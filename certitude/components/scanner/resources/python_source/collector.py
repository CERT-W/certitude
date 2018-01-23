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

import sys

# Dynamic import does not work with
# pyinstaller (easy to undesrtsand why)...
import getarp
import getdns
import getfiles
import getfiles_hash
import getport
import getprefetch
import getprocess
import getservices

collectors = {
    'getarp':getarp,
    'getdns':getdns,
    'getfiles':getfiles,
    'getfileshash':getfiles_hash,
    'getport':getport,
    'getprefetch':getprefetch,
    'getprocess':getprocess,
    'getservices':getservices,
        }

if __name__=='__main__':

    if len(sys.argv)<2:

        sys.stderr.write('Usage: %s <action>\n' % sys.argv[0])
        sys.stderr.write('Actions:\n')
        for collector in collectors.keys() :
            sys.stderr.write('\t- %s\n' % collector)

        sys.exit(1)

    name = sys.argv[1]
    if name not in collectors.keys():
        sys.stderr.write('Err: Collector %s does not exist' % name)
        sys.exit(2)

    collectors[name].main()