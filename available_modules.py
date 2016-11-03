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

import helpers.iocscan_modules as A
import helpers.hashscan_modules as B

print '*** IOCSCAN ***'

for k,v in A.flatEvaluatorList.items():
    print '%s\t%s' % (k, ', '.join(v.evalList))
    
print '\n'
print '*** HashSCAN ***'

for k,v in B.flatEvaluatorList.items():
    print '%s\t%s' % (k, ', '.join(v.evalList))
    
print '\n'
