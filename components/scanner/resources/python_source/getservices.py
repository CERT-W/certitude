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

import os, re, hashlib

MD5SUMS = {}

def getServiceQC(name):

    # ServiCe QueryConfiguration
    commandOutput = os.popen('sc qc "'+name+'" 4096').read()

    lines = [ e.strip()  for e in commandOutput.split('\n')]
    MODE, PATH, PATHMD5 = None, None, None
    OK='OK'

    for line in lines:

        if line=='' or line[0]=='[':
            continue

        value = ':'.join(line.split(':')[1:])[1:]

        if line.find('START_TYPE')==0:
            MODE = value.split(' ')[0]

        if line.find('BINARY_PATH_NAME')==0:
            value=value.strip().lower()

            if value[0]=='"':
                value = value.split('"')[1]

            if '/' in value:
                value = value.split('/')[0]


            if ' -' in value:
                tab = value.split(' -')
                init = tab[0]
                tab.pop(0)

                while init[::-1].find('exe.')!=0:

                    if len(tab)==0:
                        path=None
                        break

                    init += ' -'+tab[0]
                    tab.pop(0)
                value = init

            PATH = value.strip()
            PATH = 'C:\\WINDOWS\\'+PATH if len(PATH)<1 or PATH[1]!=':' else PATH

            if not os.path.exists(PATH):
                OK=None

    if OK is not None:
        if not PATH in MD5SUMS.keys():
            try:
                MD5SUMS[PATH] = hashlib.md5(open(PATH, 'rb').read()).hexdigest()
            except Exception, e:
                PATHMD5 = '0'*32

        PATHMD5 = MD5SUMS[PATH]
    else:
        PATHMD5 = '0'*32

    return PATH, PATHMD5, MODE

def getServices():

    ret = []
    commandOutput = os.popen('sc query state= all').read()

    lines = commandOutput.split('\n')

    lines = [re.sub(r' +', r' ', e).strip() for e in lines]
    ID=1

    CURRENT_SERVICE, c = None, 0
    DNAME, MODE, PATH, PATHMD5, STATUS= None, None, None, None, None

    for line in lines:

        if line=='':
            continue

        if line.find('SERVICE_NAME')==0:
            CURRENT_SERVICE = ' '.join(line.split(' ')[1:])
            c=0

        else:

            if not ':' in line:
                continue

            if c==3:
                PATH, PATHMD5, MODE = getServiceQC(CURRENT_SERVICE)

                ret.append( [ ID, DNAME, MODE, PATH, PATHMD5, STATUS, CURRENT_SERVICE ] )
                ID += 1

            value = line.split(':')[1].strip()
            if line.find('DISPLAY_NAME')!=0:
                value = value.split(' ')[0]

            if c==0:
                DNAME = value

            if c==2:
                STATUS = value

            c+=1

    return ret

def main():

    services = getServices()

    print '\n'.join(['\t'.join([str(f) for f in e]) for e in services])

if __name__=='__main__':
    main()