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

import os, re, psutil, time

SIDS = {}

# Well, you know how much Python and encoding are friends ;)
def sanitize(username):

    ret = username
    for i in range(0, len(ret)):
        if ord(ret[i])>128:
            ret[i]='_'

    return ret


def getHandles():
    handles = os.popen('handle /accepteula -a -nobanner').read().split('\r\n')

    HANDLE_SEARCH = ['File', 'Directory', 'Process', 'Key', 'Mutant']
    CURRENT_PROCESS = None
    SET_PROCESS = False


    handles_res = {}

    for handle in handles:
        
        if handle == '------------------------------------------------------------------------------':
            SET_PROCESS = True
            continue
            
        if SET_PROCESS:
            SET_PROCESS = False
            
            CURRENT_PROCESS = re.sub('^.+pid: ([0-9]+) .+$', '\\1', handle)
            handles_res[CURRENT_PROCESS] = []
            continue
            
        if CURRENT_PROCESS is not None:
        
            if handle=='':
                continue
                
            _, handle = handle.split(': ', 1)
            HANDLE_TYPE, HANDLE_NAME = handle.split(' ', 1)

            if HANDLE_TYPE not in HANDLE_SEARCH:
                continue
                
            HANDLE_NAME = re.sub('\s+(\([RWD-]+\))?\s*', '', HANDLE_NAME)
            
            handles_res[CURRENT_PROCESS].append((HANDLE_TYPE, HANDLE_NAME))
            
    return handles_res
    

#['pid', 'parentpid', 'UserSID', 'Username', 'name', 'path', 'handletype', 'handlename']
def getPsList(handles):

    ret = []

    process_list = psutil.process_iter()

    i=0

    for process in process_list:

        PID = process.pid
        PPID = process.ppid()

        USERSID = '-'
        USERNAME = '-'
        try:
            USERNAME = process.username().encode('utf-8')

            if not USERNAME in SIDS.keys():
                p = os.popen('.\\PsGetSid.exe /accepteula "'+USERNAME+'"')
                r = p.read().split('\n')
                try:
                    p.close()
                except IOError:
                    pass

                if len(r)>1:
                    SIDS[USERNAME] = r[1]
                else:
                    SIDS[USERNAME] = '-'
            USERSID = SIDS[USERNAME]

        except psutil.AccessDenied, e:
            pass

        NAME = '-'
        try:
            NAME = process.name()
        except psutil.AccessDenied, e:
            pass

        PATH = '-'
        try:
            PATH = process.exe()
        except psutil.AccessDenied, e:
            pass

        #CMDLINE = process.cmdline()
        HANDLE_TYPE = '-'
        HANDLE_NAME = '-'
        
        sPid = str(PID)
        if sPid not in handles.keys():
            handles[sPid] = [('-', '-')]
        
        for HANDLE_TYPE, HANDLE_NAME in handles[sPid]:
            ret.append( [ i, PID, PPID, USERSID, USERNAME, NAME, PATH, HANDLE_TYPE, HANDLE_NAME ] )
            i+=1

    return ret

def main():

    handles = getHandles()
    process = getPsList(handles)
    
    print '\n'.join(['\t'.join([str(f) for f in e]) for e in process])

if __name__=='__main__':
    main()