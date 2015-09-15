#!/usr/bin/python

import os, re, psutil

SIDS = {}

def sanitize(username):

    ret = username
    for i in range(0, len(ret)):
        if ord(ret[i])>128:
            ret[i]='_'
            
    return ret
            

#['pid', 'parentpid', 'UserSID', 'Username', 'name', 'path', 'moduleList']
def getPsList():

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
        MODULE_LIST = '-'
        
        i+=1
        ret.append( [ i, PID, PPID, USERSID, USERNAME, NAME, PATH, MODULE_LIST ] )
        
    return ret
    
def main():

    process = getPsList()
    
    print '\n'.join(['\t'.join([str(f) for f in e]) for e in process])
    
if __name__=='__main__':
    main()