#!/usr/bin/env python
# -*- coding: UTF-8 -*-
'''
    CERTitude: the seeker of IOC
    Copyright (c) 2017-CERT-W
    
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

import base64
import cmd
import getpass
import logging
import os
import random
import string
import sys
import traceback
import time
from threading import Thread, Lock

from impacket import nt_errors, version, smb
from impacket.smbconnection import SMBConnection, FILE_READ_DATA, FILE_WRITE_DATA, FILE_APPEND_DATA, SessionError
from impacket.dcerpc.v5 import transport, scmr
from impacket.structure import Structure
import pipes


# Options
PROGRAM_NAME = 'CERTitude'

# Structure for RemComSvc incoming packets
class RemComMessage(Structure):
    structure = (
        ('Command','4096s=""'),
        ('WorkingDir','260s=""'),
        ('Priority','<L=0x20'),
        ('ProcessID','<L=0x01'),
        ('Machine','260s=""'),
        ('NoWait','<L=0'),
    )

# Process priority
PRIORITY_NORMAL = 32
PRIORITY_IDLE = 64
PRIORITY_HIGH = 128
PRIORITY_REALTIME = 256
PRIORITY_BELOWNORMAL = 16384
PRIORITY_ABOVENORMAL = 32768


# Default options
DEFAULT_DOMAIN = ''
DEFAULT_PRIORITY = PRIORITY_NORMAL


# Structure for RemComSvc outgoing packets
class RemComResponse(Structure):
    structure = (
        ('ErrorCode','<L=0'),
        ('ReturnCode','<L=0'),
    )
    
    
class LoginError(Exception):
    pass
    
    
class SetupError(Exception):
    pass     
    
    
class CleanupError(Exception):
    pass    
    
    
class CommandError(Exception):
    pass    
    
    
class DriveError(Exception):
    pass    
    
    
class FileError(Exception):
    pass
    

def getRandomName(l=8):
    return ''.join([random.choice(string.letters+string.digits) for i in range(l)])
    
    
# Remote Command class
#
#   Arguments :
#       Target IP
#       Remote username
#       Remote password
#
class RemoteCmd:

    REMCOMSVC_LOCAL = os.path.join('resources','RemComSvc.exe')
    REMCOMSVC_REMOTE = 'RemComSvc.exe'
    REMCOMSVC_SERVICE_NAME = PROGRAM_NAME + '-SVC'
    REMCOMSVC_SERVICE_DESC = 'Remote Command provided by CERTitude (c) Wavestone 2017'


    # LOGGER FUNCTION
    def __log__(self, debugLevel, message, exception=None):

        import inspect
        func = inspect.currentframe().f_back.f_code

        m = '%s@%s\t%-30s\t%s' % (self.__login.encode(sys.stdout.encoding), self.__ip.encode(sys.stdout.encoding), func.co_name, message)
        self.logger.log(debugLevel, m)

        if exception is not None:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            for line in traceback.format_exc(exc_tb).splitlines():
                self.logger.log(debugLevel, line)



    # CONSTRUCTOR
    def __init__(self, threadname, ip, login, password, **kwargs):

        self.logger = logging.getLogger('remotecmd.' + threadname)
        if 'verbosity' in kwargs.keys():
            self.logger.setLevel(kwargs['verbosity'])

        # Init variables
        self.__ip = ip
        self.__login = login

        # KWargs
        domain = DEFAULT_DOMAIN if 'domain' not in kwargs.keys() else kwargs['domain']
        commandPriority = DEFAULT_PRIORITY if 'priority' not in kwargs.keys() else kwargs['priority']
        self.rootDir = '.' if not 'rootDir' in kwargs.keys() else kwargs['rootDir']
        
        # Local variables
        self.__rootDir = '.' if 'rootDir' not in kwargs.keys() else kwargs['rootDir']
        self.__writableShare = None
        self.__workingDirectory = None
        self.__SVCManager = None
        self.__service = None
        self.drive = None
        
        # Setup & cleanup actions
        self.__pendingCleanupActions = []
        self.__pendingSetupActions = [
            (self.__findWritableShare, 3),
            (self.__createWorkingDirectory, 3),
            (self.__openSVCManager, 3),
            (self.__createService, 3),
            (self.__dropBinary, 3),
            (self.__startService, 3),
            (self.__setNet, 1),
        ]

        # Transport connection
        self.__rpctransport = transport.DCERPCTransportFactory('ncacn_np:%s[\pipe\svcctl]' % ip)
        self.__rpctransport.set_dport(445)
        self.__rpctransport.set_credentials(login, password, domain, '', '', '')
        self.__rpctransport.set_kerberos(False, '')
        self.__dcerpc = self.__rpctransport.get_dce_rpc()
        
        # Initiate login
        try:
            self.__dcerpc.connect()
            self.__smbconnection = self.__rpctransport.get_smb_connection()
            self.__log__(logging.INFO, 'Login successful')
            
        except SessionError, e:
            raise LoginError('Error during login: %s' % e.getErrorString()[0])
    
    
    # SETUP function
    def setup(self):
    
        while len(self.__pendingSetupActions)>0:
            action, count = self.__pendingSetupActions.pop(0)
            
            c=1
            while c<=count:
                try:
                    action()
                    break
                    
                except Exception, e:
                    self.__log__(logging.ERROR, 'error in %s, sleep %ds' % (action.__name__, c), e)
                    c += 1
                    time.sleep(c)
                    
            if count<c:
                self.__log__(logging.CRITICAL, 'Fatal error during setup - proceeding to cleanup')
                self.cleanup()
                raise SetupError('Could not setup service, aborting')
            
    
    # List shares, try to create directory in them
    def __findWritableShare(self):
        self.__log__(logging.DEBUG, 'Searching for writable share')
        shares = self.__smbconnection.listShares()
        dirname = getRandomName() + '-write-test'
        
        tries = []
        for share in shares:
            if share['shi1_type'] in [smb.SHARED_DISK, smb.SHARED_DISK_HIDDEN]:
                shareName = share['shi1_netname'][:-1]
                shareOK = True

                try:
                    # try to create directory
                    self.__smbconnection.createDirectory(shareName, dirname)
                except SessionError, e:
                    tries.append(shareName)
                    # if error, depends on whether the test directory existed or not
                    shareOK = True if e.getErrorCode == nt_errors.STATUS_OBJECT_NAME_COLLISION else False

                if shareOK:
                    # We found a share, delete our test
                    self.__smbconnection.deleteDirectory(shareName, dirname)
                    self.__log__(logging.DEBUG, 'Using share "%s"' % shareName)
                    self.__writableShare = shareName
                    return
                    
        raise Exception('Could not find writable share among [%s]' % (','.join(tries)))
   
   
    # Process to working directory on remote wks
    def __createWorkingDirectory(self):
        self.__log__(logging.DEBUG, 'Creating working directory')
        
        try:
            dirname = '%s-local' % PROGRAM_NAME
            self.__smbconnection.createDirectory(self.__writableShare, dirname)
            self.__workingDirectory = dirname
            self.__pendingCleanupActions.append((self.__deleteWorkingDirectory, 3))
            
        except SessionError, e:
            if e.getErrorCode()!=nt_errors.STATUS_OBJECT_NAME_COLLISION:
                raise e
            
            else:
                self.__workingDirectory = dirname
                self.__pendingCleanupActions.append((self.__deleteWorkingDirectory, 3))
                self.__log__(logging.WARNING, 'Directory "%s" is already present' % dirname)
                                
        return
          
          
    # Installs the service
    def __openSVCManager(self):
        self.__log__(logging.DEBUG, 'Opening service manager')
        
        self.__dcerpc.bind(scmr.MSRPC_UUID_SCMR)
        resp = scmr.hROpenSCManagerW(self.__dcerpc)
        self.__pendingCleanupActions.append((self.__closeSVCManager, 3))
        self.__SVCManager = resp['lpScHandle']
        return
    
    # Creates the service
    def __createService(self):
        self.__log__(logging.DEBUG, 'Creating service')

        try:
            resp = scmr.hROpenServiceW(self.__dcerpc, self.__SVCManager, RemoteCmd.REMCOMSVC_SERVICE_NAME + '\x00')
            self.__log__(logging.WARNING, 'Service already exists, renewing it')
            
            try:
                scmr.hRControlService(self.__dcerpc, resp['lpServiceHandle'], scmr.SERVICE_CONTROL_STOP)
                time.sleep(1)
            except: 
                pass
                
            scmr.hRDeleteService(self.__dcerpc, resp['lpServiceHandle'])
            scmr.hRCloseServiceHandle(self.__dcerpc, resp['lpServiceHandle'])
            
        except:
            pass
                
        resp = scmr.hRCreateServiceW(
                self.__dcerpc, 
                self.__SVCManager, 
                RemoteCmd.REMCOMSVC_SERVICE_NAME + '\x00',
                RemoteCmd.REMCOMSVC_SERVICE_NAME + '\x00',
                lpBinaryPathName = self.__getWritableUNCPath() + '\\' + RemoteCmd.REMCOMSVC_REMOTE + '\x00',
                dwStartType=scmr.SERVICE_DEMAND_START,
        )
        
        resp = scmr.hROpenServiceW(self.__dcerpc, self.__SVCManager, RemoteCmd.REMCOMSVC_SERVICE_NAME + '\x00')
        self.__service = resp['lpServiceHandle']
                
        self.__pendingCleanupActions.append((self.__deleteService, 3))
        return
    
    
    # Drops the binary file to register as a service
    def __dropBinary(self):
        self.__log__(logging.DEBUG, 'Dropping binary file')
        
        localBinary = open( os.path.join(self.__rootDir, RemoteCmd.REMCOMSVC_LOCAL), 'rb')
        remoteBinary = '%s\\%s' % (self.__workingDirectory, RemoteCmd.REMCOMSVC_REMOTE)
        self.__smbconnection.putFile(self.__writableShare, remoteBinary, localBinary.read)
        self.__pendingCleanupActions.append((self.__deleteBinary, 3))
        return 

    
    # Starts the service
    def __startService(self):
        self.__log__(logging.DEBUG, 'Starting service')
    
        scmr.hRStartServiceW(self.__dcerpc, self.__service)    
        self.__pendingCleanupActions.append((self.__stopService, 3))
        return
       
       
    '''
        By default, remote share is targeted by UNC path \\REMOTE\SHARE-NAME$\
        CMD.EXE /C commands can be specified a working directory but UNC Path do not work
        Trick is to allocate a network drive LETTER: to \\REMOTE\SHARE-NAME$\ and to use LETTER:\ as CWD
    '''
    # Search and set unallocated network drive
    def __setNet(self):

        for letter in [chr(i) for i in range(ord('A'), ord('Z')+1)]:
            out = self.execute('net use * /delete /y 2>&1')
            out = self.execute('net use %s: %s 2>&1' % (letter, self.__getWritableUNCPath()))
            if out.find('85')==-1:
                self.__log__(logging.DEBUG, 'Using network drive %s:' % letter)
                self.drive = letter
                self.__pendingCleanupActions.append((self.__unsetNet, 3))
                return letter+':'

        raise DriveError('Cannot find suitable network drive')
       
     
    # CLEANUP function
    def cleanup(self):
        while len(self.__pendingCleanupActions)>0:
            action, count = self.__pendingCleanupActions.pop()
            
            c=1
            while c<=count:
                try:
                    action()
                    break
                    
                except Exception, e:
                    self.__log__(logging.ERROR, 'error in %s, sleep %ds' % (action.__name__, c), e)
                    c += 1
                    time.sleep(c)
                    
            if count==0:
                raise CleanupError('Fatal error during cleanup - could not recover')

                
    # Deletes allocated drive
    def __unsetNet(self):
        time.sleep(1)
        out = self.execute('net use %s: /DELETE /y' % self.drive)
        self.__log__(logging.DEBUG, 'Net unuse: %s' % out[:-2])
        
    
    # Stops the service
    def __stopService(self):
        self.__log__(logging.DEBUG, 'Stopping service')
    
        scmr.hRControlService(self.__dcerpc, self.__service, scmr.SERVICE_CONTROL_STOP)    
        time.sleep(1)
        return
                
        
    # Deletes binary
    def __deleteBinary(self):
        self.__log__(logging.DEBUG, 'Deleting binary file')
        
        remoteBinary = '%s\\%s' % (self.__workingDirectory, RemoteCmd.REMCOMSVC_REMOTE)
        self.__smbconnection.deleteFile(self.__writableShare, remoteBinary)
        return 
       
     
    # Deletes the service
    def __deleteService(self):
        self.__log__(logging.DEBUG, 'Deleting service')
        
        scmr.hRDeleteService(self.__dcerpc, self.__service)
        scmr.hRCloseServiceHandle(self.__dcerpc, self.__service)
        self.__service = None
        return 
        
        
    # Uninstalls the service
    def __closeSVCManager(self):
        self.__log__(logging.DEBUG, 'Closing service manager')
        
        scmr.hRCloseServiceHandle(self.__dcerpc, self.__SVCManager)
        self.__SVCManager = None
        return

        
    # Deletes working directory
    def __deleteWorkingDirectory(self):
        self.__log__(logging.DEBUG, 'Deleting working directory')
        
        self.__smbconnection.deleteDirectory(self.__writableShare, self.__workingDirectory)
        self.__workingDirectory = None
        return 

    # END CLEANUP
        
        
    # Returns the local path corresponding to the UNC path \\remote\w-share\dirname
    def __getWritableUNCPath(self):
        serverName = self.__smbconnection.getServerName()
        if serverName == '':
            serverName = '127.0.0.1'

        return '\\\\%s\\%s\\%s' % (serverName, self.__writableShare, self.__workingDirectory)
        
        
    # Handles named pipes
    def __openNamedPipe(self, tid, pipe, accessMask):
        pipeReady = False
        tries = 50

        # Tries repeatedly to open pipe
        while pipeReady is False and tries > 0:
            try:
                self.__smbconnection.waitNamedPipe(tid,pipe)
                pipeReady = True
            except Exception,e:
                #self.__log__(logging.WARNING, 'Error opening pipe "%s"' % pipe, e)
                tries -= 1
                time.sleep(1)
                

        if tries == 0:
            raise CommandError('Could not create named pipe')

        return self.__smbconnection.openFile(tid, pipe, accessMask, creationOption = 0x40, fileAttributes = 0x80)  
        
    
    # Executes command on remote system
    def execute(self, command, useDrive=False):

        try:
            assert (self.__service is not None)
            
            # Connect to the IPC tree and open RemComSvc exchange pipe
            tid = self.__smbconnection.connectTree('IPC$')
            fid = self.__openNamedPipe(tid, '\RemCom_communicaton', 0x12019f)

            # Build packet
            packet = RemComMessage()
            pid = os.getpid()

            c = 'ABCDEFGHIJKLMNOPRSTUVWXYZabcdefghijklmnoprsqtuvwxyz';
            command = 'cmd.exe /C '+command

            packet['Machine'] = ''.join([random.choice(c) for i in range(4)])
            packet['WorkingDir'] = '%s:\\' % self.drive if useDrive else '\\'
            packet['Priority'] = PRIORITY_NORMAL
            packet['Command'] = command.encode('utf-8')
            packet['ProcessID'] = pid

            # Send it along with the command
            self.__log__(logging.DEBUG, 'Executing command: "'+command+'" with priority '+str(PRIORITY_NORMAL))
            self.__smbconnection.writeNamedPipe(tid, fid, str(packet))

            # Opens the STD pipes
            cred = self.__smbconnection.getCredentials()
            host = self.__smbconnection.getRemoteHost()
            port = 445

            stdin_pipe  = pipes.RemoteStdInPipe(host, port, cred,'\%s%s%d' % ('RemCom_stdin' ,packet['Machine'],packet['ProcessID']), FILE_WRITE_DATA | FILE_APPEND_DATA, self.__writableShare )
            stdin_pipe.start()
            stdout_pipe = pipes.RemoteStdOutPipe(host, port, cred,'\%s%s%d' % ('RemCom_stdout',packet['Machine'],packet['ProcessID']), FILE_READ_DATA )
            stdout_pipe.start()
            stderr_pipe = pipes.RemoteStdErrPipe(host, port, cred,'\%s%s%d' % ('RemCom_stderr',packet['Machine'],packet['ProcessID']), FILE_READ_DATA )
            stderr_pipe.start()
            
            # Should be hanging till the command is completed
            ans = self.__smbconnection.readNamedPipe(tid,fid,8)

            # get stdout
            ret = stdout_pipe.out

            # Close the pipes
            stdin_pipe.stop()
            stdout_pipe.stop()
            stderr_pipe.stop()

            # Yeah, it can happen, dunno why.
            if ret[:2] == '\x0d\x0a':
                ret = ret[2:]

            # Most commands return an additional line. See if keeping it is useful
            return ret[:-2]
            
        except Exception, e:
            self.__log__(logging.ERROR, 'Error during command execution', e)

            
    # File operations
    def dropFile(self, localName, remoteName, useRootDir = True):
        try:
            self.__log__(logging.DEBUG, 'Dropping file ' + remoteName)
            lpath = os.path.join(self.rootDir, localName) if useRootDir else localName
            remoteName = '%s\\%s' % (self.__workingDirectory, remoteName)
            self.__smbconnection.putFile(self.__writableShare, remoteName, open(lpath , 'rb').read)
            self.__log__(logging.DEBUG, 'Dropped file ' + remoteName)
            
        except Exception, e:
            self.__log__(logging.ERROR, 'Error during file drop', e)
            raise FileError()
            
    
    def getFile(self, remoteName, localName, useRootDir = True):

        try:
            self.__log__(logging.DEBUG, 'Retrieving file ' + remoteName)
            lpath = os.path.join(self.rootDir, localName) if useRootDir else localName
            remoteName = '%s\\%s' % (self.__workingDirectory, remoteName)
            self.__smbconnection.getFile(self.__writableShare, remoteName, open(lpath , 'wb').write)
            self.__log__(logging.DEBUG, 'Retrieved file ' + remoteName)
        
        except Exception, e:
            self.__log__(logging.ERROR, 'Error during file retrieval', e)
            raise FileError()
            
    
    def deleteFile(self, remoteName):
            
        try:
            self.__log__(logging.DEBUG, 'Deleting file ' + remoteName)
            remoteName = '%s\\%s' % (self.__workingDirectory, remoteName)
            self.__smbconnection.deleteFile(self.__writableShare, remoteName)
            self.__log__(logging.DEBUG, 'Deleted file ' + remoteName)
        
        except Exception, e:
            self.__log__(logging.ERROR, 'Error during file deletion', e)
            raise FileError()
      

    def fileExists(self, remoteName):
    
        try:
            self.__log__(logging.DEBUG, 'Trying to access ' + remoteName)
            tid = self.__smbconnection.connectTree(self.__writableShare)
            remoteName = '%s\\%s' % (self.__workingDirectory, remoteName)
            fid = self.__smbconnection.openFile(tid, remoteName, desiredAccess=FILE_READ_DATA)
            self.__log__(logging.DEBUG, 'File exists: ' + remoteName)
            self.__smbconnection.closeFile(tid, fid)
            return False
        
        except SessionError, e:
            if e.getErrorCode() == nt_errors.STATUS_OBJECT_NAME_NOT_FOUND:
                self.__log__(logging.DEBUG, 'File does not exist: ' + remoteName)
                return False
                
            self.__log__(logging.ERROR, 'Error during file access', e)
            raise FileError()
                
        except Exception, e:
            self.__log__(logging.ERROR, 'Error during file access', e)
            raise FileError()
      
      
# MAIN
if __name__ == '__main__':

    # Logging
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(name)-20s : %(levelname)-8s %(message)s')
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)
        
    r = RemoteCmd('toto', '127.0.0.1', raw_input('Login: '), getpass.getpass('Password: '), verbosity=logging.DEBUG, domain='DOMAIN')

    r.setup()
    r.fileExists('RemComSvc.exe')
    r.fileExists('toto.exe')
    r.cleanup()