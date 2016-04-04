#!/usr/bin/python

import socket

from psexec import remcomsvc, smbconnection, transport, dcerpc, srvsvc, svcctl, structure, pipes
from impacket import nt_errors
import logging
import sys, time, os, random, string

###################
#                 #
#  CONFIGURATION  #
#                 #
###################

PROGRAM_NAME = 'CERTitude'
FILE_READ_DATA = smbconnection.FILE_READ_DATA
FILE_WRITE_DATA = smbconnection.FILE_WRITE_DATA
FILE_APPEND_DATA = smbconnection.FILE_APPEND_DATA

# Logging options

LEVEL_CRITICAL = logging.CRITICAL
LEVEL_ERROR = logging.ERROR
LEVEL_WARNING = logging.WARNING
LEVEL_INFO = logging.INFO
LEVEL_INFODBG = logging.DEBUG

# Structure for RemComSvc incoming packets
class RemComMessage(structure.Structure):
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
DEFAULT_DEBUG_LEVEL = LEVEL_CRITICAL


# Structure for RemComSvc outgoing packets
class RemComResponse(structure.Structure):
    structure = (
        ('ErrorCode','<L=0'),
        ('ReturnCode','<L=0'),
    )


# Custom exception
class WritableShareException(Exception):
    pass



# Remote Command class
#
#   Arguments :
#       Target IP
#       Remote username
#       Remote password
#
class RemoteCmd:

    REMCOMSVC_LOCAL = os.path.join('resources','RemComSvc.exe')
    REMCOMSVC_REMOTE = 'rcs.exe'
    REMCOMSVC_SERVICE_NAME = PROGRAM_NAME + '-RCS'
    REMCOMSVC_SERVICE_DESC = 'Remote Command provided by CERTitude (c) Solucom 2014'


    ######
    #
    #   Logging functionality
    #   CRITICAL logs automatically stop the program
    #
    def __log__(self, debugLevel, message, exception=''):

        m = self.__login + '@' + self.__ip + ' ' + message.decode('cp1252')

        if exception!='':
            m += ' (%s)' % str(exception)

        self.logger.log(debugLevel, m)


    #######
    #
    #   Constructor
    #   Does the setup
    #
    def __init__(self, threadname, ip, login, password, **kwargs):

    # init variables

        self.__ip = ip
        self.__login = login

    #KWargs

        self.logger = logging.getLogger('remotecmd.' + threadname)
        domain = DEFAULT_DOMAIN if 'domain' not in kwargs.keys() else kwargs['domain']
        commandPriority = DEFAULT_PRIORITY if 'priority' not in kwargs.keys() else kwargs['priority']

    # Control variables : what did I set up ?
        self.__loggedIn = False
        self.__treeConnected = False
        self.__directoryCreated = False
        self.__ServiceManagerOpened = False
        self.__remcomDropped = False
        self.__serviceCreated = False
        self.__serviceStarted = False
        self.__serviceLaunched = False

        self.__connection = None
        self.__connection = smbconnection.SMBConnection(login+'_'+ip, ip, socket.gethostname(), 445, 3600, smbconnection.SMB2_DIALECT_21)
        self.__commandPriority = commandPriority
        self.__writableShareId = None
        self.__writableShare = None
        self.__serviceManager = None
        self.__service = None
        self.activeDirName = PROGRAM_NAME + '-active'

        self.rootDir = '.' if 'rootDir' not in kwargs.keys() else kwargs['rootDir']

        # Try to setup the program
        try:
            self.__setup(ip, login, password, domain)
        except smbconnection.SessionError,e :
            self.__log__(LEVEL_CRITICAL,'Error during setup',e)
            raise e
            


    ######
    #
    #   Setup function
    #   Boots the different functionnalities, such as :
    #       writable share
    #       working directory
    #       service manager
    #       ...
    #
    def __setup(self,ip, login, password, domain = ''):

        # Log in
        self.__connection.login(login, password, domain)
        self.__log__(LEVEL_INFODBG, 'Connection successful')
        self.__loggedIn = True

        # Search for usable share
        try:
            self.__writableShare = self.__findWritableShare()
        except WritableShareException,e:
            self.__log__(LEVEL_CRITICAL,'',e)
            self.__del__(False)
            return

        self.__writableShareId = self.__connection.connectTree(self.__writableShare)
        self.__log__(LEVEL_INFODBG, 'Tree connected')
        self.__treeConnected = True

        # Tries to create working directory
        # Uses existing if we can
        try:
            self.__connection.createDirectory(self.__writableShare, self.activeDirName)
        except smbconnection.SessionError, e:
            if e.getErrorCode()!=nt_errors.STATUS_OBJECT_NAME_COLLISION:
                raise

        self.__directoryCreated = True
        self.__log__(LEVEL_INFODBG, 'Directory created')

        # opens service manager
        self.__serviceManager = self.__openServiceManager()
        self.__ServiceManagerOpened = True
        self.__log__(LEVEL_INFODBG, 'Service Manager opened')

        # drop RemComSvc binary
        lpath = RemoteCmd.REMCOMSVC_LOCAL
        self.dropFile( lpath, RemoteCmd.REMCOMSVC_REMOTE)
        self.__log__(LEVEL_INFODBG, 'RemCom service binary dropped')

        self.__remcomDropped = True

        # Creates RemComSvc service
        self.__createService(RemoteCmd.REMCOMSVC_SERVICE_NAME, RemoteCmd.REMCOMSVC_SERVICE_DESC, RemoteCmd.REMCOMSVC_REMOTE)
        self.__serviceCreated = True
        self.__log__(LEVEL_INFODBG, 'RemCom service has been created')

        # And start it !
        self.__startService()
        self.__serviceStarted = True
        self.__log__(LEVEL_INFODBG, 'RemCom service has been started')


    ######
    #
    #   Destructor
    #   called by CRITICAL log and by del actions
    #   should be called upon program termination by the GC
    #
    def __del__(self, fromError = False):

        try:
            self.__unsetup()

        except Exception, e:
            self.logger.critical('Cleanup error: '+str(e).replace('\n', ' - '))

        if fromError:
            sys.exit(1)



    ######
    #
    #   Unsetup function
    #   undo what the setup did
    #
    def __unsetup(self):

        # Stop remcomsvc
        if self.__serviceStarted:
            self.__rpcsvc.StopService(self.__service['ContextHandle'])
            self.__log__(LEVEL_INFODBG, 'RemCom service has been stopped')

        # Deletes RemComSvc
        if self.__serviceCreated:

            self.__rpcsvc.DeleteService(self.__service['ContextHandle'])
            self.__rpcsvc.CloseServiceHandle(self.__service['ContextHandle'])
            self.__log__(LEVEL_INFODBG, 'RemCom service deleted')

        # Deletes RemComSvc binary
        if self.__remcomDropped:
            self.deleteFile(RemoteCmd.REMCOMSVC_REMOTE, LEVEL_ERROR)
            self.__log__(LEVEL_INFODBG, 'RemCom service binary deleted')

        # Closes Service manager
        if self.__ServiceManagerOpened:
            self.__rpcsvc.CloseServiceHandle(self.__serviceManager)
            self.__log__(LEVEL_INFODBG, 'Service Manager closed')

        # Deletes working directory if empty
        if self.__directoryCreated:
            try:
                self.__connection.deleteDirectory(self.__writableShare, self.activeDirName)
            except smbconnection.SessionError, e:
                if e.getErrorCode()!=nt_errors.STATUS_DIRECTORY_NOT_EMPTY:
                    raise
                else:
                    self.__log__(LEVEL_WARNING, 'Directory was not empty therefore not deleted')
            else:
                self.__log__(LEVEL_INFODBG, 'Directory deleted')

        # disonnect from share
        if self.__treeConnected:
            self.__connection.disconnectTree(self.__writableShareId)
            self.__log__(LEVEL_INFODBG, 'Tree disconnected')

        # Log off
        if self.__loggedIn:
            self.__connection.logoff()
            self.__log__(LEVEL_INFODBG, 'Logged off')

        # Manually close socket
        if self.__connection is not None:
            s = self.__connection.getSMBServer().get_socket()
            s.shutdown(2)
            s.close()

    ######
    #
    #   Return the local path corresponding to the UNC path \\remote\w-share\dirname
    #
    def getWritablePath(self):
        serverName = self.__connection.getServerName()
        if serverName == '':
            serverName = '127.0.0.1'

        return '\\\\%s\\%s\\%s' % (serverName, self.__writableShare, self.activeDirName)

    ######
    #
    #   Opens the service manager
    #   Returns handle to SvcMgr
    #
    def __openServiceManager(self):
        self.__rpctransport = transport.SMBTransport('','',filename = r'\svcctl', smb_connection = self.__connection)
        self.__dce = dcerpc.DCERPC_v5(self.__rpctransport)
        self.__dce.connect()
        self.__dce.bind(svcctl.MSRPC_UUID_SVCCTL)
        self.__rpcsvc = svcctl.DCERPCSvcCtl(self.__dce)
        try:
            resp = self.__rpcsvc.OpenSCManagerW()
            return resp['ContextHandle']
        except Exception, e:
            self.__log__(LEVEL_CRITICAL,'Cannot open Service Manager',e)
            self.__del__(False)


    ######
    #
    #   Uses the SvcMgr to create the service
    #   ServiceName is the short name
    #   ServiceDesc is display name
    #   path is the location of the service binary (UNC allowed)
    #
    def __createService(self, serviceName, serviceDesc, path):

        path = '%s\\%s' % (self.getWritablePath(), path)

        try:
            # try to open service
            svcCheck = self.__rpcsvc.OpenServiceW(self.__serviceManager, serviceName.encode('utf-16le'))
        except svcctl.SVCCTLSessionError,e:
            if e.get_error_code()!= svcctl.ERROR_SERVICE_DOES_NOT_EXISTS:
                # Error furing the check
                self.__log__(LEVEL_CRITICAL, 'Cannot check for service '+serviceName, e)
                self.__del__(False)
                return
        else:
            # Service is already open, remove it
            try:
                self.__rpcsvc.StopService(svcCheck['ContextHandle'])
            except svcctl.SVCCTLSessionError, e:
                # Oops, it was not running
                if e.get_error_code()!=svcctl.ERROR_SERVICE_NOT_ACTIVE:
                    # Or maybe yes, and we have another error
                    raise

            # Delete it and close its handle
            self.__rpcsvc.DeleteService(svcCheck['ContextHandle'])
            self.__rpcsvc.CloseServiceHandle(svcCheck['ContextHandle'])

        try:
            # We are sure that the service does not exist
            # we try to create it
            self.__service = self.__rpcsvc.CreateServiceW(self.__serviceManager,
                                                          serviceName.encode('utf-16le'),
                                                          serviceDesc.encode('utf-16le'),
                                                          path.encode('utf-16le'))
        except svcctl.SVCCTLSessionError,e:
            # bad for us...
            self.__log__(LEVEL_CRITICAL, 'Unable to create service '+RemoteCmd.REMCOMSVC_SERVICE_NAME, e)
            self.__del__(False)



    ######
    #
    #   Starts the service
    #
    def __startService(self):
        try:
            self.__rpcsvc.StartServiceW(self.__service['ContextHandle'])
        except svcctl.SVCCTLSessionError,e:
            self.__log__(LEVEL_CRITICAL, 'Unable to start service '+RemoteCmd.REMCOMSVC_SERVICE_NAME, e)
            self.__del__(False)



    ######
    #
    #   Pipe utilities
    #   returns handle to pipe
    #
    def __openPipe(self, tid, pipe, accessMask):
        pipeReady = False
        tries = 50

        # Tries repeatedly to open pipe
        while pipeReady is False and tries > 0:
            try:
                self.__connection.waitNamedPipe(tid,pipe)
                pipeReady = True
            except Exception,e:
                print e
                tries -= 1
                time.sleep(1)
                pass

        if tries == 0:
            self.__log__(LEVEL_CRITICAL, 'Unable to create named pipe')
            self.__del__(False)
            return

        return self.__connection.openFile(tid, pipe, accessMask, creationOption = 0x40, fileAttributes = 0x80)


    ######
    #
    #   Main function : executes command remotely
    #   command is what is to be launched via "cmd /C command"
    #   path is the working directory in which the command will be executed (UNC *not* allowed)
    #
    #   Returns stdout of the command
    #
    def execCommand(self, command, path = None):

        # Connect to the IPC tree and open RemComSvc exchange pipe
        tid = self.__connection.connectTree('IPC$')
        fid = self.__openPipe(tid, '\RemCom_communicaton', 0x12019f)

        # Build packet
        packet = RemComMessage()
        pid = os.getpid()

        c = 'ABCDEFGHIJKLMNOPRSTUVWXYZabcdefghijklmnoprsqtuvwxyz';
        command = 'cmd.exe /C '+command

        packet['Machine'] = ''.join([random.choice(c) for i in range(4)])
        packet['WorkingDir'] = path if path is not None else '\\'
        packet['Priority'] = self.__commandPriority
        packet['Command'] = command.encode('utf-8')
        packet['ProcessID'] = pid

        # Send it along with the command
        self.__log__(LEVEL_INFODBG, 'Executing command: "'+command+'" with priority '+str(self.__commandPriority))
        self.__connection.writeNamedPipe(tid, fid, str(packet))

        # Opens the STD pipes
        cred = self.__connection.getCredentials()
        rh = self.__connection.getRemoteHost()
        port = 445

        try:
            stdin_pipe  = pipes.RemoteStdInPipe(rh, port, cred,'\%s%s%d' % ('RemCom_stdin' ,packet['Machine'],packet['ProcessID']), FILE_WRITE_DATA | FILE_APPEND_DATA, self.__writableShare )
            stdin_pipe.start()
            stdout_pipe = pipes.RemoteStdOutPipe(rh, port, cred,'\%s%s%d' % ('RemCom_stdout',packet['Machine'],packet['ProcessID']), FILE_READ_DATA )
            stdout_pipe.start()
            stderr_pipe = pipes.RemoteStdErrPipe(rh, port, cred,'\%s%s%d' % ('RemCom_stderr',packet['Machine'],packet['ProcessID']), FILE_READ_DATA )
            stderr_pipe.start()
        except Exception, e:
            self.__log__(LEVEL_CRITICAL, 'Error while creating the pipes', e)

        # Should be hanging till the command is completed
        ans = self.__connection.readNamedPipe(tid,fid,8)

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


    ######
    #
    #   Finds a writable share among the available shares present
    #   on the remote server.
    #
    def __findWritableShare(self):

        # get all shares
        allShares = self.__connection.listShares()
        dirName = PROGRAM_NAME + '-write-test'
        tries = []

        for share in allShares:

            # Filter by share type
            if share['shi1_type'] in [smbconnection.smb.SHARED_DISK, smbconnection.smb.SHARED_DISK_HIDDEN]:
                shareName = share['shi1_netname'][:-1]
                shareOK = True

                try:
                    # try to create directory
                    self.__connection.createDirectory(shareName, dirName)
                except smbconnection.SessionError, e:
                    tries.append(shareName)
                    # if error, depends on whether the test directory existed or not
                    shareOK = True if e.getErrorCode == nt_errors.STATUS_OBJECT_NAME_COLLISION else False

                if shareOK:
                    # We found a share, delete our test
                    self.__connection.deleteDirectory(shareName, dirName)
                    return shareName

        raise WritableShareException('No writable share found among ['+(', '.join(tries))+']')


    ######
    #
    #   Returns handle to remotely opened file
    #
    def __openFile(self, filename, mode = FILE_READ_DATA, useWd=True):

        filename = self.activeDirName+'\\'+filename if useWd else filename

        try:
            # try to get handle of existing file
            fid = self.__connection.openFile(self.__writableShareId, filename, mode)
            return fid
        except smbconnection.SessionError, e:
            # File did not exist
            if e.getErrorCode() != nt_errors.STATUS_OBJECT_NAME_NOT_FOUND:
                self.__log__(LEVEL_CRITICAL, 'Cannot open file '+filename+': ',e)
                self.__del__(False)
                return

        try:
            # then create it !
            fid = self.__connection.createFile(self.__writableShareId, filename)
            return fid
        except smbconnection.SessionError, e:
            # or not ...
            self.__log__(LEVEL_CRITICAL, 'Cannot create file '+filename+': ',e)
            self.__del__(False)


    ######
    #
    #   Closes a file according to its FID
    #
    def __closeFile(self, fid):

        try:
            self.__connection.closeFile(self.__writableShareId, fid)
        except smbconnection.SessionError, e:
            self.__log__(LEVEL_CRITICAL, 'Cannot close file '+fid+': ',e)
            self.__del__(False)


    ######
    #
    #   Returns true if file exists within the working directory (if useWD)
    #   or in the share
    #
    def fileExists(self, filename, useWd=True):

        filename = self.activeDirName+'\\'+filename if useWd else filename

        try:
            # try to open file
            fid = self.__connection.openFile(self.__writableShareId, filename, FILE_READ_DATA)
            self.__connection.closeFile(self.__writableShareId, fid)
            return True
        except smbconnection.SessionError, e:
            # does not work
            if e.getErrorCode() != nt_errors.STATUS_OBJECT_NAME_NOT_FOUND:
                # because of unknown error
                self.__log__(LEVEL_CRITICAL, 'Cannot stat file '+filename+': ',e)
                self.__del__(False)
            else:
                # because file existed
                return False

    ######
    #
    #   Reads the entire file located at <filename>
    #
    def readFile(self, filename,useWd=True):

        if not self.fileExists(filename, useWd):
            self.__log__(LEVEL_ERROR, 'File '+filename+' does not exist')
            return None

        fid = self.__openFile(filename, useWd)
        offset = 0
        ret = ""    # buffer

        try:
            while True:
                # read bytes
                data = self.__connection.readFile(self.__writableShareId, fid, offset)
                l = len(data)

                if l==0:
                    # EOF
                    self.__closeFile(fid)
                    return ret
                else:
                    # append
                    ret += data
                    offset += l

        except smbconnection.SessionError, e:
            self.__log__(LEVEL_CRITICAL, 'Cannot read '+filename+': ',e)
            self.__del__(False)


    ######
    #
    #   Writes <data> to <filename>
    #   Erases original file if exists
    #
    def writeFile(self, filename, data, initOffset = 0, useWd=True):

        fid = self.__openFile(filename, FILE_WRITE_DATA, useWd)
        offset = initOffset
        bytesWritten = 0

        try:
            while len(data) != 0:
                # write bytes
                bytesWritten = self.__connection.writeFile(self.__writableShareId, fid, data, offset)

                if bytesWritten is None:
                    bytesWritten = len(data)

                offset += bytesWritten
                data = data[bytesWritten:]

            # EOF
            self.__closeFile(fid)
            return bytesWritten
        except smbconnection.SessionError, e:
            self.__log__(LEVEL_CRITICAL, 'Cannot write in '+filename+': ',e)
            self.__del__(False)


    ######
    #
    #   Deletes remote file
    #   Throws errorLevel in case of error
    def deleteFile(self, filename, errorLevel = LEVEL_CRITICAL, useWd=True):

        self.__log__(LEVEL_INFODBG, 'Deleting file ' + filename)
        filename = self.activeDirName+'\\'+filename if useWd else filename

        try:
            self.__connection.deleteFile(self.__writableShare, filename)
        except smbconnection.SessionError, e:
            self.__log__(errorLevel, 'Cannot delete '+filename+': ',e)
            if errorLevel == LEVEL_CRITICAL:
                self.__del__(False)


    ######
    #
    #   Drops file <localFile> to <remoteName> in
    #   remote share.
    #
    def dropFile(self, localFile, remoteName, useWd=True, useLocalRef=True):

        try:
            self.__log__(LEVEL_INFODBG, 'Dropping file ' + remoteName)
            lpath = os.path.join(self.rootDir,localFile) if useLocalRef else localFile
            content = open(lpath , 'rb').read()
            self.writeFile(remoteName, content, 0, useWd)
            self.__log__(LEVEL_INFODBG, 'Dropped file ' + remoteName)
        except IOError:
            self.__log__(LEVEL_CRITICAL, 'File '+lpath+' was not found')
            self.__del__(False)

    ######
    #
    #   Gets file <remoteName> to <localFile> from
    #   remote share.
    #
    def getFile(self, remoteName, localFile, useWd=True):

        try:
            lpath = os.path.join(self.rootDir,localFile)
            f = open(lpath, 'wb')
            content = self.readFile(remoteName, useWd)
            f.write(content)
            self.__log__(LEVEL_INFODBG, 'Retrieved file ' + remoteName)
        except IOError:
            self.__log__(LEVEL_CRITICAL, 'File '+lpath+' could not be created')
            self.__del__(False)


    '''
        By default, remote share is targeted by UNC path \\REMOTE\SHARE-NAME$\
        CMD.EXE /C commands can be specified a working directory but UNC Path do not work
        Trick is to allocate a network drive LETTER: to \\REMOTE\SHARE-NAME$\ and to use LETTER:\ as CWD
    '''
    ######
    #
    #   Search for unallocated network drive
    #
    def setNet(self):

        for letter in [chr(i) for i in range(ord('A'), ord('Z')+1)]:
            out = self.execCommand('net use %s: %s 2>&1' % (letter, self.getWritablePath()))
            if out.find('85')==-1:
                self.__log__(LEVEL_INFODBG, 'Using network drive %s:' % letter)
                self.__netLetter = letter
                return letter+':'

        self.__log__(LEVEL_CRITICAL, 'Cannot find suitable network drive')
        self.__del__(False)

    ######
    #
    #   Deallocated network drive
    #
    def unsetNet(self):
        out = self.execCommand('net use %s: /Delete' % self.__netLetter)
        self.__log__(LEVEL_INFODBG, 'Net unuse: '+out[:-2])

if __name__ == '__main__':
    RemoteCmd.setDebugLevel(logging.INFO)
