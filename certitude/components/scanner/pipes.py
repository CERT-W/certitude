from threading import Thread, Lock
from impacket.smbconnection import *
import cmd

lock = Lock()

class Pipes(Thread):
    def __init__(self, remoteHost, dport, credentials, pipe, permissions, share=None):
        Thread.__init__(self)
        self.server = 0
        self.remoteHost = remoteHost
        self.credentials = credentials
        self.tid = 0
        self.fid = 0
        self.share = share
        self.port = dport
        self.pipe = pipe
        self.permissions = permissions
        self.daemon = True
        self.__run = False

    def connectPipe(self):
        try:
            lock.acquire()
            global dialect
            self.server = SMBConnection('*SMBSERVER', self.remoteHost, sess_port = self.port, preferredDialect = SMB2_DIALECT_21)
            user, passwd, domain, lm, nt = self.credentials[:5]
            self.server.login(user, passwd, domain, lm, nt)
            lock.release()
            self.tid = self.server.connectTree('IPC$')

            self.server.waitNamedPipe(self.tid, self.pipe)
            self.fid = self.server.openFile(self.tid,self.pipe,self.permissions, creationOption = 0x40, fileAttributes = 0x80)
            self.server.setTimeout(10000000)
        except Exception, e:
            raise

    def run(self):

        self.connectPipe()
        self.__run = True

        while self.__run:
            self.run_loop()


    def stop(self):
        self.__run = False
        s = self.server.getSMBServer().get_socket()
        s.shutdown(2)
        s.close()

    def run_loop(self):
        pass


class RemoteStdOutPipe(Pipes):

    def __init__(self, remoteHost, dport, credentials, pipe, permissions):
        Pipes.__init__(self, remoteHost, dport, credentials, pipe, permissions)
        self.out = ''

    def run_loop(self):

        try:
            ans = self.server.readFile(self.tid,self.fid, 0, 1024)
        except Exception, e:
            pass
        else:
            try:
                global LastDataSent
                if ans != LastDataSent:
                    #sys.stdout.write(ans)
                    #sys.stdout.flush()
                    self.out += ans

                else:
                    # Don't echo what I sent, and clear it up
                    LastDataSent = ''
                # Just in case this got out of sync, i'm cleaning it up if there are more than 10 chars,
                # it will give false positives tho.. we should find a better way to handle this.
                if LastDataSent > 10:
                    LastDataSent = ''
            except NameError, e:
                self.out += ans


class RemoteStdErrPipe(Pipes):
    def __init__(self, remoteHost, dport, credentials, pipe, permissions):
        Pipes.__init__(self, remoteHost, dport, credentials, pipe, permissions)

    def run_loop(self):

        try:
            ans = self.server.readFile(self.tid,self.fid, 0, 1024)
        except Exception, e:
            pass
        else:
            try:
                sys.stderr.write(str(ans))
                sys.stderr.flush()
            except:
                pass

class RemoteShell(cmd.Cmd):
    def __init__(self, server, port, credentials, tid, fid, share):
        cmd.Cmd.__init__(self, False)
        self.prompt = '\x08'
        self.server = server
        self.transferClient = None
        self.tid = tid
        self.fid = fid
        self.credentials = credentials
        self.share = share
        self.port = port
        self.intro = ''

    def connect_transferClient(self):
        self.transferClient = SMBConnection('*SMBSERVER', self.server.getRemoteHost(), sess_port = self.port, preferredDialect = SMB_DIALECT)
        #self.transferClient = SMBConnection('*SMBSERVER', self.server.getRemoteHost(), sess_port = self.port, preferredDialect = dialect)
        user, passwd, domain, lm, nt = self.credentials[:5]
        self.transferClient.login(user, passwd, domain, lm, nt)

    def do_help(self, line):
        print """
 lcd {path}                 - changes the current local directory to {path}
 exit                       - terminates the server process (and this session)
 put {src_file, dst_path}   - uploads a local file to the dst_path RELATIVE to the connected share (%s)
 get {file}                 - downloads pathname RELATIVE to the connected share (%s) to the current local dir
 ! {cmd}                    - executes a local shell cmd
""" % (self.share, self.share)
        self.send_data('\r\n', False)

    def do_shell(self, s):
        os.system(s)
        self.send_data('\r\n')

    def do_get(self, src_path):
        try:
            if self.transferClient is None:
                self.connect_transferClient()

            import ntpath
            filename = ntpath.basename(src_path)
            fh = open(filename,'wb')
            ##print "[*] Downloading %s\%s" % (self.share, src_path)
            self.transferClient.getFile(self.share, src_path, fh.write)
            fh.close()
        except Exception, e:
            #print e
            pass

        self.send_data('\r\n')

    def do_put(self, s):
        try:
            if self.transferClient is None:
                self.connect_transferClient()
            params = s.split(' ')
            if len(params) > 1:
                src_path = params[0]
                dst_path = params[1]
            elif len(params) == 1:
                src_path = params[0]
                dst_path = '/'

            src_file = os.path.basename(src_path)
            fh = open(src_path, 'rb')
            f = dst_path + '/' + src_file
            pathname = string.replace(f,'/','\\')
            ##print "[*] Uploading %s to %s\%s" % (src_file, self.share, dst_path)
            self.transferClient.putFile(self.share, pathname, fh.read)
            fh.close()
        except Exception, e:
            #print e
            pass

        self.send_data('\r\n')


    def do_lcd(self, s):
        if s == '':
            pass
            #print os.getcwd()
        else:
            os.chdir(s)
        self.send_data('\r\n')

    def emptyline(self):
        self.send_data('\r\n')
        return

    def default(self, line):
        self.send_data(line+'\r\n')

    def send_data(self, data, hideOutput = True):
        if hideOutput is True:
            global LastDataSent
            LastDataSent = data
        else:
            LastDataSent = ''
        self.server.writeFile(self.tid, self.fid, data)


class RemoteStdInPipe(Pipes):
    def __init__(self, remoteHost, dport, credentials, pipe, permissions, share=None):
        Pipes.__init__(self, remoteHost, dport, credentials, pipe, permissions, share=None)

    def run_loop(self):
        #self.shell = RemoteShell(self.server, self.port, self.credentials, self.tid, self.fid, self.share)
        #self.shell.cmdloop()
        pass
