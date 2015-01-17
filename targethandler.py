from random import random as rand
from threading import Thread, Lock
import remotecmd, time, logging, os, sys
import openioc.ioc as IOC

# Evaluators

import flatevaluators.result as FlatEvltResult
import flatevaluators.services
import flatevaluators.registry
import flatevaluators.files
import flatevaluators.arp
import flatevaluators.dns
import flatevaluators.port
import flatevaluators.prefetch
import flatevaluators.process

import logicevaluators.result as LogicEvltResult
import logicevaluators.services
import logicevaluators.registry
import logicevaluators.files
import logicevaluators.arp
import logicevaluators.dns
import logicevaluators.port
import logicevaluators.prefetch
import logicevaluators.process

flatEvaluatorList = {
	'ServiceItem': flatevaluators.services.Evaluator,
	'RegistryItem': flatevaluators.registry.Evaluator,
	'FileItem': flatevaluators.files.Evaluator,
	'ArpEntryItem': flatevaluators.arp.Evaluator,
	'DnsEntryItem': flatevaluators.dns.Evaluator,
	'PortItem': flatevaluators.port.Evaluator,
	'PrefetchItem': flatevaluators.prefetch.Evaluator,
	'ProcessItem': flatevaluators.process.Evaluator,
}

logicEvaluatorList = {
	'ServiceItem': logicevaluators.services.Evaluator,
	'RegistryItem': logicevaluators.registry.Evaluator,
	'FileItem': logicevaluators.files.Evaluator,
	'ArpEntryItem': logicevaluators.arp.Evaluator,
	'DnsEntryItem': logicevaluators.dns.Evaluator,
	'PortItem': logicevaluators.port.Evaluator,
	'PrefetchItem': logicevaluators.prefetch.Evaluator,
	'ProcessItem': logicevaluators.process.Evaluator,
}

DR_PLUS_DIR = 'DR_PLUS'

# File droplist

dropList = [
	[os.path.join('resources','gzip.exe'), 'gzip.exe'],
	[os.path.join('resources','tar.exe'), 'tar.exe'],
	[os.path.join('resources','binaries.tar.gz'), 'binaries.tar.gz'],
	[os.path.join('resources','scripts.tar.gz'), 'scripts.tar.gz'],
	[os.path.join('resources','rmtar.bat'), 'rmtar.bat'],
]


# Commands executed at startup (after files being dropped)
StartCommandList = [
	'gzip -d -k binaries.tar.gz',
	'gzip -d -k scripts.tar.gz',
	'tar xf binaries.tar',
	'tar xf scripts.tar',
]

# Commands executed at the end (after files being dropped)
# 0 = do not execute if keep files
EndCommandList = [
	['rmtar.bat scripts.tar',0],
	['rmtar.bat binaries.tar',0],
]

def getClass(obj):
	return str(obj.__class__).split('.')[-1]

	
######
#
#	Thread inheriting class
#	Handles a single target and perform the analysis
#
class TargetHandler(Thread):

	# Init stuff
	def __init__(self, ip, login, password, domain, p, iocTrees, rootDir, confidential, keepFiles):
		Thread.__init__(self)
		
		self.__run = False
		self.__name = login+'@'+ip
		self.iocTrees = iocTrees
		self.finished = False
		self.result = None
		self.loggerName = 'CERTitude'
		self.keepFiles = keepFiles
		self.confidential = confidential
		self.dirname = None
		self.rootDir = rootDir
		
		self.__args = [ip, login, password, domain, p]
		
	
	# Let it run !
	def run(self):
				
		ip, login, password, domain, priority = self.__args
				
		# Try to connect to the target
		try:
			self.remoteCmd = remotecmd.RemoteCmd(ip, login, password, debugLevel=logging.getLogger(self.loggerName).getEffectiveLevel(), domain=domain, priority=priority, rootDir=self.rootDir)
			self.isOk = True
			self.log('Le handler "%s" a ete contacte avec succes' % self.getName())
		except Exception, e:
			self.log('Le handler "%s" n\'a pas pu etre contacte (erreur %s)' % (self.getName(),str(e)), logging.WARNING)
			self.isOk = False
			self.finished = True
			self.result = None
			return	# Too bad, stop here :/
				
		self.log('Demarrage de l\'analyse')
		
		
		if self.confidential:
			self.dirname = os.path.join(self.rootDir, DR_PLUS_DIR, self.__name)
			if not os.path.isdir(self.dirname):
				os.popen('mkdir "'+self.dirname+'"')
		
		# Sets the remote network drive
		drive = self.remoteCmd.setNet()

		# Drop files
		for local, remote in dropList:
			lpath = os.path.join(self.rootDir, local)
			
			if self.remoteCmd.fileExists(remote):
				self.remoteCmd.deleteFile(remote)
			self.remoteCmd.dropFile(lpath, remote)
		
		# Start commands
		for command in StartCommandList:
			self.remoteCmd.execCommand(command, drive)
		
		# <analysis>
		result = self.performAnalysis(drive)
		# </analysis>
		
		# End commands
		for command in EndCommandList:
			if (not self.keepFiles or self.confidential) or command[1]!=0:
				self.remoteCmd.execCommand(command[0], drive)
			
		# Delete dropped files
		if not self.keepFiles or self.confidential:
			for local, remote in dropList:
				self.remoteCmd.deleteFile(remote)
		
		# Unuse the network drive
		self.remoteCmd.unsetNet()		
		del self.remoteCmd
		
		self.log('L\'analyse est terminee')

		self.result = result
		self.finished = True
	
	# Yep, virtual class
	def performAnalysis(self, drive):
		raise NotImplementedError
				
	def getName(self):
		return self.__name
			
	def log(self, s, level = logging.INFO):
		logging.getLogger(self.loggerName).log(level, '%s %s' % (self.__name, s))
		

##########
#
#	Flat search
#	No intelligent analysis
#	Only output the atomic result of IOC presence
#
class FlatTargetHandler(TargetHandler):

	def performAnalysis(self, drive):
		# <analysis>
		
		result = {}
		initFilesPresent = []
		
		if not os.path.isdir('tmp'):
			os.popen('mkdir tmp')
		tmpFile = os.path.join('tmp', 'value'+str(rand())+str(rand())+str(rand())+'.tmp')
		
		for filename, tree in self.iocTrees.items():
			self.log('Recherche de l\'IOC '+filename)
			
			leaves = tree.getLeaves()

			# IOC Tree evaluation
			for uid, leaf in leaves.items():
				if uid not in result.keys():
					if leaf.document in flatEvaluatorList.keys():
					
						evlt = flatEvaluatorList[leaf.document](leaf, self.remoteCmd, drive,self.keepFiles, self.confidential, self.dirname)
						newFiles = evlt.createInitFiles(initFilesPresent)

						for newFile in newFiles:
							initFilesPresent.append(newFile)
							
							if self.confidential:
								self.remoteCmd.getFile(newFile, os.path.join(self.dirname, newFile))
							
							
						res = evlt.eval(tmpFile)

					else:
						self.log('Resultat mis a UNDEFINED pour '+leaf.document, logging.INFO)
						res = FlatEvltResult.UNDEF
	
					result[uid] = FlatEvltResult._str(res)
				
			self.log('La recherche de '+filename+' s\'est terminee')
		
		if not self.keepFiles or self.confidential:
			for remoteFile in initFilesPresent:
				self.remoteCmd.deleteFile(remoteFile, drive)
			
		os.popen('del "'+tmpFile+'"')
		
		return result

##########
#
#	Logic search
#	Intelligent analysis
#	Outputs the presence of the complete IOC
#
class LogicTargetHandler(TargetHandler):

	def performAnalysis(self, drive):
		# <analysis>
		
		result = {}
		initFilesPresent = []
		
		if not os.path.isdir('tmp'):
			os.popen('mkdir tmp')
		tmpFile = os.path.join('tmp', 'value'+str(rand())+str(rand())+str(rand())+'.tmp')
		
		
		for filename, tree in self.iocTrees.items():
			self.log('Recherche de l\'IOC '+filename)
			
			logicTree = IOC.IOC2LogicTree(tree)
			values = {}
			
			# IOC Trees evaluation
			for uid, leaf in logicTree.getLeaves().items():
				document = leaf.getDocuments()[0]
				
				evlt = logicEvaluatorList[document](leaf, self.remoteCmd, drive, self.keepFiles, self.confidential, self.dirname)
				newFiles = evlt.createInitFiles(initFilesPresent)

				for newFile in newFiles:
					initFilesPresent.append(newFile)
					
					if self.confidential:
						self.remoteCmd.getFile(newFile, os.path.join(self.dirname, newFile))
					
				values[uid] = evlt.eval(tmpFile)
			
			# Logic Tree evaluation, according to IOC Tree values
			result[filename] = str(logicTree.eval(values))
				
			self.log('La recherche de '+filename+' s\'est terminee')
		
		if not self.keepFiles:
			for remoteFile in initFilesPresent:
				self.remoteCmd.deleteFile(remoteFile, drive)
			
		os.popen('del "'+tmpFile+'"')
		
		return result
