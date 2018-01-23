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

import result as evltResult
import logging
import sys, os

PCREplace = [
				["\"", "\\\""],
			]

conditionList = {
	'is' : 'LIKE "%s"',
	'contains' : 'LIKE "%%%s%%"',
	'containsnot' : 'NOT LIKE "%%%s%%"',
	'isnot' : 'NOT LIKE "%s"',
	'regex' : 'REGEXP "%s"',
}

# logger

LOCAL_ANALYSIS_DIR = 'resources\\localanalysis'
FORMAT = logging.Formatter('%(asctime)-15s\t%(name)s\t%(levelname)s\t%(message)s')
sh = logging.StreamHandler()
sh.setFormatter(FORMAT)

logger = logging.getLogger('LogicEval')
logger.addHandler(sh)

# FUTURE
#
# param :
#	table_name
#	accepted_param

class EvaluatorInterface:

	# Debug level
	@staticmethod
	def setDebugLevel(level):
		logger.setLevel(level)

	# Init stuff
	def __init__(self, iocTree, remoteCommand, wd, keepFiles, confidential, dirname):
	
		self.__iocTree = iocTree
		self.__remoteCommand = remoteCommand
		self.__wd = wd
		self.__initFiles = {}
		self.__dbname = ''
		self.__tableName = '<unknown>'
		self.__bypass = False
		self.__keepFiles = keepFiles
		self.dirname = dirname
		self.__confidential = confidential

	#############
	#
	#	Creates init files to be used
	#	Needs a list of existing files (within the current context)
	#	so that the same file is not created twice
	#	Can use old existing files
	#
	def createInitFiles(self, existingFiles, useOld = False):
		newFiles = []
		
		if self.__bypass:
			return []
		
		for initFile, initCommands in self.__initFiles.items():
			if initFile not in existingFiles and ((not useOld) or (not self.__remoteCommand.fileExists(initFile))):
				newFiles.append(initFile)
				for no, cmd in initCommands.items():
					self.__remoteCommand.execCommand(cmd, self.__wd)
				
		return newFiles
	
	def getIOCTree(self):
		return self.__iocTree
		
	def getWD(self):
		return self.__wd
		
	def getRemoteCommand(self):
		return self.__remoteCommand
		
	############
	#
	#	Sets the private params from the child
	#
	def setEvaluatorParams(self, **kwargs):
	
		if not 'name' in kwargs.keys():
			self.log('No name specified for evaluator', logging.ERROR)
			return
			
		if not 'evalList' in kwargs.keys():
			self.log('No evaluation list specified for evaluator', logging.ERROR)
			return
			
		name = kwargs['name']
		self.__evalList = kwargs['evalList']
		ext = 'bat' if not 'ext' in kwargs.keys() else kwargs['ext']
	
		self.__tableName = name
		self.__dbName = '%s.db' % name
		
		if ext == 'bat':
			getCmd = 'get%(name)s.%(ext)s' % {'name':name, 'ext':ext}
		else:
			getCmd = 'bash get%(name)s.%(ext)s' % {'name':name, 'ext':ext}
		
		self.__initFiles = {
			self.__dbName : {
				0 : 'del %(name)s' % {'name':self.__dbName},											# del template.db
				1 : '%(cmd)s %(name)s.list' % {'name':name, 'cmd':getCmd},								# gettemplate.bat template.list
				2 : 'type %(name)s.sql | sqlite3 %(dbName)s' % {'name':name, 'dbName':self.__dbName},	# type template.sql | sqlite3 template.db
				3 : 'del %(name)s.list' % {'name':name},
			}
		}
		
		if self.__keepFiles and not  self.__confidential:
			del self.__initFiles[self.__dbName][3];
	
	def eval(self, valueFile):
	
		if self.__bypass:
			return evltResult.UNDEF
			
		iocTree = self.getIOCTree()
		rc = self.getRemoteCommand()
		wd = self.getWD()
		
		
		res = evltResult.FALSE
		
		queryStart = 'SELECT COUNT(*) FROM %s WHERE ' % (self.__tableName)
		queryVariable = iocTree.buildWhereClause(conditionList, self.escapeValue)
		queryEnd = ';'
		query = queryStart + queryVariable + queryEnd
		
		queryContent = query
		loadext = 'SELECT load_extension("pcre.so");\n'
		
		self.log('query=%s' % query, logging.DEBUG)
		
		f = open(valueFile, 'w')
		f.write(loadext)
		f.write(queryContent)
		f.close()
		
		if self.__confidential:
			sqlite3loc = os.path.join(LOCAL_ANALYSIS_DIR, 'sqlite3.exe')
			dbloc = os.path.join(self.dirname, self.__dbName)
			localcommand = 'type "%s" | "%s" "%s"' % (valueFile, sqlite3loc, dbloc)
			res = os.popen(localcommand).read().replace('\r','').replace('\n','')
		else:
			rc.dropFile(valueFile, 'query.sql')
			res = rc.execCommand('type query.sql | sqlite3 %s' % self.__dbName, wd)
			rc.deleteFile('query.sql')
		
		self.log('query returned "%s"' % res, logging.DEBUG)
		
		
		return evltResult.FALSE if res=='0' else evltResult.TRUE
		
	def escapeValue(self, value):
	
		ret = value
	
		for rep in PCREplace:
			old, new = rep
			ret = ret.replace(old, new)
			
		return ret
		
	def log(self, m, level=logging.INFO):
		logging.getLogger('FlatEval').log(level, '%s: %s' % (self.__tableName, m))
		
		if level>=logging.ERROR:
			self.__bypass = True

		if level>=logging.CRITICAL:
			sys.exit(1)
			
