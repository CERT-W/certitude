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

LOCAL_ANALYSIS_DIR = 'components\\iocscan\\resources\\localanalysis'
FORMAT = logging.Formatter('%(asctime)-15s\t%(name)s\t%(levelname)s\t%(message)s')
sh = logging.StreamHandler()
sh.setFormatter(FORMAT)

logger = logging.getLogger('FlatEval')
logger.addHandler(sh)

# Interface for evaluators
class EvaluatorInterface:

    # Debug level
    @staticmethod
    def setDebugLevel(level):
        logger.setLevel(level)

    # Init stuff
    def __init__(self, logger, ioc, remoteCommand, wd, keepFiles, confidential, dirname):

        self.__ioc = ioc
        self.__remoteCommand = remoteCommand
        self.__wd = wd
        self.__initFiles = {}
        self.__dbname = ''
        self.__bypass = False
        self.__keepFiles = keepFiles
        self.__tableName = '<unknown>'
        self.__confidential = confidential
        self.dirname = dirname
        self.logger = logger

    #############
    #
    #    Creates init files to be used
    #    Needs a list of existing files (within the current context)
    #    so that the same file is not created twice
    #    Can use old existing files
    #
    def createInitFiles(self, existingFiles, useOld = False):
        newFiles = []

        for initFile, initCommands in self.__initFiles.items():
            if initFile not in existingFiles and ((not useOld) or (not self.__remoteCommand.fileExists(initFile))):
                newFiles.append(initFile)
                for no, cmd in initCommands.items():
                    self.__remoteCommand.execCommand(cmd, self.__wd)

        return newFiles

    def getIOC(self):
        return self.__ioc

    def getWD(self):
        return self.__wd

    def getRemoteCommand(self):
        return self.__remoteCommand

    ############
    #
    #    Sets the private params from the child
    #
    def setEvaluatorParams(self, **kwargs):

        if not 'name' in kwargs.keys():
            self.log('No name specified for evaluator', logging.ERROR)
            return

        if not 'command' in kwargs.keys():
            self.log('No command specified for evaluator', logging.ERROR)
            return

        if not 'evalList' in kwargs.keys():
            self.log('No evaluation list specified for evaluator', logging.ERROR)
            return

        name = kwargs['name']
        command = kwargs['command']
        self.__evalList = [e.lower() for e in kwargs['evalList']]

        self.__tableName = name
        self.__dbName = '%s.db' % name

        getCmd = 'launch.bat %(command)s' % {'command':command}

        # CData collection
        self.__initFiles = {
            self.__dbName : {
                0 : 'del %(name)s' % {'name':self.__dbName},                                            # Delete old DB if present
                1 : '%(cmd)s %(name)s.list' % {'name':name, 'cmd':getCmd},                              # Collect data into <name>.list
                2 : 'type %(name)s.sql | sqlite3 %(dbName)s' % {'name':name, 'dbName':self.__dbName},   # Insert data in empty database
                3 : 'del %(name)s.list %(name)s.list.err' % {'name':name},                              # Remove <name>.list plain file
            }
        }

        # Well keep it if you have too
        if self.__keepFiles  and not  self.__confidential:
            del self.__initFiles[self.__dbName][3]


    #######
    #
    #    Eval the atomic IOC presence
    #
    def eval(self, valueFile):

        if self.__bypass:
            return evltResult.UNDEF

        # private attribute for child class
        ioc = self.getIOC()
        rc = self.getRemoteCommand()
        wd = self.getWD()

        select = ioc.select.replace('%s/'%ioc.document, '')

        self.log('IOC : %s' % (ioc), logging.DEBUG)

        # Hey, I don't know how to search for that
        if (ioc.search.lower() not in self.__evalList)\
                or (ioc.condition not in conditionList.keys()):
            self.log('%s/%s is not in evaluation list' % (ioc.search, ioc.condition), logging.WARNING)
            return (evltResult.UNDEF, None)

        if select and select.lower() not in self.__evalList:
            self.log('Could not select %s (not in evaluation list)' % (ioc.select), logging.WARNING)
            select = ''

        category = ioc.search.replace('%s/' % ioc.document, '')
        conditionTerm = conditionList[ioc.condition]

        # Escape '\' not using REGEX
        condition =  conditionTerm % self.escapeValue(ioc.value) if ioc.condition != 'regex' else conditionTerm % ioc.value

        # Craft query
        # > selecting count by default, otherwise selecting the user defined element
        # SELECT COUNT *  FROM <table> WHERE <index> LIKE <value> (default example)
        # SELECT FilePath FROM <table> WHERE <index> LIKE <value> (user defined example)
        querySelect = 'COUNT(*)' if not select else select
        queryStart = 'SELECT `%s` FROM %s WHERE ' % (querySelect, self.__tableName)
        queryVariable = '`%(index)s` %(clause)s' % {'index' : category, 'clause': (condition)}
        queryEnd = ';' if not select else ' UNION SELECT CHAR(1);'
        query = queryStart + queryVariable + queryEnd

        # Load PCRE for REGEX support
        loadext = 'SELECT load_extension("pcre.so");\n'

        queryContent = query

        res = ''
        retryCount = 15

        # Sometimes, queries may return "" (empty result)
        # Happens randomly, so just retry until it does not happen anymore
        while res=='' and retryCount > 0:
            self.log('query=%s' % query, logging.DEBUG)

            f = open(valueFile, 'w')
            f.write(loadext)
            f.write(queryContent)
            f.close()

            if self.__confidential:
                # Local SQLITE3 instance
                sqlite3loc = os.path.join(LOCAL_ANALYSIS_DIR, 'sqlite3.exe')
                dbloc = os.path.join(self.dirname, self.__dbName)
                localcommand = 'type "%s" | "%s" "%s"' % (valueFile, sqlite3loc, dbloc)
                res = os.popen(localcommand).read().replace('\r','').replace('\n','')
            else:
                rc.dropFile(valueFile, 'query.sql', True, False)
                res = rc.execCommand('type query.sql | sqlite3 %s' % self.__dbName, wd)
                rc.deleteFile('query.sql')

            self.log('query returned "%s"' % res, logging.DEBUG)

            retryCount -= 1

        ret = evltResult.TRUE
        if res == '':
            ret = evltResult.UNDEF
        elif res == '0' or res == '\x01':
            ret = evltResult.FALSE

        resData = res.splitlines()[1:] if select else None

        return (ret, resData)

    # Escapes the value
    def escapeValue(self, value):

        ret = value

        for rep in PCREplace:
            old, new = rep
            ret = ret.replace(old, new)

        return ret

    # No need for description...
    def log(self, m, level=logging.INFO):
        self.logger.log(level, 'FlatEval\t%s: %s' % (self.__tableName, m))

        if level>=logging.ERROR:
            self.__bypass = True

        if level>=logging.CRITICAL:
            sys.exit(1)

