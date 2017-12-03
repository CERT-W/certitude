#!/usr/bin/env python
# -*- coding: UTF-8 -*-
'''
    CERTitude: the seeker of IOC
    Copyright (c) 2017 CERT-W
    
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

import logging
import os
import sys
import tarfile

from helpers.helpers import threadname
import result as evltResult

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

LOCAL_ANALYSIS_DIR = 'components\\scanner\\resources\\localanalysis'
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
    def __init__(self, logger, ioc, remoteCommand, keepFiles, confidential, dirname):

        self.__ioc = ioc
        self.__remoteCommand = remoteCommand
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
                    self.__remoteCommand.execute(cmd, True)

        return newFiles

    def getIOC(self):
        return self.__ioc
        

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
    def eval(self, valueFile, iocList = None):
        if iocList is not None:
            return self.eval_list(valueFile, iocList)
        if self.getIOC() is None:
            return AttributeError

        if self.__bypass:
            return evltResult.UNDEF

        # private attribute for child class
        ioc = self.getIOC()
        rc = self.getRemoteCommand()

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
        querySelect = 'COUNT(*)' if not select else ('`%s`' % select)
        queryStart = 'SELECT %s FROM %s WHERE ' % (querySelect, self.__tableName)
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
                rc.dropFile(valueFile, 'query.sql', False)
                res = rc.execute('type query.sql | sqlite3 %s' % self.__dbName, True)
                rc.deleteFile('query.sql')

            self.log('query returned "%s"' % res, logging.DEBUG)

            retryCount -= 1

        ret = evltResult.TRUE
        if res == '':
            ret = evltResult.UNDEF
        elif res == '0' or res == '\x01':
            ret = evltResult.FALSE

        resData = res.splitlines()[1:] if select else None

        return (evltResult._str(ret), resData)

    #######
    #
    #    Eval an IOC list from the same category
    #
    def eval_list(self, value_file, ioc_list):

        if self.__bypass:
            return evltResult.UNDEF

        # private attribute for child class
        rc = self.getRemoteCommand()
        useWorkingDirectory = True

        result = {}

        ioc_list = self.filter_ioc_list(ioc_list)
        
        if len(ioc_list)==0:
            return result
        
        file_name, file_content = self.file_from_ioc_list(ioc_list)
        self.log('Loading file %s' % file_name, logging.DEBUG)

        with open(value_file, 'w') as f:
            f.write(file_content)

        if self.__confidential:
            raise NotImplementedError
            # Local SQLITE3 instance
            # TODO: do it
            # sqlite3loc = os.path.join(LOCAL_ANALYSIS_DIR, 'sqlite3.exe')
            # dbloc = os.path.join(self.dirname, self.__dbName)
            # localcommand = 'type "%s" | "%s" "%s"' % (value_file, sqlite3loc, dbloc)
            # res = os.popen(localcommand).read().replace('\r', '').replace('\n', '')
        else:
            rc.dropFile(value_file, file_name, False)
            file_identifier = '%s.%s' % (threadname, ioc_list[0].document.lower())

            results_filename = '%s.tar.gz' % (file_identifier)

            # self.log('Running the sql file %s' % file_name, logging.DEBUG)
            rc.execute('type %s | sqlite3 %s' % (file_name, self.__dbName), useWorkingDirectory)

            # self.log('Compressing results from %s' % file_identifier, logging.DEBUG)
            rc.execute('getresults.bat %s' % (file_identifier), useWorkingDirectory)

            # self.log('Downloading results from %s' % results_filename, logging.DEBUG)
            # TODO: find a clean way to get the localanalysis directory
            extract_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), 'resources','localanalysis')
            rc.getFile(results_filename, os.path.join(extract_dir, results_filename))

            rc.deleteFile(results_filename)

            self.log('Extracting results from %s' % os.path.join(extract_dir, results_filename), logging.DEBUG)
            tarname = os.path.join(extract_dir, results_filename)
            tar = tarfile.open(tarname, 'r:gz')
            # 'r|gz' might be used for better perf & stream-mode reading ?

            self.log('Found %s' % tar.getnames(), logging.DEBUG)

            for member in tar.getmembers():
                f = tar.extractfile(member)

                tmp_data = f.read()
                tmp_id = member.name.split('.')[2]
                tmp_db_ioc_id = member.name.split('.')[3]

                ret = evltResult.TRUE
                res_data = None

                if tmp_data == '':
                    ret = evltResult.UNDEF
                elif tmp_data == '0\n' or tmp_data == '\x01\n':
                    ret = evltResult.FALSE
                elif tmp_data[:1] == '\x01':
                    res_data = [e.decode(sys.stdout.encoding) for e in tmp_data.splitlines()[1:]]

                result[tmp_id] = {'res': evltResult._str(ret), 'iocid':tmp_db_ioc_id, 'data': res_data}

            tar.close()
            
            if not self.__keepFiles:
                os.remove(tarname)

        return result


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


    def filter_ioc_list(self, ioc_list):
        return [ioc for ioc in ioc_list if \
                (ioc.search.lower() in self.__evalList) and \
                (ioc.condition in conditionList.keys())]

    def file_from_ioc_list(self, ioc_list):
        """
        Generate file names and their contents from an IOC dictionary
        :return: a dictionary with file names as keys and file contents as values
        """
        result_name = '%s.%s.sql' % (threadname, ioc_list[0].document.lower())
        result_file = 'SELECT load_extension("pcre.so");\n'

        for ioc in ioc_list:
            # loggingiocscan.debug('IOC parsing: checking IOC "%s"' % (ioc_id))
            result_file += self.query_from_ioc(ioc)

        return result_name, result_file

    def query_from_ioc(self, ioc):
        select = ioc.select.replace('%s/' % ioc.document, '')

        # Hey, I don't know how to search for that
        if (ioc.search.lower() not in self.__evalList) \
                or (ioc.condition not in conditionList.keys()):
            print '%s/%s is not in evaluation list' % (ioc.search, ioc.condition)
            return ''

        if select and select.lower() not in self.__evalList:
            print 'Could not select %s (not in evaluation list)' % (ioc.select)
            select = ''

        category = ioc.search.replace('%s/' % ioc.document, '')
        conditionTerm = conditionList[ioc.condition]

        # Escape '\' not using REGEX
        condition = conditionTerm % self.escapeValue(
            ioc.value) if ioc.condition != 'regex' else conditionTerm % ioc.value

        # Craft query
        # > selecting count by default, otherwise selecting the user defined element
        # SELECT COUNT *  FROM <table> WHERE <index> LIKE <value> (default example)
        # SELECT FilePath FROM <table> WHERE <index> LIKE <value> (user defined select)
        querySelect = 'COUNT(*)' if not select else ('`%s`' % select)
        queryStart = 'SELECT %s FROM %s WHERE ' % (querySelect, self.__tableName)
        queryVariable = '`%(index)s` %(clause)s' % {'index': category, 'clause': (condition)}
        queryEnd = ';' if not select else ' UNION SELECT CHAR(1);'
        query = queryStart + queryVariable + queryEnd

        filename = '%s.%s.%s.%s.res' % (threadname, ioc.document.lower(), ioc.id, ioc.db_ioc_id)
        output = '.output "%s"' % (filename)

        res = output + '\n' + query + '\n'

        return res