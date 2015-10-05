#!/usr/bin/python

import template

class Evaluator(template.EvaluatorInterface):

    evalList = ['FilePath', 'FullPath', 'FileExtension', 'FileName']

    def __init__(self, logger, ioc, remoteCommand, wd, keepFiles, confidential, dirname):
        template.EvaluatorInterface.__init__(self, logger, ioc, remoteCommand, wd, keepFiles, confidential, dirname)

        self.setEvaluatorParams(evalList=Evaluator.evalList, name='files', command='collector getfiles')