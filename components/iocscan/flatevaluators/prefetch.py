#!/usr/bin/python

import template

class Evaluator(template.EvaluatorInterface):

    evalList = ['PrefetchHash', 'ApplicationFileName', 'ReportedSizeInBytes', 'SizeInBytes', 'TimesExecuted', 'FullPath']

    def __init__(self, logger, ioc, remoteCommand, wd, keepFiles, confidential, dirname):
        template.EvaluatorInterface.__init__(self, logger, ioc, remoteCommand, wd, keepFiles, confidential, dirname)
        
        self.setEvaluatorParams(evalList=Evaluator.evalList, name='prefetch', command='collector getprefetch')