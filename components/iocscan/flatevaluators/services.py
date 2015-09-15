#!/usr/bin/python

import template

class Evaluator(template.EvaluatorInterface):

    evalList = ['descriptiveName', 'mode', 'path', 'pathmd5sum', 'status', 'name']

    def __init__(self, logger, ioc, remoteCommand, wd, keepFiles, confidential, dirname):
        template.EvaluatorInterface.__init__(self, logger, ioc, remoteCommand, wd, keepFiles, confidential, dirname)
        
        self.setEvaluatorParams(evalList=Evaluator.evalList, name='services', command='collector getservices')