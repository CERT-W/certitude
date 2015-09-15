#!/usr/bin/python

import template

class Evaluator(template.EvaluatorInterface):

    evalList = ['pid', 'parentpid', 'name', 'page_addr', 'page_size', 'access_read', 'access_write', 'access_execute', 'access_copy_on_write']

    def __init__(self, logger, ioc, remoteCommand, wd, keepFiles, confidential, dirname):
        template.EvaluatorInterface.__init__(self, logger, ioc, remoteCommand, wd, keepFiles, confidential, dirname)
        
        self.setEvaluatorParams(evalList=Evaluator.evalList, name='memory', command='getmemory')
