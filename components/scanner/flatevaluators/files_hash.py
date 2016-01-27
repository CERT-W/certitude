#!/usr/bin/python

import template

class Evaluator(template.EvaluatorInterface):

    evalList = ['FilePath', 'Md5Sum', 'Sha1Sum', 'Sha256Sum']

    def __init__(self, logger, ioc, remoteCommand, wd, keepFiles, confidential, dirname):
        template.EvaluatorInterface.__init__(self, logger, ioc, remoteCommand, wd, keepFiles, confidential, dirname)

        self.setEvaluatorParams(evalList=Evaluator.evalList, name='files_hash', command='collector getfileshash')