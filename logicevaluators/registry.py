#!/usr/bin/python

import template

class Evaluator(template.EvaluatorInterface):

	evalList = ['KeyPath', 'ValueName']

	def __init__(self, iocTree, remoteCommand, wd, keepFiles, confidential, dirname):
		template.EvaluatorInterface.__init__(self, iocTree, remoteCommand, wd, keepFiles, confidential, dirname)
		
		self.setEvaluatorParams(evalList=Evaluator.evalList, name='registry', ext='bat')