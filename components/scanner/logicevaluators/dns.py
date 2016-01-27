#!/usr/bin/python

import template

class Evaluator(template.EvaluatorInterface):

	evalList = ['RecordName', 'RecordType', 'TimeToLive', 'DataLength', 'RecordData/Host', 'RecordData/IPv4Address']

	def __init__(self, iocTree, remoteCommand, wd, keepFiles, confidential, dirname):
		template.EvaluatorInterface.__init__(self, iocTree, remoteCommand, wd, keepFiles, confidential, dirname)
		
		self.setEvaluatorParams(evalList=Evaluator.evalList, name='dns', ext='sh')