#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import components.scanner.flatevaluators.result as FlatEvltResult
import components.scanner.logicevaluators.result as LogicEvltResult

flatModuleList = [('FileItem','files_hash'),]

logicModuleList = []

flatEvaluatorList = {}
logicEvaluatorList = {}

for document, module in flatModuleList:
    flatEvaluatorList[document] = getattr(__import__('components.scanner.flatevaluators.%s' % module, fromlist = ['Evaluator']), 'Evaluator')

for document, module in logicModuleList:
    logicEvaluatorList[document] = getattr(__import__('components.scanner.logicevaluators.%s' % module, fromlist = ['Evaluator']), 'Evaluator')