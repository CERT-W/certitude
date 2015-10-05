#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import components.iocscan.flatevaluators.result as FlatEvltResult
import components.iocscan.logicevaluators.result as LogicEvltResult

flatModuleList = [('ServiceItem','services'),
                    ('RegistryItem','registry'),
                    ('FileItem','files'),
                    ('ArpEntryItem','arp'),
                    ('DnsEntryItem','dns'),
                    ('PortItem','port'),
                    ('PrefetchItem','prefetch'),
                    ('ProcessItem','process'),
                    ('MemoryItem','memory')]

logicModuleList = [('ServiceItem','services'),
                    ('RegistryItem','registry'),
                    ('FileItem','files'),
                    ('ArpEntryItem','arp'),
                    ('DnsEntryItem','dns'),
                    ('PortItem','port'),
                    ('PrefetchItem','prefetch'),
                    ('ProcessItem','process')]

flatEvaluatorList = {}
logicEvaluatorList = {}

for document, module in flatModuleList:
    flatEvaluatorList[document] = getattr(__import__('components.iocscan.flatevaluators.%s' % module, fromlist = ['Evaluator']), 'Evaluator')

for document, module in logicModuleList:
    logicEvaluatorList[document] = getattr(__import__('components.iocscan.logicevaluators.%s' % module, fromlist = ['Evaluator']), 'Evaluator')