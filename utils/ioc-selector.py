#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import re
import xml.etree.ElementTree as ET


selectors = {'ServiceItem': ['descriptiveName', 'mode', 'path', 'pathmd5sum', 'status', 'name'],
             'RegistryItem': ['KeyPath', 'ValueName'],
             'FileItem': ['FilePath', 'FullPath', 'FileExtension', 'FileName'],
             'ArpEntryItem': ['Interface', 'IPv4Address', 'PhysicalAddress', 'CacheType'],
             'DnsEntryItem': ['RecordName', 'RecordType', 'TimeToLive', 'DataLength', 'RecordData/Host',
                              'RecordData/IPv4Address'],
             'PortItem': ['protocol', 'localIP', 'localPort', 'remoteIP', 'remotePort', 'state', 'pid'],
             'PrefetchItem': ['PrefetchHash', 'ApplicationFileName', 'ReportedSizeInBytes', 'SizeInBytes',
                              'TimesExecuted', 'FullPath'],
             'ProcessItem': ['pid', 'parentpid', 'UserSID', 'Username', 'name', 'path', 'HandleList/Handle/Type', 'HandleList/Handle/Name'],
             'MemoryItem': ['pid', 'parentpid', 'name', 'page_addr', 'page_size', 'access_read', 'access_write',
                            'access_execute', 'access_copy_on_write']
             }

def multiprompt(options, all=False):
    regex = re.compile('(\d+|\*)' if all else '(\d)')
    for counter, opt in enumerate(options):
        print '({})\t{}'.format(counter + 1, opt)

    if all:
        print '(*)\tAll of them'

    user_input = raw_input('> ')

    if not regex.search(user_input):
        print '\n[>] Please enter a valid value.'
        return multiprompt(options)

    return user_input if user_input == '*' else int(user_input) - 1

def setSelectAttribute(items, choosenItem, choosenSelector):
    context = items[choosenItem].find('Context')
    document = context.get('document')
    context.set('select', '{}/{}'.format(document, selectors[document][choosenSelector]))


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print 'Usage : python ioc-selector.py [ioc path]'
        exit(1)

    try :
        tree = ET.parse(sys.argv[1])
    except IOError:
        print 'Your IOC file was not found.'
        exit(1)

    # Stripping IOC namespaces
    for el in tree.getroot().iter():
        if '}' in el.tag:
            el.tag = el.tag.split('}', 1)[1]
    root = tree.getroot()

    # Getting all indicator items elements
    items = root.findall('.//IndicatorItem')

    itemsList = []
    for i in items:
        itemsList.append('{} {} {}'.format(i.find('Context').get('search'), i.get('condition'), i.find('Content').text))

    print '[>] Which indicator item would you like to edit?'
    choice = multiprompt(itemsList, True)

    print '\n[>] Which attribute would you like to select?'

    if choice == '*':
        print '[!] All the indicators will get the same \'select\' attribute.'
        document = items[0].find('Context').get('document')
        selec = multiprompt(selectors[document])

        for nb in range(len(items)):
            setSelectAttribute(items, nb, selec)
    else:
        document = items[choice].find('Context').get('document')
        selec = multiprompt(selectors[document])
        setSelectAttribute(items, choice, selec)

    try:
        filename = sys.argv[1] + '-select'
        tree.write(filename)

        print '[>] File successfully saved as ' + filename
    except Exception as e:
        print '[X] Something happened' + str(e)


