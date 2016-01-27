#!/usr/bin/env python
# -*- coding: UTF-8 -*-

"""
This Script Was Added In November 2015 By :
Valentin RESSEGUIER - Consultant at Randco (http://www.randco.fr)
"""

import sqlite3, base64

conn = sqlite3.connect('files.db')
conn.text_factory = str
c = conn.cursor()

database = c.execute('SELECT "StringList/string", "FullPath" FROM files')

EditScript = ""

for row in database:
	basedRow = row[0]
	if basedRow != "":
		if basedRow == "U3RyaW5nczIgdjEuMgogIENvcHlyaWdodCCpIDIwMTIsIEdlb2ZmIE1jRG9uYWxkCiAgaHR0cDovL3d3dy5zcGxpdC1jb2RlLmNvbS8KCg==":
			unbasedRow = ""
		else:
			try:
				unbasedRow = base64.b64decode(basedRow)
			except:
				unbasedRow = ""

		fullPath = row[1]
		EditScript += 'UPDATE files SET "StringList/string"="'+unbasedRow+'" WHERE "FullPath"="'+fullPath+'";'

try:
	c.executescript(EditScript)
except:
	pass

conn.commit()
conn.close()