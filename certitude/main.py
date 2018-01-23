#!/usr/bin/env python
# -*- coding: UTF-8 -*-
'''
    CERTitude: the seeker of IOC
    Copyright (c) 2016 CERT-W
    
    Contact: cert@wavestone.com
    Contributors: @iansus, @nervous, @fschwebel
    
    CERTitude is under licence GPL-2.0:
    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
'''

import argparse, sys

from helpers import log

parser = argparse.ArgumentParser(
	description='CERTitude, the modular Python scanner, network mapper and IOC Seeker'
)
parser.add_argument(
	'command',
	type=str,
	nargs=1,
	help="command to run ('init', 'run')"
)
parser.add_argument(
	'-c',
	'--component',
	type=str,
	default='0',
	nargs=1,
	help="component to run ('interface', 'iocscan')"
)
parser.add_argument(
	'-b',
	'--batch-name',
	type=str,
	help='[iocscan] Specify batch name'
)


log.init()


def main():
	args = parser.parse_args()

	if args.command == ['init']:
		from helpers import init
	elif args.command == ['run']:
		if args.component == ['interface']:
			from components.interface import web
			web.run_server()
		elif args.component == ['iocscan']:
			from components.scanner import iocscan_queue
			iocscan_queue.startScanner(batch = args.batch_name)
		elif args.component == ['hashscan']:
			from components.scanner import hashscan_queue
			hashscan_queue.startScanner(batch = args.batch_name)
		else:
			print 'Error: specify the component to run'
			print parser.print_help()
	else:
		print parser.print_help()


if __name__ == '__main__':
	main()
