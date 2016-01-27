#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
CERTitude: The Seeker of IOC
CERT-Solucom cert@solucom.fr
"""
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
			iocscan_queue.demarrer_scanner(batch = args.batch_name)
		elif args.component == ['hashscan']:
			from components.scanner import hashscan_queue
			hashscan_queue.demarrer_scanner(batch = args.batch_name)
		else:
			print 'Error: specify the component to run'
			print parser.print_help()
	else:
		print parser.print_help()


if __name__ == '__main__':
	main()
