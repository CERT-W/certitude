#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
CERTitude: The Seeker of IOC
CERT-Solucom cert@solucom.fr
"""
import argparse, sys

from helpers import log, verify_settings

parser = argparse.ArgumentParser(
    description='CERTitude, the modular Python scanner, network mapper and IOC Seeker'
)
parser.add_argument(
    'command',
    type=str,
    nargs=1,
    help="command to run ('init', 'service', 'run')"
)
parser.add_argument(
    '-c',
    '--component',
    type=str,
    default='0',
    nargs=1,
    help="component to run ('interface', 'discovery', 'iocscan', 'conso', 'note', 'visu')"
)
parser.add_argument(
    '-b',
    '--batch-name',
    type=str,
    help='[iocscan] Specify batch name'
)


log.init()

# Vérification de la conformité de la configuration
verify_settings.verify()


def main():
    args = parser.parse_args()

    if args.command == ['init']:
        from helpers import init
    elif args.command == ['service']:
        from services import init_services
    elif args.command == ['run']:
        if args.component == ['interface']:
            from components.interface import web
            web.run_server()
        elif args.component == ['discovery']:
            from components.discovery import discover_queue
            discover_queue.demarrer_scanner()
        elif args.component == ['iocscan']:
            from components.iocscan import iocscan_queue
            iocscan_queue.demarrer_scanner(batch = args.batch_name)
        elif args.component == ['conso']:
            from components.consolidation import conso
            conso.demarrer_conso()
        elif args.component == ['visu']:
            from components.visualisation import visu_graph
            visu_graph.graph()
        elif args.component == ['note']:
            from components.consolidation import note
            note.demarrer_note()
        else:
            print 'Error: specify the component to run'
            print parser.print_help()
    else:
        print parser.print_help()


if __name__ == '__main__':
    main()
