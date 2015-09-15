#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
CERTitude: The Seeker of IOC
CERT-Solucom cert@solucom.fr
"""
import re
import win32serviceutil


def remove_then_install(serviceName):
    if serviceName and not re.match("^[0-9a-zA-Z\._]*$", serviceName):
        raise Exception('ERREUR CRITIQUE ! Nom du service non valide : ' + serviceName)
    service = eval(serviceName)
    print service
    try:
        win32serviceutil.RemoveService(service._svc_name_)
    except:
        pass
    win32serviceutil.InstallService(
        serviceName,
        getattr(service, '_svc_name_'),
        service._svc_display_name_
    )


import init_service_api
remove_then_install('init_service_api.CERTitudeAPIService')

import init_service_conso
remove_then_install('init_service_conso.CERTitudeConsoService')

import init_service_scan
remove_then_install('init_service_scan.CERTitudeScanService')
