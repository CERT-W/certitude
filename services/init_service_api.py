#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
CERTitude: The Seeker of IOC
CERT-Solucom cert@solucom.fr
"""
import win32serviceutil
import win32service
import win32event
import servicemanager
import socket

from components.api import server
from helpers import log

class CERTitudeAPIService(win32serviceutil.ServiceFramework):
    _svc_name_ = "CERTitudeAPI"
    _svc_display_name_ = "CERTitude service pour l'API"
    _svc_description_ = u"CERTitude, scanner réseau - service proposant une API HTTP pour l'ajout de tâches dans la queue"

    def __init__(self,args):
        win32serviceutil.ServiceFramework.__init__(self,args)
        self.hWaitStop = win32event.CreateEvent(None,0,0,None)
        socket.setdefaulttimeout(60)

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                              servicemanager.PYS_SERVICE_STARTED,
                              (self._svc_name_,''))
        self.main()

    def main(self):
        log.init()
        server.demarrer_serveur(self.hWaitStop)
        pass

if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(CERTitudeAPIService)
