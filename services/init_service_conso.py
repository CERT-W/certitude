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

from components.consolidation import conso
from helpers import log

class CERTitudeConsoService(win32serviceutil.ServiceFramework):
    _svc_name_ = "CERTitudeConso"
    _svc_display_name_ = "CERTitude service de consolidation"
    _svc_description_ = u"CERTitude, scanner réseau - service consolidant les tâches scannées en agrégeant les infos des référentiels"

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
        conso.demarrer_conso(self.hWaitStop)
        pass

if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(CERTitudeConsoService)
