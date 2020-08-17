"""

    Runs a flask server that accepts various requests related to
    AD queries

    compiling to service + install (in winpython cmd as admin):
        set PYTHONHOME=C:\python37\python-3.7.1.amd64\
	    set PYTHONPATH=C:\python37\python-3.7.1.amd64\Lib\
        pip install pyinstaller
        pyinstaller -F --hidden-import=win32timezone "AD query service.py"
        mkdir "c:\scripts"
        mkdir "c:\scripts\AD query service"
        copy "dist\AD query service.exe" "c:\scripts\AD query service\AD query service.exe"
        c:
        cd "c:\scripts\AD query service"
        "AD query service.exe" install

    testing:
        curl -s "http://localhost:9994/help"

"""

import servicemanager
import socket
import sys
import win32event
import win32service
import win32serviceutil
import datetime

from myapp import app

logfile = "C:\\scripts\\AD query service\\AD query service log.txt"
port = 9994

# Add a log entry + datetime
def log_entry(log_message):
	with open(logfile, 'a') as f:
		f.write(str(datetime.datetime.now()) + " : ")
		f.write(log_message + '\n')

class FlaskService(win32serviceutil.ServiceFramework):
    _svc_name_ = "AD query service"
    _svc_display_name_ = "AD query service"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        socket.setdefaulttimeout(10)

    def SvcStop(self):
        log_entry('SvcStop started')
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        self.ReportServiceStatus(win32service.SERVICE_STOPPED)
        log_entry('SvrStop finished')

    def SvcDoRun(self):
        log_entry('SvrDoRun started')
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                              servicemanager.PYS_SERVICE_STARTED,
                              (self._svc_name_,''))
        self.flaskmain()
        
    def flaskmain(self):
        log_entry('flaskmain() started')
        app.run(debug=False, host='0.0.0.0', port=port)
        log_entry('flaskmain() finished')


if __name__ == '__main__':
    log_entry("AD query service started")
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(FlaskService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(FlaskService)
    log_entry("AD query service stopped")