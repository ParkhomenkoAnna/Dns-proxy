import time


class Logging():
    def __init__(self, loglevel=None, logfile=None):
        self.logfile = logfile or open("/var/log/lastlog", 'a')
        self.loglevel = loglevel or 2
        return

    def critical(self, msg):
        self.logfile.write(time.strftime("%d/%b/%Y:%H:%M:%S %z "))
        self.logfile.write("CRITICAL:  " + msg + "\n")
        print(msg)

    def warning(self, msg):
        if self.loglevel >= 1:
            self.logfile.write(time.strftime("%d/%b/%Y:%H:%M:%S %z "))
            self.logfile.write("   WARNING: " + msg + "\n")
            print(msg)

    def info(self, msg):
        if self.loglevel >= 2:
            self.logfile.write(time.strftime("%d/%b/%Y:%H:%M:%S %z "))
            self.logfile.write("     INFO: " + msg + "\n")
