""" a module for log management """

import os
import sys
import time

# log levels
#
LOG_SILENT   = 0
LOG_CRITICAL = 1
LOG_ERROR    = 2
LOG_WARNING  = 3
LOG_INFO     = 4
LOG_VERBOSE  = 5
LOG_DEBUG    = 6
LOG_MIN      = LOG_SILENT
LOG_MAX      = LOG_DEBUG

DEF_LOGLEVEL = LOG_INFO

level_map = { LOG_SILENT:  "",
              LOG_CRITICAL: "critical",
              LOG_ERROR:    "error",
              LOG_WARNING:  "warning",
              LOG_INFO:     "info",
              LOG_VERBOSE:  "verbose",
              LOG_DEBUG:    "debug" }

def isespecial(file):
    """ utility function to detect especial system files """

    return file.lower() in ("stderr", "stdout")

def absfile(file):
    """ utility function providing the absolute path for a file """

    if isespecial(file):
        afile = file.lower()
    else:
        afile = os.path.abspath(file)

    return afile

class Handle(object):
    """ a wrapper around file handles
        each handle represents an unique destination file
        multiple log objects can reuse the same handle (e.g. stderr)
    """

    def __init__(self, name):
        """ class constructor """

        self.name     = name
        self.file     = "<NULL>"
        self.level    = None

        self.refcount = 0
        self.isopen   = False

        self.fh = None

    def open(self, file):
        """ open the file associated to this handle """

        # Do not open if already open. Just increase reference count
        #
        if self.isopen:
            self.refcount += 1
            return self.fh

        # Do not open 'especials'
        #
        if file.lower() == "stderr":
            fh = sys.stderr
        elif file.lower() == "stdout":
            fh = sys.stdout
        else:
            try:
                fh = open(file, 'a+')
            except OSError as ose:
                deflog.log(LOG_ERROR, "error opening file '%s': %s", file, ose.strerror)
                return None

        self.file     = file
        self.isopen   = True
        self.refcount = 1
        self.fh       = fh

        return fh

    def reopen(self, newfile):
        """ assign a new file handle to an existing handle
            this impacts all the users (refcounted) of this handle
        """

        if not self.isopen:
            deflog.log(LOG_ERROR, "error reopening file '%s'. File is closed", self.file)
            return None

        refcount = self.refcount

        self.close(force=True)

        # get a file handle for the new file
        #
        newfh = self.open(newfile)

        if newfh:
            self.file     = newfile
            self.isopen   = True
            self.refcount = refcount

        self.fh = newfh

        return newfh

    def close(self, force=False):
        """ close handle if allowed and just one reference to the handler remains
            return whether the handle was actually closed for cache management
        """

        # Already closed
        #
        if self.isopen is False:
            return True

        # decrease reference count or force to no references
        #
        if force:
            self.refcount = 0
        else:
            self.refcount -= 1

        if self.refcount < 1:
            # do not close 'especials' internally
            #
            if not isespecial(self.name):
                self.fh.close()
            self.isopen   = False
            self.refcount = 0

        return not self.isopen

class Log(object):
    """ This is the logging class """

    handle_cache = {}

    def __init__(self, file="stderr",
                       facility=None,
                       loglevel=DEF_LOGLEVEL,
                       setglobal=False,
                       lock=None,
                       lf_date_severity="lf+date+severity"):
        """ class constructor. Build a new log object using the following parameters:

            file              file taking the log. Especials are "stderr" (the default) and "stdout"
            facility          name identifying the module that generates the log (default is no facility)
            loglevel          severity level above which no log is produced (default is the current level,
                              LOG_INFO if not provided)
            setglobal         whether the specified log level is applied to the current log object or
                              to all objects associated to the same handle
            lock              a multiprocessing o threading lock controlling writes in multiprocess/thread
                              scenarios (defult is None)
            lf_date_severity  a string containing (or missing) the keys "lf" for line feed after each log entry,
                              "date" for adding a timestamp to the entry or severity for including
                              the criticallity level
        """

        self.facility = facility
        self.lock     = lock

        # format options
        #
        lds = lf_date_severity.lower()
        self.lf       = "lf"       in lds
        self.date     = "date"     in lds
        self.severity = "severity" in lds

        # set the local log level for this object
        #
        self.level = loglevel

        # lookup handle associated with the log object in the handle cache
        #
        handle = self._get_handle(file)

        if setglobal and handle:
            # change the handle logging level so it now affects
            # to all log objects associated to the same handle
            #
            handle.level = loglevel

        self.handle = handle
        self.closed = False

    def _get_handle(self, file):
        """ return a file handle object for the file either from the cache or by actually opening the file """

        cache = self.__class__.handle_cache

        # look up handle cache
        #
        abs_file = absfile(file)
        handle   = cache.get(abs_file)
        uncached = handle is None

        if uncached:
            # handle is not in the cache. Create a new instance and cache it
            #
            handle = Handle(file)

        fh = handle.open(abs_file)
        if not fh:
            return None

        if uncached:
            self._cache_add(abs_file, handle)

        return handle

    def _cache_add(self, file, handle):

        cache = self.__class__.handle_cache

        # add valid handles to cache
        #
        if handle:
            cache[file] = handle

    def _cache_remove(self, file):

        cache = self.__class__.handle_cache

        # remove handle from cache
        #
        if file in cache:
            del cache[file]

    def _change_handle(self, file):
        """ change handle for the current log object (others unaffected)
            you may want to call 'set_global' and/or 'set_lock' for the new handle if needed
        """

        handle = self.handle
        if not (handle and handle.isopen):
            deflog.log(LOG_ERROR, "could not change handle to file '%s'. Invalid handle", file)
            return None

        oldfile = handle.file

        # lookup handle
        #
        abs_file  = absfile(file)
        newhandle = self._get_handle(abs_file)
        if not newhandle:
            return None

        # close handle and remove it from cache
        #
        closed = handle.close()
        if closed:
            self._cache_remove(oldfile)

        self.handle = newhandle

        return newhandle

    def _redirect_handle(self, file):
        """ redirect handle output to another file (all log objects attached to handle impacted) """

        handle = self.handle

        if not (handle and handle.isopen):
            deflog.log(LOG_ERROR, "invalid handle for redirecting to file %s", file)
            return handle

        cache = self.__class__.handle_cache

        abs_file = absfile(file)
        fh = handle.reopen(abs_file)

        if not fh:
            return None

        return handle

    @classmethod
    def _dump_cache(cls):
        """ dump the contents of the handle cache """

        dumplog = cls("stderr", loglevel=LOG_INFO, lf_date_severity="lf")
        cache   = cls.handle_cache

        for file in cache:
            handle = cache[file]
            dumplog.log(LOG_INFO, "%s  ------------", handle.name)
            for attr in vars(handle):
                dumplog.log(LOG_INFO, "     '%s': %s", attr, getattr(handle, attr))

        dumplog.close()

    def _objlevel(self):
        """ return the log level associated to a log object """

        level = self.level

        handle = self.handle
        if handle and handle.level is not None:
            level = handle.level

        return level

    def _log_write(self, msg):
        """ write to the log file using specified format """

        handle = self.handle

        if not (handle and handle.isopen):
            deflog.log(LOG_CRITICAL, "invalid or closed handle 'None'")
            return

        fh = handle.fh
        if fh.closed:
            deflog.log(LOG_CRITICAL, "attempting to log to a closed file: '%s'", fh.name)
            return

        try:
            if self.lock:
                self.lock.acquire()
            fh.write(msg)
            if self.lf:
                fh.write(os.linesep)
            fh.flush()
            if self.lock:
                self.lock.release()
        except (KeyboardInterrupt, BrokenPipeError) as exc:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, fh.fileno())
            self.close()
            raise exc
        except OSError as ose:
            deflog.log(LOG_ERROR, 'could not log message: %s to file "%s", "%s"', msg, fh.name, ose.strerror)

    # public methods
    #

    def close(self):
        """ close this log object """

        handle = self.handle

        if not handle:
            return

        closed = handle.close()

        if closed:
            # remove from cache
            #
            self._cache_remove(handle.file)
            self.handle = None

        self.closed = True

    @classmethod
    def closeall(cls):
        """ close all handles in the cache """

        for handle in list(cls.handle_cache.values()):
            closed = handle.close(force=True)
            if closed:
                file = handle.file
                del cls.handle_cache[file]

    def log(self, loglevel, format, *arglist):
        """ a method for formatted logging  """

        if self.closed or self.handle is None:
            deflog.log(LOG_CRITICAL, "attempting to log to a an invalid/closed handle")
            return

        level = self._objlevel()
        if level == LOG_SILENT or loglevel > level:
            return

        ldate = ""
        if self.date:
            ldate = "%d/%02d/%02d:%02d:%02d:%02d " % time.localtime()[:6]

        if self.facility:
            ldate += "%s: " % self.facility.upper()

        if loglevel > LOG_MIN and self.severity:
            ldate += "[%s] " % level_map[loglevel]

        if arglist:
            try:
                msg = ldate + format % arglist
            except TypeError:
                deflog.log(LOG_ERROR, 'argument list (%i elements) mismatch with format "%s"', len(arglist), format)
                return
        else:
            msg = ldate + format

        self._log_write(msg)

    def log_bam(self, format, *arglist):
        """ log by all means """

        self.log(LOG_MIN, format, *arglist)

    def log_change(self, file):
        """ change log for this object to another file """

        return self._change_handle(file)

    def log_redirect(self, file):
        """ redirect log to another file (all log objects attached to the same handle) """

        return self._redirect_handle(file)

    def set_global(self, mode=True):
        """ set/cancel global log level for all objects associated to the same handle """

        handle = self.handle

        if handle and mode:
            handle.level = self.level
        elif handle:
            handle.level = None

    def set_log_level(self, loglevel, setglobal=False):
        """ set log level for this instance """

        level = max(LOG_MIN, min(loglevel, LOG_MAX))

        self.level = level

        self.set_global(setglobal)

    def show_log_level(self):
        """ show log level for this instance """

        return self._objlevel()

    def set_lock(self, lock=None):
        """ set lock for writes """

        self.lock = lock

    def set_log_fmt(self, facility=None, lf=None, date=None, severity=None):
        """ set the logging format """

        if facility is not None:
            self.facility = facility

        if lf in (True, False):
            self.lf   = lf
        if date in (True, False):
            self.date = date
        if severity in (True, False):
            self.severity = severity

#######################

# This is what is actually imported into the local namespace when "from modlog import *" is issued
#
__all__ = [ "LOG_SILENT", "LOG_CRITICAL", "LOG_ERROR", "LOG_WARNING", "LOG_INFO", "LOG_VERBOSE", "LOG_DEBUG",
            "Log" ]

# Default log object for reporting problems within this module
#
deflog = Log(file="stderr", facility="log", loglevel=LOG_ERROR)

