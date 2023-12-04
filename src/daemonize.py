""" This module contains process related functions, including
    - a function to detach the current process from the terminal and 
      from any related process in the same group
"""

import os
import sys
import atexit

from modlog import LOG_ERROR, Log

# set log object for this module. We only report errors

lg = Log(file="stderr", facility=__name__, loglevel=LOG_ERROR)

def delpidfile(pidfile):
    """ Remove pid file """

    if pidfile is not None:
        try:
            os.unlink(pidfile)
        except TypeError:
            lg.log(LOG_ERROR, "Invalid pid file %s: wrong file type", str(pidfile))
            status = 1
        except OSError as ose:
            lg.log(LOG_ERROR, "Error deleting pid file %s: %s", pidfile, ose.strerror)
            status = ose.errno
        else:
            status = 0

    return status

def daemonize(ifile=os.devnull,
              lfile=os.devnull,
              efile=os.devnull,
              pidfile=None,
              umask=0o22):
    """ Detach this process and its children from terminal
        fork twice to create a session leader process
    """

    # first fork
    #
    try:
        if os.fork() > 0:
            sys.exit(0)

    except OSError as ose:
        lg.log(LOG_ERROR, 'unable to perform 1st fork: %s', ose.strerror)
        sys.exit(ose.errno)

    # Make this process the session leader and build a new environment
    #
    os.chdir("/")

    try:
        os.setsid()
    except OSError as ose:
        lg.log(LOG_ERROR, 'unable to set new session with setsid(): %s', ose.strerror)
        sys.exit(ose.errno)

    os.umask(umask)

    # second fork
    #
    try:
        if os.fork() > 0:
            sys.exit(0)
    except OSError as ose:
        lg.log(LOG_ERROR, 'unable to perform 2nd fork: %s', ose.strerror)
        sys.exit(ose.errno)

    # Detach from user terminal by redirecting stdin, stdout and stderr
    #
    sys.stdout.flush()
    sys.stderr.flush()
    for file, mode, fno in ( (ifile, 'r',  sys.stdin.fileno()),
                             (lfile, 'a+', sys.stdout.fileno()),
                             (efile, 'a+', sys.stderr.fileno()) ):
        try:
            fd = open(file, mode)
            os.dup2(fd.fileno(), fno)
        except OSError as ose:
            lg.log(LOG_ERROR, 'error redirecting file descriptor %d to %s: %s', fno, file, ose.strerror)
            sys.exit(ose.errno)

        fd.close()

    # create a file containing the pid for this process
    # register pidfile deletion at process exit
    #
    if pidfile:

        pid = 0

        # pid file already exists?
        try:
            with open(pidfile, 'r') as f:
                pid = int(f.readline())
        except FileNotFoundError:
            # No. That's what we expect
            status = 0
        except TypeError:
            # invalid file type
            lg.log(LOG_ERROR, "Invalid pid file %s: wrong file type", str(pidfile))
            status = 1
        except ValueError:
            # file exists but pid is meaningless
            status = delpidfile(pidfile)
        else:
            # file exists
            if pid > 1:
                # File exists. Contains a running process?
                try:
                    os.kill(pid, 0)
                except OSError as ose:
                    # No. Assume stalled file (e.g. after a system crash) and remove it
                    status = delpidfile(pidfile):
                else:
                    # process already running
                    lg.log(LOG_ERROR, "pid file '%s' exists and must be removed manually", pidfile)
                    status = 1

        if status != 0:
            sys.exit(status)  

        # write pid to file
        try:
            with open(pidfile, 'w+') as f:
                f.write("%d\n" % os.getpid())
        except OSError as ose:
            lg.log(LOG_ERROR, "error creating pidfile '%s': %s", pidfile, ose.strerror)
            sys.exit(ose.errno)

        atexit.register(delpidfile, pidfile)

    return 0

