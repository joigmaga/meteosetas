""" This module contains process related functions, including
    - interface functions to setuid() and getgid()
    - a function to detach the current process from the terminal and 
      from any related process in the same group
"""

import os
import sys
import atexit
import pwd, grp

# module imports from perftools
#
from modlog import *

# set log object for this module. We only report errors
#
lg = Log(file="stderr", facility=__name__, loglevel=LOG_ERROR)

def change_uid(uid, setreal=True):
    """ change effective uid for this process
        if 'setreal' is true (default), use setuid to change both real and effective uid
        the later permits regaining root privileges
        allow numeric values and user names for ids

        return errno status
    """

    euid = None

    if uid and isinstance(uid, int):
        euid = uid
    elif uid:
        try:
            euid = pwd.getpwnam(uid)[2]
        except (TypeError, KeyError) as e:
            lg.log(LOG_ERROR, "Could not setuid(): to %s: %s", uid, e.strerror)
            return e.errno
    
    if euid:
        ruid  = os.getuid()
        if setreal:
            ruid = euid 
        try:
            os.setreuid(ruid, euid)
        except PermissionError as pe:
            lg.log(LOG_ERROR, "Could not setreuid(): to %s, %s: %s", ruid, euid, pe.strerror)
            return pe.errno
    
    return 0

def change_gid(gid, setreal=True):
    """ change effective gid for this process
        if 'setreal' is true, use setgid to change both real and effective gid
        allow numeric values and user names for ids

        return errno status
    """

    egid = None

    if gid and isinstance(gid, int):
        egid = gid
    elif gid:
        try:
            egid = grp.getgrnam(gid)[2]
        except (TypeError, KeyError) as e:
            lg.log(LOG_ERROR, "Could not setgid(): to %s: %s", gid, e.strerror)
            return e.errno

    if egid:
        rgid  = os.getgid()
        if setreal:
            rgid = egid 
        try:
            os.setregid(rgid, egid)
        except PermissionError as pe:
            lg.log(LOG_ERROR, "Could not setregid(): to %s, %s: %s", rgid, egid, pe.strerror)
            return pe.errno
    
    return 0

def delpidfile(pidfile):
    """ Remove pid file """

    try:
        os.unlink(pidfile)
    except OSError as ose:
        lg.log(LOG_ERROR, "Error deleting pid file %s: %s", pidfile, ose.strerror)
        return ose.errno

    return 0

def daemonize(ifile=os.devnull,
              lfile=os.devnull,
              efile=os.devnull,
              pidfile=None,
              chroot=None,
              uid=None, gid=None,
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
    if chroot:
        os.chroot(chroot)

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

    # optionally, change userid and groupid for this process
    #
    if gid is not None:
        status = change_gid(gid)
        if status != 0:
            lg.log(LOG_ERROR, "Could not setgid(). Exiting")
            sys.exit(status)
    if uid is not None:
        status = change_uid(uid)
        if status != 0:
            lg.log(LOG_ERROR, "Could not setuid(). Exiting")
            sys.exit(status)

    # create a file containing the pid for this process
    # register pidfile deletion at process exit
    # note that deletion may no work if this process changes uid to a non-privileged user
    # fork() and setuid() in the child is the way to go, leaving this process with root privileges
    #
    if pidfile:

        # write pid to file
        try:
            with open(pidfile, 'w+') as f:
                f.write("%d\n" % os.getpid())
        except OSError as ose:
            lg.log(LOG_ERROR, "error creating pidfile: %s", ose.strerror)
            sys.exit(ose.errno)
        else:
            atexit.register(delpidfile, pidfile)

    return 0

