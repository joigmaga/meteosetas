""" This module implements a wrapper to the socket interface adding SSL and other features """

import sys
import os
import socket
from socket import *
import ssl
import errno
import select
import struct

from modlog import LOG_ERROR, Log

##########################################
#
#  Interface functions to the socket library
#
PORT     = 80
BACKLOG  = 128
BUFFSIZE = 4096

# Errors 1 and greater are reported as errno error codes
# The following statuses correspond to generic responses
#
OK    =  0
ERROR = -1
EOF   = -2

DFL_CERTFILE = "certfile.pem"
DFL_KEYFILE  = "keyfile.key"
DFL_PASSFILE = None
#DFL_PASSFILE = "passfile.pwd"

NULL_ADDR = ""

DFL_SSL_SERVER_PROTOCOL = ssl.PROTOCOL_TLS_SERVER
DFL_SSL_CLIENT_PROTOCOL = ssl.PROTOCOL_TLS_CLIENT

DFL_SSL_SERVER_CIPHERS = "HIGH:RSA:!MD5"
DFL_SSL_CLIENT_CIPHERS = ':'.join(("ECDHE-ECDSA-AES128-GCM-SHA256",
                                   "ECDHE-ECDSA-AES256-GCM-SHA384",
                                   "EECDH+AES128",
                                   "RSA+AES128",
                                   "EECDH+AES256",
                                   "RSA+AES256",
                                   "EECDH+CHACHA20",
                                   "EECDH+3DES",
                                   "RSA+3DES",
                                   "!MD5"))

has_epoll = sys.platform.startswith('linux')

# list of functions available with 'from modsocket import *'
#
__all__ = ["server_start", "conn_create",
           "schedule_server", "schedule_async_server", "poll_async_server"]
__all__.extend(os._get_exports_list(socket))

##########################################
# log object for this module
#
lg = Log(file='stderr', facility="SOCKET")

##########################################
#
class Secdesc(object):
    """ A security descriptor object with SSL options """

    def __init__(self, cert = None,
                       verify_client_cert=False,
                       verify_server_cert=True,
                       match_hostname=True,
                       cafile=None,
                       server_side=False):

        # Certificate selection:
        # - user provided (client or server)
        # - system default certificate for servers
        # - no certificate for clients by default
        #
        if cert is not None:
            self.certfile, self.keyfile, self.passfile = cert
        elif server_side:
            self.certfile = DFL_CERTFILE
            self.keyfile  = DFL_KEYFILE
            self.passfile = DFL_PASSFILE
        else:
            self.certfile  = None
            self.keyfile   = None
            self.passfile  = None

        if server_side:
            self.verify = verify_client_cert
        else:
            self.verify = verify_server_cert
        self.match  = match_hostname
        self.cafile = cafile
        self.server = server_side

        # Generate a default context with all the parameters gathered so far.
        # Can be changed later by modifying object attributes and rerunning 'build_x_context()'
        #
        if server_side:
            self.protocol = DFL_SSL_SERVER_PROTOCOL
            self.ciphers  = DFL_SSL_SERVER_CIPHERS
            self.purpose  = ssl.Purpose.CLIENT_AUTH
            self.context  = self.build_server_context()
        else:
            self.protocol = DFL_SSL_CLIENT_PROTOCOL
            self.ciphers  = DFL_SSL_CLIENT_CIPHERS
            self.purpose  = ssl.Purpose.SERVER_AUTH
            self.context  = self.build_client_context()

    def build_server_context(self):
        """ build SSL context for a server socket """

        context = ssl.SSLContext(self.protocol)
        context.set_ciphers(self.ciphers)
        context.verify_mode = ssl.CERT_NONE

        # Client certificate verification required
        # Supply a convenient CA to verify that the certificate presented by the client
        # has been issued by such a CA
        # Otherwise the certficate is checked against all the CAs defined in the system
        # so any valid certificate will pass the check
        #
        if self.verify:
            if self.cafile is not None:
                context.load_verify_locations(self.cafile)
            else:
                context.load_default_certs()
            context.verify_mode = ssl.CERT_REQUIRED

        # Always build a certificate for presenting to clients
        #
        context.load_cert_chain(self.certfile, self.keyfile, self.passfile)

        return context

    def build_client_context(self):
        """ build SSL context for a client socket """

        context = ssl.SSLContext(self.protocol)
        context.set_ciphers(self.ciphers)
        context.check_hostname = False
        context.verify_mode    = ssl.CERT_NONE

        if self.verify:
            if self.cafile is not None:
                context.load_verify_locations(self.cafile)
            else:
                context.load_default_certs()
            context.verify_mode    = ssl.CERT_REQUIRED
            context.check_hostname = self.match

        if self.certfile and self.keyfile:
            context.load_cert_chain(self.certfile, self.keyfile, self.passfile)

        return context

class Mysocket(object):
    """ A wrapper class to the socket interface enhanced with SSL methods """

    def __init__(self, sock=None):

        self.sock = sock

    def __getattribute__(self, name):
        """ method selection changed to look for socket/sslsocket methods
            in addition to local ones """

        # resolve instance attributes using parent's methods so we do not interfere with 'getattr'
        #
        mygetattr = super().__getattribute__

        # try local methods first
        #
        excp = None

        try:
            attr = mygetattr(name)
        except AttributeError as ae:
            excp = ae
        else:
            return attr

        # raise exception if no socket has been loaded yet
        #
        sock = mygetattr('sock')
        if sock is None:
            raise excp

        # last chance is checking socket/ssl methods
        # if that fails, the appropiate exception will be raised
        #
        try:
            attr = getattr(sock, name)
        except AttributeError:
            raise excp

        return attr

    def server_accept(self, accept_timeout=None):
        """ create a new socket for an arriving connection
            a custom interface to accept() with a result code """

        # This makes sure that the TCP socket created by accept() below has a timeout if requested
        # Subsequent calls to SSL routines (e.g. SSL Handshake) will not block
        #
        if getdefaulttimeout() != accept_timeout:
            setdefaulttimeout(accept_timeout)

        try:
            newsock, addrport = self.accept()
        except timeout as te:
            lg.log(LOG_ERROR, 'Socket accept error: "%s"', str(te))
            res     = errno.ETIMEDOUT
            addr    = NULL_ADDR
            newsock = None
        except OSError as ose:
            if ose.errno != errno.EAGAIN:
                lg.log(LOG_ERROR, 'Socket accept error: "%s"', ose.strerror)
            res     = ose.errno
            addr    = NULL_ADDR
            newsock = None
        else:
            res  = OK
            addr = addrport[0]

        mynewsock = None
        if newsock:
            mynewsock = Mysocket(newsock)

        return res, mynewsock, addr

    def conn_check(self):
        """ check whether socket has data ready for reading without actually reading """

        check = False

        try:
            s = self.recv( 1, MSG_PEEK | MSG_DONTWAIT )
        except OSError as ose:
            lg.log(LOG_ERROR, 'Socket peek error: "%s"', ose.strerror)
        else:
            check = len(s) > 0

        return check

    def conn_recv(self, bsize=BUFFSIZE, charset=None):
        """ custom recv() method with error status """

        # return a result code together with the buffer read

        try:
            s = self.recv(bsize)
        except timeout:
            lg.log(LOG_ERROR, 'receive timeout')
            s = None
            r = errno.ETIMEDOUT
        except OSError as ose:
            lg.log(LOG_ERROR, 'receive error "%s"', ose.strerror)
            s = None
            r = ose.errno
        else:
            r = OK
            if len(s) <= 0:
                r = EOF

            if charset:
                try:
                    s = s.decode(encoding=charset)
                except (UnicodeDecodeError, LookupError) as ude:
                    lg.log(LOG_ERROR, 'recv() decode error: "%s"', ude)
                    s = None
                    r = ERROR

        return r, s

    def conn_read(self, bsize=BUFFSIZE, charset=None):
        """ custome recv() method """

        _, s = self.conn_recv(bsize, charset)

        return s

    def conn_send(self, buff, charset=None):
        """ custom send() method with status code """

        l = 0

        if charset:
            try:
                buff = buff.encode(encoding=charset)
            except (UnicodeEncodeError, LookupError) as ude:
                lg.log('send() encode error: "%s"', ude)
                r = ERROR
                return r, l

        try:
            l = self.send(buff)
        except timeout:
            lg.log(LOG_ERROR, 'send timeout')
            r = errno.ETIMEDOUT
        except OSError as ose:
            r = ose.errno
            if r not in (errno.EAGAIN, errno.EPIPE):
                lg.log(LOG_ERROR, 'send error "%s"', ose.strerror)
        else:
            r = OK

        return r, l

    def conn_write(self, buff, charset=None):
        """ custom send() method """

        _, l = self.conn_send(buff, charset)

        return l

    def get_cert(self):
        """ obtain peer's certificate """

        cdict = None

        try:
            cdict = self.getpeercert()
        except ssl.SSLError as sse:
            lg.log(LOG_ERROR, "Error getting peer's certificate: %s", sse)
        else:
            if not cdict:
                lg.log(LOG_ERROR, "Error getting peer's certificate: not connected")

        return cdict

    def get_cipher(self):
        """ obtain negotiated cipher suite """

        res = None

        try:
            ctuple = self.cipher()
        except ssl.SSLError as sse:
            lg.log(LOG_ERROR, "Error getting cipher suite from peer: %s", sse)
        else:
            if ctuple is None:
                lg.log(LOG_ERROR, "Error getting cipher suite from peer: not connected")
            else:
                res = ctuple[0]

        return res

    def linger(self, value=True, tout=0):
        """ set linger on close option for socket """

        ling = 0
        if value:
            ling = 1

        self.setsockopt(SOL_SOCKET, SO_LINGER, struct.pack('ii', ling, tout))

#########################
# Convenience functions #
#########################

def read_pass_file(passfile=DFL_PASSFILE):
    """ read a certificate password from a password file """

    pwd = None

    if passfile is not None:

        # returns an unencoded byte string containing the password
        #
        try:
            with open(passfile, 'rb') as fd:
                pwd = fd.read()
        except OSError:
            pwd = b''

    return pwd

def server_start(host, port=PORT, backlog=BACKLOG, reuse_port=False, secdesc=None):
    """ start a server on a given address/port """

    sock = socket()

    try:
        sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        if reuse_port:
            sock.setsockopt(SOL_SOCKET, SO_REUSEPORT, 1)
        sock.bind((host, port))
        sock.listen(backlog)
    except OSError as ose:
        lg.log(LOG_ERROR, 'Socket configuration error "%s"', ose.strerror)
        sock.close()
        sock = None
    else:
        if secdesc:
            context = secdesc.context
            try:
                sock = context.wrap_socket(sock, server_side=True)
            except ssl.SSLError as sse:
                lg.log(LOG_ERROR, 'SSL socket wrap error "%s"', sse)
                sock = None

    mysock = None
    if sock:
        mysock = Mysocket(sock)

    return mysock

def schedule_server(listr, listw=None, listx=None, tout=None):
    """ check for file descriptor readiness based on select() """

    if listw is None:
        listw = []
    if listx is None:
        listx = []

    try:
        rl, wl, xl = select.select(listr, listw, listx, tout)
    except OSError as ose:
        lg.log(LOG_ERROR, 'Select error "%s"', ose)
        return None, None, None

    return rl, wl, xl

def dispatch(listr, listw=None, listx=None):
    """ generic interface to schedule_server """

    if listw is None:
        listw = []
    if listx is None:
        listx = []

    return schedule_server(listr, listw, listx)

def schedule_async_server(sock, *other):
    """ an epoll() based interface to deal with non-blocking sockets and other descriptors """

    # select.EPOLLEXCLUSIVE flag is not available in RH7 libraries
    #
    EPOLLEXCLUSIVE = 268435456

    flags = select.POLLIN
    if has_epoll:
        flags = select.EPOLLIN | EPOLLEXCLUSIVE
        pdesc = select.epoll()
    else:
        pdesc = select.poll()

    pdesc.register(sock.fileno(), flags)

    if has_epoll:
        flags = select.EPOLLIN
        
    for desc in other:
        pdesc.register(desc, flags)

    return pdesc

def poll_async_server(pdesc, tout=-1):
    """ the actual poll for ready file descriptors """

    dlist = pdesc.poll(tout)

    return [desc[0] for desc in dlist]

def conn_create(host, port, conn_timeout=None, secdesc=None):
    """ setup a connection to a remote endpoint """

    sock = None

    try:
        addrlist = getaddrinfo(host, port, AF_UNSPEC, SOCK_STREAM)
    except gaierror as se:
        lg.log(LOG_ERROR, 'Address resolution error "%s"', se.strerror)
        return None

    for res in addrlist:
        af, socktype, proto, _, sa = res
        try:
            sock = socket(af, socktype, proto)
        except OSError as ose:
            lg.log(LOG_ERROR, 'Socket creation error "%s"', ose.strerror)
            break

        if secdesc:
            context = secdesc.context
            try:
                sock = context.wrap_socket(sock, server_side=False, server_hostname=host)
            except ssl.SSLError as sse:
                lg.log(LOG_ERROR, 'SSL socket wrap error "%s"', sse.strerror)
                sock = None
                break

        try:
            sock.settimeout(conn_timeout)
            sock.connect(sa)
        except timeout as te:
            lg.log(LOG_ERROR, 'Socket connect error "%s"', str(te))
            sock.close()
            sock = None
            continue
        except OSError as ose:
            lg.log(LOG_ERROR, 'Socket connect error "%s"', ose.strerror)
            sock.close()
            sock = None
            continue
        else:
            sock.settimeout(getdefaulttimeout())
            break

    mysock = None
    if sock:
        mysock = Mysocket(sock)

    return mysock
