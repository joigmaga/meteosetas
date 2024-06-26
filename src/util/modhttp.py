""" Interface to basic HTTP functions """

import sys
import time

import modsocket
import modurl
from modlog import LOG_ERROR, Log

OK  = 0
NOK = 1
WSPACE = ' \t'

DEF_CHARSET = "ISO-8859-15"

BUFFSIZE = 8192

#################################################################
# log object for this module
#
lg = Log(file="stderr", facility="HTTP")

#################################################################
#
class Hdesc(object):
    """ HTTP transport connection object descriptor """

    cookie_jar = {}

    def __init__(self, sock=None):

        self.sock = sock

        self.persist   = False
        self.verbose   = False
        self.nooutput  = False
        self.silent    = False
        self.capture   = False
        self.ctimeout  = None
        self.verify    = True
        self.cafile    = None

        self.connected = False
        self.basetime  = 0
        self.ctime     = 0
        self.time2fb   = 0
        self.ttime     = 0
        self.file      = None
        self.bytes     = 0
        self.method    = ''
        self.httpresp  = None
        self.proto     = ''
        self.version   = ''
        self.code      = ''
        self.hdict     = None
        self.buff      = b""
        self.clen      = 0
        self.charset   = DEF_CHARSET

        self.cipher      = None
        self.certificate = None

    def pout(self, msg, addlf=True):
        """ output content. 'msg' must be of byte/bytearray type """

        # move this out of here
        #
        if self.capture:
            self.buff += msg
            return

        if self.nooutput:
            return

        if type(msg) is not str:
            try:
                msg = msg.decode(self.charset)
            except (UnicodeDecodeError, LookupError) as ude:
                lg.log(LOG_ERROR, "error attempting to decode output as '%s': %s", self.charset, ude)

        if type(msg) is str:
            sys.stdout.write(msg)
            if addlf:
                sys.stdout.write('\n')
            sys.stdout.flush()

    def perr(self, msg, addlf=True):
        """ output error and informative messages. 'msg' must be of byte/bytearray type """

        if self.silent:
            return

        if type(msg) is str:
            sys.stderr.write(msg)
            if addlf:
                sys.stderr.write('\n')
            sys.stderr.flush()

    def close(self):
        """ close the transport session """

        # close the file object first
        file = self.file
        if file:
            file.close()
        self.file = None

        # then the socket
        sock = self.sock
        if sock:
            sock.close()
        self.connected = False
        self.sock = None

    def exitnow(self, msg=None, status=NOK):
        """ Exit handler """

        if msg:
            lg.log(LOG_ERROR, "%s", msg)

        self.close()

        return status

    def socket_readline(self):
        """ read a line from a socket. Return a string """

        sock = self.sock
        if not sock:
            return None

        line  = b''
        carry = b''
        while True:
            c = sock.conn_read(1)
            if c is None:
                return c
            if c is b'':
                line += carry
                break
            if c == b'\n':
                break
            if c == b'\r':
                carry = c
            else:
                line += carry
                line += c
                carry = b''

        try:
            line = line.decode(self.charset)
        except (UnicodeDecodeError, LookupError) as ude:
            lg.log(LOG_ERROR, "error attempting to decode line: %s", ude.strerror)
            line = None

        return line

    def readline(self):
        """ return the next line in the socket after removing line-separators, if any
            using the sockets's file interface. Return a string  """

        fo = self.file
        if not fo:
            return self.socket_readline()

        try:
            line = fo.readline().decode(self.charset)
        except (UnicodeDecodeError, LookupError) as ude:
            lg.log(LOG_ERROR, "error attempting to decode line: %s", ude.strerror)
            line = None

        if line and line.endswith('\n'):
            line = line[:-1]
            if line.endswith('\r'):
                line = line[:-1]

        return line

    def socket_read(self, size):
        """ read 'size' bytes from socket. Return a bytes object """

        sock = self.sock
        if not sock:
            return None

        rbuff  = b""
        remain = size

        while remain > 0:
            buff = sock.conn_read(remain)
            if not buff:
                break
            rbuff  += buff
            remain -= len(buff)

        return rbuff

    def read(self, size=BUFFSIZE):
        """ read bytes into buffer. Return bytes """

        fo = self.file
        if not fo:
            return self.socket_read(size)

        try:
            buff = fo.read(size)
        except OSError:
            buff = None

        return buff

    def writeline(self, buff):
        """ pass a string, write bytes """

        buff += '\r\n'

        try:
            buff = buff.encode(self.charset)
        except (UnicodeEncodeError, LookupError) as ude:
            lg.log(LOG_ERROR, "error attempting to encode line: %s", ude.strerror)
            return None

        return self.write(buff)

    def write(self, buff):
        """ write buffer contents as bytes """

        fo = self.file
        if not fo:
            sock = self.sock
            if not sock:
                return None
            return sock.conn_write(buff)

        return fo.write(buff)

    def flush(self):
        """ complete file write operation by flushing the output buffer """

        fo = self.file
        if fo:
            fo.flush()

    def conn_timeout(self, timeout):
        """ set socket timeout for recv operations """

        cur_timeout = None

        sock = self.sock
        if sock:
            cur_timeout = sock.gettimeout()
            sock.settimeout(timeout)

        return cur_timeout

#################################################################
#
# Request methods
#

    def request_header(self, method, url, file, xhead):

        header = []

        hosthdr = "Host: %s" % url.hostport()
        accphdr = "Accept: application/json, */*"
        morehdr = []

        if isinstance(xhead, dict):
            hosthdr = "Host: %s" % xhead.get('Host', url.hostport())
            if "Host" in xhead:
                del xhead['Host']
            for h in xhead.keys():
                morehdr.append("%s: %s" % (h, xhead[h]))

        elif isinstance(xhead, str):
            if xhead.startswith("Host:"):
                hosthdr = xhead
            else:
                morehdr.append(xhead)

        header.append(hosthdr)
        header.append(accphdr)
        header.extend(morehdr)

        if self.persist:
            header.append("Connection: keep-alive")
        else:
            header.append("Connection: close")

        if method == "POST":
            header.append("Content-Type: application/x-www-form-urlencoded")
        elif method == "PUT":
            header.append("Content-Type: application/octet-stream")
        if method in ("POST", "PUT"):
            header.append("Content-Length: %d" % len(file))

        hdr = self.request_cookies(url.host)
        if hdr:
            header.append(hdr)

        header.append("")

        return header

    def request_cookies(self, host):

        hdr = ''

        if host in self.cookie_jar.keys():
            hdr += "Cookie: "
            for cookie in self.cookie_jar[host]:
                cname, cval, _, _ = cookie
                hdr += cname + '=' + cval + ';'

        return hdr

    def request_body(self, method, file):

        if method == "POST" or method == "PUT":
            return file

        return None

    def sslout(self):

        if not self.verbose:
            return OK

        if self.cipher:
            self.perr('* SSL connection using ' + self.cipher)

        if not self.certificate:
            return OK

        dct   = self.certificate

        substr, cname = self.get_cert_attr("subject", dct)
        issstr, _     = self.get_cert_attr("issuer", dct)

        sanlist = []
        for (t, n) in dct.get('subjectAltName', ()):
            if t == "DNS":
                sanlist.append(n)

        self.perr('* Server certificate:')
        self.perr('*       subject: '         + substr)
        self.perr('*       start date: '      + dct.get('notBefore', ''))
        self.perr('*       expire date: '     + dct.get('notAfter', ''))
        self.perr('*       common name: '     + cname)
        self.perr('*       alternate names: ' + ','.join(sanlist))
        self.perr('*       issuer: '          + issstr)

        return OK

    def get_cert_attr(self, attr, dct):

        certmap = { "countryName":            "CN",
                    "organizationName":        "O",
                    "organizationalUnitName": "OU",
                    "stateOrProvinceName":    "ST",
                    "localityName":            "L",
                    "commonName":             "CN",
                  }

        cname  = ""
        outstr = ""

        l1 = dct.get(attr, ())
        prev = False
        for l2 in l1:
            for (name, val) in l2:
                if prev:
                    outstr += ","
                outstr += certmap.get(name, name) + "=" + val
                prev = True
                if name == "commonName":
                    cname = val

        return outstr, cname

    def create_connection(self, url):

        if self.connected:
            return OK

        sdesc = None
        secure = url.scheme == "https"
        if secure:
            sdesc = modsocket.Secdesc(verify_server_cert=self.verify, match_hostname=self.verify, cafile=self.cafile)

        # time reference for this request
        self.basetime = time.time()

        sock = modsocket.conn_create(url.host, url.port, self.ctimeout, sdesc)
        if sock is None:
            return NOK

        self.ctime = time.time()
        self.sock  = sock
        self.host  = url.hostport
        self.connected = True

        if self.verbose:
            h, p = sock.getpeername()
            self.perr('* Connected to %s (%s) port %s' % (h, url.host, p))

        if secure:
            self.cipher = sock.get_cipher()
            if self.verbose and not self.verify:
                self.perr('* skipping SSL peer certificate verification')
            else:
                self.certificate = sock.getpeercert()
            self.sslout()

        return OK

    def request(self, urlstr, method='GET', file=None, xhead=None, makefile=False):

        url = modurl.Url(urlstr)

        # Empty capture buffer and response body counter
        self.buff  = b""
        self.bytes = 0

        # Keep track of method used in request for handling responses to "HEAD"
        self.method = method

        # New connection if required
        res = self.create_connection(url)
        if res != OK:
            return self.exitnow('unable to connect to host "%s" port "%s"' % (url.host, url.port))

        if makefile and (self.file is None):
            # create a file object interface to the socket for parsing the whole response
            # make sure socket is in blocking state for the file interface to work properly
            #
            self.conn_timeout(None)
            sock = self.sock
            fo = sock.makefile(mode='rwb')
            if not fo:
                return self.exitnow("could not associate file to socket")
            self.file = fo

        req_line = "%s %s HTTP/1.1" % (method, url.pathquery())
        self.writeline(req_line)
        if self.verbose:
            self.perr('> ' + req_line)

        header = self.request_header(method, url, file, xhead)
        for hdr in header:
            self.writeline(hdr)
            if self.verbose:
                self.perr('> ' + hdr)
        self.flush()

        body = self.request_body(method, file)
        if body:
            self.write(body)
            self.flush()

        return OK

#################################################################
#
# Response methods
#
    def response_status_line(self):
        """ read and analyze HTTP response status line """

        self.httpresp = self.readline()
        if not self.httpresp:
            return NOK

        self.time2fb = time.time()

        try:
            pre, self.code, _ = self.httpresp.split(None, 2)
            self.proto, self.version = pre.split('/')
        except ValueError:
            return NOK

        if self.verbose:
            self.perr('< ' + self.httpresp)

        return OK

    def response_headers(self):
        """ capture headers from HTTP response """

        headers  = []

        while True:
            hdr = self.readline()
            if self.verbose:
                self.perr('< ' + hdr)
            if not hdr:
                break

            if hdr[0] in WSPACE:
                try:
                    headers[-1] += hdr[0] + hdr.lstrip(WSPACE)
                except IndexError:
                    lg.log(LOG_ERROR, "Malformed continuation line in response header")
                    return NOK
            else:
                headers.append(hdr)

        self.hdict = {}

        for h in headers:
            try:
                hdr, val = h.split(":", 1)
            except ValueError:
                lg.log(LOG_ERROR, "malformed header '%s'", h)
                return NOK
            self.hdict[hdr.strip()] = val.strip()

        if "Content-Type" in self.hdict:
            for parval in self.hdict["Content-Type"].split(';'):
                p, _, v = parval.partition('=')
                if p.strip() == "charset":
                    self.charset = v.strip()

        return OK

    def add_cookie(self):
        """ add received cookie to jar """

        if self.hdict and 'Set-Cookie' in self.hdict.keys():
            cpar = self.hdict['Set-Cookie']
            try:
                cnam, sep, rest = cpar.partition(';')
                n, v = cnam.split('=', 1)
                if self.host not in self.cookie_jar.keys():
                    self.cookie_jar[self.host] = []
                self.cookie_jar[self.host].append((n, v, '', ''))
            except ValueError:
                lg.log(LOG_ERROR, "Invalid Cookie format '%s'", cpar)
                return NOK

        return OK

    def response_chunked_body(self):
        """ read response body in chunked encoding format """

        while True:
            line = self.readline()
            if not line:
                lg.log(LOG_ERROR, "unexpected empty line in chunked body")
                return NOK
            size = line.split(';')[0]

            try:
                s = int(size, 16)
            except ValueError:
                lg.log(LOG_ERROR, "unexpected trailer header found in chunked body: '%s'", line)
                return NOK

            if s > 0:
                chunk = self.read(s)
                if not chunk:
                    lg.log(LOG_ERROR, "chunked body read error")
                    return NOK
                chlen = len(chunk)
                if chlen != s:
                    lg.log(LOG_ERROR, "chunked body length mismatch: length: %d, expected: %d", chlen, s)
                    return NOK
                self.pout(chunk, addlf=False)
                self.bytes += chlen

            self.readline()

            if s == 0:
                break

        return OK

    def response_cl_body(self):
        """ read body response with predetermined length """

        while self.bytes < self.clen:
            block = self.read(min(self.clen, BUFFSIZE))
            if not block:
                break
            self.pout(block, addlf=False)
            self.bytes += len(block)

        if self.bytes != self.clen and self.method != "HEAD":
            lg.log(LOG_ERROR, "content length mismatch in response body")
            return NOK

        return OK

    def response_body(self):
        """ process the body in an HTTP response """

        if 'Transfer-Encoding' in self.hdict and self.hdict['Transfer-Encoding'] == 'chunked':
            # Chunked body
            res = self.response_chunked_body()
        elif 'Content-Length' in self.hdict:
            # Body length is embedded in the header
            try:
                self.clen = int(self.hdict['Content-Length'])
            except ValueError:
                lg.log(LOG_ERROR, "Invalid Content-Length value")
                return NOK
            res = self.response_cl_body()
        else:
            # No encoding so body is empty
            res = OK

        if res == OK:
            self.ttime = time.time()

        return res

    def check_response(self):
        """ check HTTP response line """

        errmsg = None

        res = self.response_status_line()
        if res != OK:
            if self.httpresp is None:
                errmsg = "transport error"
            elif len(self.httpresp) == 0:
                errmsg = "server disconnected before providing a reponse"
            else:
                errmsg = "invalid response status line"

        return res, errmsg

    # entry point to all the response receiving logic
    #
    def response(self):
        """ parse HTTP response """

        res = OK

        if not self.connected:
            errmsg = "socket not connected"
            res = NOK

        if res == OK:
            # status line
            res, errmsg = self.check_response()

        if res == OK:
            # headers
            res = self.response_headers()
            if res != OK:
                errmsg = "invalid header"
            else:
                self.add_cookie()

        if res == OK:
            # body
            res = self.response_body()
            if res != OK:
                errmsg = "invalid body"

        if res != OK:
            return self.exitnow(errmsg)

        # check whether server wants to disconnect or do it just because connection is not persistent
        closed = False
        if 'Connection' in self.hdict.keys():
            closed = self.hdict['Connection'].lower() == 'close'
        if closed or not self.persist:
            self.close()

        return OK

    # combined request/response
    #
    def transaction(self, urlstr, method='GET', file=None, xhead=None, makefile=False):
        """ a full HTTP transaction """

        res = self.request(urlstr, method, file, xhead, makefile)
        if res == OK:
            res = self.response()

        return res

