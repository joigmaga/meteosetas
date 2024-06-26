""" a module for parsing and building URLs """

import re

UNRESERVED = "-._~"

# Allowed characters when used as intra-component delimiters or when used as data,
# character not having any delimiter role
#
SUB_DELIMS = "!$&'()*+,;="
QRY_DELIMS = "!$'()*+,"
FTP_DELIMS = "!$&'()*+,"

HTTP_USER     = UNRESERVED + SUB_DELIMS
HTTP_USERINFO = UNRESERVED + SUB_DELIMS + ":"
HTTP_HOST     = UNRESERVED + SUB_DELIMS
HTTP_PATH     = UNRESERVED + SUB_DELIMS + ":@"
HTTP_QUERY    = UNRESERVED + QRY_DELIMS + ":@/?"
HTTP_FRAGMENT = UNRESERVED + SUB_DELIMS + ":@/?"

FTP_PATH      = UNRESERVED + FTP_DELIMS + ":@"

URLPATT  = (
r'(?:(?P<scheme>[^:/?#]+):)?(?://(?P<authority>[^/?#]*))?(?P<path>[^?#]*)(?:\?(?P<query>[^#]*))?(?:#(?P<fragment>.*))?'
)
ALTPATT  = r'(?P<authority>[^/?#]*)(?P<path>[^?#]*)(?:\?(?P<query>[^#]*))?(?:#(?P<fragment>.*))?'
AUTHPATT = r'(?:(?P<userinfo>[^@]*)@)?(?P<host>[^:*]*)(?::(?P<port>.*))?'
USERPATT = r'(?P<user>[^:]*)(?::(?P<password>.*))?'

def urlencode(text, allowed=''):
    """ Percent-encode text, which is expected to be an UTF-8 encoded string """

    if not text:
        return text

    penc = lambda b: "%%%02X" % b

    outstr = ''
    for c in text:
        # we should use c.isascii() here but only available from 3.7
        o = ord(c)
        if o < 128:
            if c.isalnum() or c in allowed:
                outstr += c
            else:
                outstr += penc(o)
        else:
            for b in c.encode():
                outstr += penc(b)

    return outstr

def urldecode(text):
    """ decode percent-encoded text into a UTF-8 string """

    if not text:
        return text

    outstr = ''

    i = 0
    l = len(text)
    while i < (l-2):

        if text[i] == '%':
            try:
                outstr += chr( int(text[i+1:i+3], 16) )
            except ValueError:
                outstr += text[i:i+3]
            i += 2
        else:
            outstr += text[i]
        i += 1

    while i < l:
        outstr += text[i]
        i += 1

    return outstr

class Url(object):
    """ break a URI into pieces and parse them """

    DEF_URL      = ''
    DEF_SCHEME   = 'http'
    DEF_HOST     = 'localhost'

    def_port = { "http":   "80",
                 "https": "443",
                 "ftp":    "21",
                 "ldap":  "389",
                 "ldaps": "636",
                 "file":     "",
               }

    HTTPS_SCHEME = 'https'
    FTP_SCHEME   = 'ftp'
    LDAP_SCHEME  = "ldap"
    LDAPS_SCHEME = "ldaps"

    HTTPS_PORT   = '443'
    FTP_PORT     = '21'
    LDAP_PORT    = '389'
    LDAPS_PORT   = '636'

    absp = re.compile(URLPATT)
    altp = re.compile(ALTPATT)
    auth = re.compile(AUTHPATT)
    user = re.compile(USERPATT)

    def __init__(self, urlstr=DEF_URL):
        """ class constructor """

        self.uri = urlstr

        #  scheme
        #  authority
        #    userinfo
        #      user
        #      password
        #    host
        #    port
        #  path
        #  query
        #  fragment

        # Try full URl syntax including scheme, authority and path
        # parsing is very leniant, allowing for many variants. Building approach, on the contrary, is strict
        #
        m = Url.absp.match(urlstr)
        self.scheme = m.group('scheme')

        # Missing scheme, assume 'http'
        #
        if not self.scheme:

            if not m.group('authority'):
                # Try 'host/path'
                # (note that 'host:port/path' cannot be accepted as 'host' would be taken as 'scheme')
                #
                m = Url.altp.match(urlstr)

            # (note that '//host/part' is accepted even though is quite weird)
            #
            self.scheme = Url.DEF_SCHEME

        else:
            self.scheme = urldecode(self.scheme.lower())

        # Structured fields are not decoded
        #
        self.authority = m.group('authority')
        self.path      = m.group('path')
        self.query     = m.group('query')
        self.fragment  = urldecode(m.group('fragment'))

        if self.authority is None:
            self.userinfo = None
            self.host     = None
            self.port     = None
        else:
            m = Url.auth.match(self.authority)
            self.userinfo = m.group('userinfo')
            self.host     = urldecode(m.group('host'))
            self.port     = urldecode(m.group('port'))
            if not self.port:
                self.port = Url.def_port.get(self.scheme, Url.DEF_SCHEME)

        if self.userinfo is None:
            self.user     = None
            self.password = None
        else:
            m = Url.user.match(self.userinfo)
            self.user     = urldecode(m.group('user'))
            self.password = urldecode(m.group('password'))

        # list members are decoded internally
        self.pathlist = self.pathsplit()

        # dict members are decoded internally
        self.querydict = self.querysplit()

    def pathsplit(self):
        """ split the path into segments """

        plist = []

        if self.path is not None:
            for p in self.path.split('/'):
                plist.append(urldecode(p))

        return plist

    def querysplit(self):
        """ split the query string into arg, value pairs and put them into a dictionary """

        qdict = {}

        if self.query is None:
            return qdict

        qlist = []
        for q in self.query.split('&'):
            altq = q.split(';')
            qlist.extend(altq)

        for q in qlist:
            try:
                k, v = q.split('=')
            except ValueError:
                k = q
                v = None

            qdict[urldecode(k)] = urldecode(v)

        return qdict

    def pathencode(self, pos=0):
        """ construct the path from its segments url-encoding them if neccessary """

        plist = []
        for p in self.pathlist[pos:]:
            plist.append(urlencode(p, HTTP_PATH))

        path = '/'.join(plist)
        if not path:
            path = '/'

        return path

    def queryencode(self):
        """ construct the query string from its arg, value pairs url-encoding them if neccessary """

        if not self.querydict:
            return None

        outstr = ''

        # Use '&' as the only delimiter when generating query strings
        #
        for k, v in self.querydict.items():
            if outstr:
                outstr += '&'

            outstr += urlencode(k, HTTP_QUERY)
            if v is not None:
                outstr += '=' + urlencode(v, HTTP_QUERY)

        return outstr

    def fragmentencode(self):
        """ encode the fragment component """

        if not self.fragment:
            return self.fragment

        return urlencode(self.fragment, HTTP_FRAGMENT)

    def pathquery(self):
        """ build the /path?query part, useful for creating "Host: " headers """

        outstr = self.pathencode()

        if self.querydict:
            outstr += '?' + self.queryencode()

        if self.fragment:
            outstr += '#' + self.fragmentencode()

        return outstr

    def hostport(self):
        """ the host & port altogether """

        outstr = ''

        if self.host:
            outstr += urlencode(self.host, HTTP_HOST)
        else:
            outstr += urlencode(Url.DEF_HOST, HTTP_HOST)

        if self.port and self.port != Url.def_port.get(self.scheme, Url.DEF_SCHEME):
            outstr += ':' + self.port

        return outstr

    def uinfo(self):
        """ encode the userinfo part, if present """

        outstr = ''

        if self.user is not None:
            outstr += urlencode(self.user, HTTP_USER)
            if self.password is not None:
                outstr += ':' + urlencode(self.password, HTTP_USERINFO)
            outstr += '@'

        return outstr

    def __str__( self ):
        """ a printable representation of the URL as a string """

        outstr = self.scheme
        if not self.scheme:
            outstr = Url.DEF_SCHEME

        outstr += ':'
        if self.authority is not None:
            outstr += '//'
            outstr += self.uinfo()
            outstr += self.hostport()

        outstr += self.pathencode()

        if self.querydict:
            outstr += '?' + self.queryencode()

        if self.fragment:
            outstr += '#' + self.fragmentencode()

        return outstr

