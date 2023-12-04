""" A module containing various json parsing functions """

import io
import re
import json

from modlog import LOG_ERROR, Log

# log object for this module
#
lg = Log(file="stderr", facility=__name__, loglevel=LOG_ERROR)

OCT_DIGITS = "01234567"
HEX_DIGITS = "0123456789abcdefABCDEF"

# compiled regular expressions
#
none_pattern    = re.compile(r'\s*(?:null|None)\s*$')
bool_pattern    = re.compile(r'\s*([Ff]alse|[Tt]rue)\s*$')
hex_pattern     = re.compile(r'\s*[+-]?0[xX][0-9a-fA-F]+\s*$')
octal_pattern   = re.compile(r'\s*([+-]?)0+([1-7][0-7]*)\s*$')
octpy_pattern   = re.compile(r'\s*[+-]?0[oO][0-7]+\s*$')

# Private exception to signal argument parsing errors
#
class InvalidArgument(Exception):
    """ A custom exception to signal an invalid value in a config file """

    def __init__(self, msg):
        super().__init__(msg)

        self.errmsg = msg

# Internal functions
#

def _unescape(string):
    """ encode string as a sequence of 'iso-latin-1' bytes, keeping backslashes and escaping unicode
        chars with code point > 255 as sequences of bytes with format b'\\uhhhh' or b'\\Uhhhhhhhh'
        Then decode as 'utf-8' string interpreting all escape sequences """

    return string.encode('raw_unicode_escape').decode('unicode_escape')

def _get_token(iow, remove_ws=True):
    """ extract and format a quoted/unquoted part of a string """

    token = iow.getvalue()
    if remove_ws:
        token = token.strip()

    iow.seek(io.SEEK_SET)
    iow.truncate(0)

    return token

def _typecast(token, quoted):

    # if the string is explicitly quoted, take it as such and do not try to interpret it
    if quoted:
        return token

    # Json formatted objects include 'null', 'true/false', integer and floating point numbers 
    #
    try:
        obj = json.loads(token)
    except json.decoder.JSONDecodeError:
        pass
    else:
        return obj

    # Some additions to standard JSON

    # 'None' as a pythonic synonym for 'null'
    # 
    if none_pattern.match(token):
        return None

    # 'True' and 'False'
    #
    m = bool_pattern.match(token)
    if m:
        return m.group(1).lower() == "true"
        
    # hexadecimal integers of the form '0xfe'
    #
    if hex_pattern.match(token):
        return int(token, 16)

    # Python style octal integers of the form ' 0o66'
    #
    if octpy_pattern.match(token):
        return int(token, 8)

    # C style '066' octal integers
    #
    m = octal_pattern.match(token)
    if m:
        return int(m.group(1) + "0o" + m.group(2), 8)

    return token

def _escape_char(c, ior, checkonly=True):
    """ check or interpret C/Python style escape sequences """

    ucodelen  = { "u": 4, "U": 8 }
    escapemap = { "a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v" }

    outc = ""
    if checkonly:
        outc = '\\'

    if c in "\"'\\":
        outc += c

    elif c in "abfnrtv":
        if checkonly:
            outc += c
        else:
            outc += escapemap[c]

    elif c in OCT_DIGITS:
        outc +=c 
        for _ in range(2):
            c = ior.read(1)
            if c in OCT_DIGITS:
                outc += c
            else:
                ior.seek(io.SEEK_CUR, -1)                
                break
        if not checkonly:
            outc = chr(int(outc, 8))

    elif c == 'x':
        outc += c
        outx = ""
        for _ in range(2):
            c = ior.read(1)
            outx += c
            if c not in HEX_DIGITS:
                raise InvalidArgument("bad escape secuence (\\x%s)" % outx)
        if checkonly:
            outc += outx
        else:
            outc = chr(int(outx, 16))

    elif c in "uU":
        outc += c
        outx = ior.read(ucodelen[c])
        if len(outx) != ucodelen[c]:
            raise InvalidArgument("bad escape secuence: \\%c%s (too short)" % (c, outx))
        for char in outx:
            if char not in HEX_DIGITS:
                raise InvalidArgument("bad escape secuence: \\%c%s (not hex)" % (c, outx))
        if checkonly:
            outc += outx
        else:
            outc = chr(int(outx, 16))

    elif c == 'N':
        # assume that the escape sequence '\\N{unicode-code-name}' can be safely encoded
        # as a latin-1 byte string (actually, all characters in sequence should be ASCII)
        #
        outc == '\\'
        outc += c
        c = ior.read(1)
        outc += c
        if c != '{':
            raise InvalidArgument("bad escape secuence: %s (bad format)" % outc)
        while c != '}':
            ior.read(1)
            outc += c
        if not c:
            raise InvalidArgument("bad escape secuence: %s (bad format)" % outc)
        if not checkonly:
            outc = bytes(outc, encoding='latin-1').decode('unicode-escape')

    # as in Python, allow for invalid escape sequence
    else:
        # includes '\\\n' (skip line break)
        outc = '\\'
        outc += c

    return outc
 
###
### Public methods
###

def qlist(s):
    """ The first item of the qstring if there is just one item in the list. Otherwise the list itself """

    l = []

    for item in qstring(s):
        l.append(item)

    if len(l) == 1:
        return l[0]

    return l

    
def qstring(s):
    """ A generator yielding the elements of a list containing quoted and unquoted strings """

    inobject = ""
    inquote  = ""
    isquoted = False
    level    = 0
    yields   = 0
    escaped  = False
    token    = ""

    ior = io.StringIO(s)
    iow = io.StringIO()

    c = ior.read(1)

    while c:

        # inclear.  Try to cast it to any type. If that fails, assume it's a string
        # inquote.  Quoted strings. Cannot be other thing than a string
        # inobject. Strings surrounded by '[]' or '{}'
        #

        # for implicit (quoteless) and explicitly quoted strings, pass escape sequences transparently
        # '\' preceding EOL is treated at file read time
        #
        if escaped:
            escseq = _escape_char(c, ior, inobject)
            iow.write(escseq)
            escaped = False

        elif c == '\\':
            escaped = True

        elif inobject:
            if (c == ']' and inobject == '[') or (c == '}' and inobject == '{'):
                level -= 1
            elif c == inobject:
                level += 1

            iow.write(c)

            if level == 0:
                token += _get_token(iow, False)
                inobject = ""

        # quoted strings may contain anything and are always strings
        # concatenate with previously read strings
        #
        elif inquote:
            if c == inquote:
                token += _get_token(iow, False)
                inquote = ""
            else:
                iow.write(c)
        
        # quoteless strings end when either a '"' or a "'" is input
        # concatenate this string after removing heading and trailing white space 
        #
        elif c in '\'"':
            token += _get_token(iow)
            inquote = c
            isquoted = True

        # only allow JSON formatted objects when they appear in quoteless strings
        #
        elif c in "{[":
            token += _get_token(iow)
            inobject = c
            level += 1
            iow.write(c)

        # string terminator. Must occur in a quoteless string part
        #
        elif c == ',':
            token += _get_token(iow)
            item = _typecast(token, isquoted)
            yield item
            yields += 1
            token = ""
            isquoted = False
            
        else:
            iow.write(c)

        c = ior.read(1)

    if inquote:
        raise InvalidArgument("unbalanced quotes in string: '%s'" % token)

    token += _get_token(iow)
    last_item = _typecast(token, isquoted)
    if last_item or yields == 0:
        yield last_item

    ior.close()
    iow.close()

#
# JSON serialization/deserialization
#
def toobj(string=None, fd=None):
    """ JSON formatted string to internal object """

    if fd is not None:
        try:
            obj = json.load(fd)
        except json.decoder.JSONDecodeError as je:
            obj = None
            lg.log(LOG_ERROR, "Error parsing JSON string from file: %s", je)

    elif string is None:
        obj = None
        lg.log(LOG_ERROR, "Invalid JSON string: <NULL>")

    else:
        try:
            obj = json.loads(string)
        except json.decoder.JSONDecodeError as je:
            obj = None
            lg.log(LOG_ERROR, "Error parsing JSON string: %s", je)

    return obj

def tostring(obj, fp=None, pp=None, sort=False):
    """ string representation of an object in JSON format """

    string = None

    try:
        if fp is not None:
            json.dump(obj, fp, indent=pp, sort_keys=sort)
        else:
            string = json.dumps(obj, indent=pp, sort_keys=sort)
    except (ValueError, TypeError) as te:
        lg.log(LOG_ERROR, "JSON serialization error: %s", te)

    return string

if __name__ == '__main__':

    class Modjson_test(object):

        def __init__(self):
            pass

        def run(self):
            pass

