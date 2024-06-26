""" A placeholder for miscellaneous applications """

import os
import sys

from modlog import LOG_ERROR, Log

# set log object for this module. We only report errors
#
lg = Log(file="stderr", facility=__name__, loglevel=LOG_ERROR)

def objmap(dct):
    """ Create an object holding references to dictionary mappings without actually copying them
        the mapped entries can be retrieved as object attributes if the corresponding dict key
        has identifier syntax ('[_a-zA-Z0-9]') otherwise the getattr() builtin must be used
    """

    if not isinstance(dct, dict):
        raise TypeError("Invalid argument type '%s'. Must be 'dict'" % type(dct).__name__)

    return type('ObjectMap', (object,), dct)

def progname():
    """ file name under which the program was invoked, removing the '.py' extension if present """

    try:
        file = getattr(sys.modules['__main__'], '__file__')
    except AttributeError:
        # likely called from the interpreter
        #
        file = 'main'

    return os.path.basename(file).rstrip('.py')
