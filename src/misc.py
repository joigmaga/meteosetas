""" A placeholder for miscellaneous applications """

import os
import sys

from modlog import LOG_ERROR, Log

# set log object for this module. We only report errors
#
lg = Log(file="stderr", facility=__name__, loglevel=LOG_ERROR)

def dict_to_obj(dct):
    """ convert a dictionary into an object without actually copying its contents """

    class Namespace(object):
        """ a local class defining a basic object that just holds a reference to the dictionary """

        def __init__(self, dct):

            self.dct = dct

        def __getattribute__(self, name):

            dct = super().__getattribute__("dct")

            if dct:
                return dct.get(name)
            return None

    return Namespace(dct)

def progname():
    """ file name under which the program was invoked, removing the '.py' extension if present """

    try:
        file = getattr(sys.modules['__main__'], '__file__')
    except AttributeError:
        # likely called from the interpreter
        #
        file = 'main'

    return os.path.basename(file).rstrip('.py')
