import sys
import os
import json

def jlatin(file=None, codec='ISO-8859-15'):
    """ read latin-1 encoded Json files. Python only accepts unicode """

    if file:
        with open(file, "rb") as f:
            jbin = f.read()
    else:
        with os.fdopen(sys.stdin.fileno(), "rb") as f:
            jbin = f.read()

    return json.loads(jbin.decode(codec))

