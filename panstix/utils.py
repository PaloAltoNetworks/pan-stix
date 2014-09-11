import logging

import cybox.utils
import maec.utils
import stix.utils

def set_id_namespace(uri, name):
    # stix
    nsdict = {}
    nsdict[uri] = name
    stix.utils.set_id_namespace(nsdict)

    # maec and cybox
    WFNS = cybox.utils.Namespace(uri, name)
    maec.utils.set_id_namespace(WFNS)
    cybox.utils.set_id_namespace(WFNS)
