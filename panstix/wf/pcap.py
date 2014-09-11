import logging

import cybox.core
import cybox.objects.artifact_object

def get_raw_artifact_from_pcap(pcap):
    rao = cybox.core.Object()
    rao.properties = cybox.objects.artifact_object.Artifact(pcap, 
                                                            cybox.objects.artifact_object.Artifact.TYPE_NETWORK)
    rao.properties.packaging.append(cybox.objects.artifact_object.Base64Encoding())

    return rao    

def get_raw_artifact_from_pcap_hash(tag, hash, debug, platform=None):
    import pan.wfapi

    logging.info("Retrieving pcap for hash %s/platform %s"%(hash, (platform if platform is not None else '')))

    try:
        wfapi = pan.wfapi.PanWFapi(debug=debug, tag=tag)
    except pan.wfapi.PanWFapi as msg:
        logging.error('pan.wfapi.PanWFapi: %s'%msg)
        return None

    try:
        wfapi.pcap(hash=hash, platform=platform)
    except pan.wfapi.PanWFapiError as msg:
        logging.error('pcap: %s'%msg)
        return None

    if (wfapi.attachment is None or not 'content' in wfapi.attachment):
        logging.error('no pcap from wildfire')
        return None

    return get_raw_artifact_from_pcap(wfapi.attachment['content'])
