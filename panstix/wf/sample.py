import logging

import cybox.core
import cybox.objects.artifact_object

def get_raw_artifact_from_wfsample(sample):
    rao = cybox.core.Object()
    rao.properties = cybox.objects.artifact_object.Artifact(sample, 
                                                            cybox.objects.artifact_object.Artifact.TYPE_FILE)
    rao.properties.packaging.append(cybox.objects.artifact_object.Base64Encoding())

    return rao

def get_raw_artifact_from_wfsample_hash(tag, hash, debug):
    import pan.wfapi

    try:
        wfapi = pan.wfapi.PanWFapi(debug=debug,
                                   tag=tag)
    except pan.wfapi.PanWFapiError as msg:
        logging.error('pan.wfapi.PanWFapi: %s'%msg)
        return None

    try:
        wfapi.sample(hash=hash)
    except pan.wfapi.PanWFapiError as msg:
        logging.error('sample: %s' % msg)
        return None

    if (wfapi.attachment is None or not 'content' in wfapi.attachment):
        logging.error('no sample from wildfire')
        return None

    return get_raw_artifact_from_wfsample(wfapi.attachment['sample'])


