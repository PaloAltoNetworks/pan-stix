#
# Copyright (c) 2014 Palo Alto Networks, Inc. <info@paloaltonetworks.com>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

import logging

import cybox.core
import cybox.objects.artifact_object

def get_raw_artifact_from_pcap(pcap):
    rao = cybox.core.Object()
    rao.properties = cybox.objects.artifact_object.Artifact(pcap, 
                                                            cybox.objects.artifact_object.Artifact.TYPE_NETWORK)
    rao.properties.packaging.append(cybox.objects.artifact_object.Base64Encoding())

    return rao    

def get_raw_artifact_from_pcap_hash(tag, hash, platform=None):
    import pan.wfapi

    logging.info("Retrieving pcap for hash %s/platform %s"%(hash, (platform if platform is not None else '')))

    try:
        wfapi = pan.wfapi.PanWFapi(tag=tag)
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
