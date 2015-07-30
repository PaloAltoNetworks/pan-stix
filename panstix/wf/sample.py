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

LOG = logging.getLogger(__name__)


def get_raw_artifact_from_sample(sample):
    rao = cybox.core.Object()
    rao.properties = cybox.objects.artifact_object.Artifact(
        sample,
        cybox.objects.artifact_object.Artifact.TYPE_FILE
    )
    rao.properties.packaging.append(
        cybox.objects.artifact_object.Base64Encoding()
    )

    return rao


def get_raw_artifact_from_sample_hash(tag, hash):
    import pan.wfapi

    LOG.info("Retrieving sample for hash %s" % hash)

    try:
        wfapi = pan.wfapi.PanWFapi(tag=tag)
    except pan.wfapi.PanWFapiError as msg:
        LOG.error('pan.wfapi.PanWFapi: %s' % msg)
        return None

    try:
        wfapi.sample(hash=hash)
    except pan.wfapi.PanWFapiError as msg:
        LOG.error('sample: %s' % msg)
        return None

    if (wfapi.attachment is None or 'content' not in wfapi.attachment):
        LOG.error('no sample from wildfire')
        return None

    return get_raw_artifact_from_sample(wfapi.attachment['content'])
