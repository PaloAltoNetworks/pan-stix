#
# Copyright (c) 2014-2015 Palo Alto Networks, Inc. <info@paloaltonetworks.com>
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

import stix.indicator
import cybox.core
import cybox.objects.file_object
import logging

LOG = logging.getLogger(__name__)


def file_object_to_indicator(pd):
    LOG.debug('file: %s', pd)

    if 'file_name' not in pd and 'hashes' not in pd:
        return None

    if 'file_name' in pd and 'hashes' in pd:
        # if both file_name and hashes are present we split
        # the object in 2 observables within an ObservableComposition
        # object in OR. The first observable will match on file name, the
        # second observable will match on hashes
        fhd = {
            'xsi:type': 'FileObjectType',
            'hashes': pd.pop('hashes')
        }
        # improve matching performance on hashes with size
        size = pd.pop('size_in_bytes', None)
        if size is not None:
            fhd['size_in_bytes'] = size

        foh = cybox.objects.file_object.File.from_dict(fhd)
        ho = cybox.core.Observable(item=foh)

        fon = cybox.objects.file_object.File.from_dict(pd)
        no = cybox.core.Observable(item=fon)

        oc = cybox.core.ObservableComposition(operator="OR")
        oc.add(no)
        oc.add(ho)

        i = stix.indicator.Indicator()
        i.add_observable(oc)
        return i

    p = cybox.objects.file_object.File.from_dict(pd)
    i = stix.indicator.Indicator()
    o = cybox.core.Observable(item=p)
    i.add_observable(o)
    return i


def default_object_to_indicator(p):
    i = stix.indicator.Indicator()
    o = cybox.core.Observable(item=p)
    i.add_observable(o)
    return i


def object_to_indicator(p):
    pd = p.to_dict()

    if 'xsi:type' not in pd:
        return default_object_to_indicator(p)

    ptype = pd['xsi:type']
    if ptype == 'FileObjectType':
        return file_object_to_indicator(pd)

    return default_object_to_indicator(p)
