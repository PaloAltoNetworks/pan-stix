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

"""This module contains the main entry points for the library.

"""

import logging

import maec.package.package
import maec.package.malware_subject
import stix.extensions.malware.maec_4_1_malware
import stix.ttp
import cybox.core
import stix.indicator
import stix.core

from .exceptions import PanStixError
from . import wf
from . import iutils

LOG = logging.getLogger(__name__)

SCORE_ALL = 0.0
SCORE_LOW = 0.1
SCORE_MEDIUM = 0.3
SCORE_HIGH = 0.8


def get_stix_ol_package_from_wfreport(**kwargs):
    """Generate a STIX package with a list of CybOX Observables extracted
    from a Wildfire report.

    The Wildfire report is retrieved using Wildfire API if *hash* and
    *tag* keyword arguments are specified, or read from a file passed via
    *report* keyword argument. *report* can be a filename or a file object.

    :param hash: Hash of the sample.
    :type hash: str
    :param tag: pan-python tag used to retrieve the report.
    :type tag: str
    :param report: filename of the Wildfire report or a file object.
    :type report: str or file
    :param evidence: can be used to retrieve only indicators associated to
        malicious behaviors with a score higher than this threshold
    :type evidence: float
    :param title: title of the package
    :type title: str
    :param short_description: short description of the package
    :type short_description: str
    :returns: A STIX Package object with the list of Observables extracted
        from the Wildfire report.
    :rtype: stix.core.STIXPackage

    """

    # get malware subject from wf submodule
    subargs = {k: v for k, v in kwargs.iteritems()
               if k in ['hash', 'tag', 'report', 'evidence']
               and kwargs[k] is not None}
    subargs['pcap'] = False
    ms = wf.get_malware_subject_from_report(**subargs)
    hash = ms.malware_instance_object_attributes.properties.hashes.sha256

    # create STIX Package
    short_description = kwargs.get('short_description', None)
    description = "Sample "+hash+" - observables"
    if short_description is not None:
        description = short_description+'. '+description
    stix_package = stix.core.STIXPackage()
    stix_header = stix.core.STIXHeader(
        short_description=short_description,
        description=description,
        title=kwargs.get('title', hash)
    )
    stix_package.stix_header = stix_header

    o = cybox.core.Observable(item=ms.malware_instance_object_attributes)
    stix_package.add_observable(o)

    if not hasattr(ms, 'findings_bundles') or ms.findings_bundles is None:
        return stix_package

    for mb in ms.findings_bundles.bundle:
        if mb.collections is None:
            continue

        for ac in mb.collections.action_collections:
            for ma in ac.action_list:
                for ao in ma.associated_objects:
                    # are you still with me ?
                    p = ao.properties
                    p.parent = None
                    o = cybox.core.Observable(item=p)
                    stix_package.add_observable(o)

    return stix_package


def get_stix_il_package_from_wfreport(**kwargs):
    """Generate a STIX package with a list of STIX Indicators extracted
    from a Wildfire report.

    The Wildfire report is retrieved using Wildfire API if *hash* and
    *tag* keyword arguments are specified, or read from a file passed via
    *report* keyword argument. *report* can be a filename or a file object.

    :param hash: Hash of the sample.
    :type hash: str
    :param tag: pan-python tag used to retrieve the report.
    :type tag: str
    :param report: filename of the Wildfire report or a file object.
    :type report: str or file
    :param evidence: can be used to retrieve only indicators associated to
        malicious behaviors with a score higher than this threshold
    :type evidence: float
    :param title: title of the package
    :type title: str
    :param short_description: short description of the package
    :type short_description: str
    :param decontext: remove context from observables, default False
    :type decontext: bool
    :returns: A STIX Package object with the list of Indicators extracted
        from the Wildfire report.
    :rtype: stix.core.STIXPackage

    """
    if kwargs.get('decontext', False):
        wf.enable_decontext()

    # get malware subject from wf submodule
    subargs = {k: v for k, v in kwargs.iteritems()
               if k in ['hash', 'tag', 'report', 'evidence']
               and kwargs[k] is not None}
    subargs['pcap'] = False
    ms = wf.get_malware_subject_from_report(**subargs)
    hash = ms.malware_instance_object_attributes.properties.hashes.sha256

    # create STIX Package
    short_description = kwargs.get('short_description', None)
    description = "Sample "+hash+" - indicators"
    if short_description is not None:
        description = short_description+'. '+description
    stix_package = stix.core.STIXPackage()
    stix_header = stix.core.STIXHeader(
        short_description=short_description,
        description=description,
        title=kwargs.get('title', hash)
    )
    stix_package.stix_header = stix_header

    o = cybox.core.Observable(item=ms.malware_instance_object_attributes)
    i = stix.indicator.Indicator()
    i.add_observable(o)
    stix_package.add_indicator(i)

    if not hasattr(ms, 'findings_bundles') or ms.findings_bundles is None:
        return stix_package

    for mb in ms.findings_bundles.bundle:
        if mb.collections is None:
            continue

        for ac in mb.collections.action_collections:
            for ma in ac.action_list:
                for ao in ma.associated_objects:
                    # are you still with me ?
                    p = ao.properties
                    p.parent = None
                    i = iutils.object_to_indicator(p)
                    if i is not None:
                        stix_package.add_indicator(i)

    return stix_package


def get_maec_package_from_wfreport(**kwargs):
    """Generate a MAEC package from a Wildfire report.

    The Wildfire report is retrieved using Wildfire API if *hash* and
    *tag* keyword arguments are specified, or read from a file passed via
    *report* keyword argument. *report* can be a filename or a file object.

    :param hash: Hash of the sample.
    :type hash: str
    :param tag: pan-python tag used to retrieve the report.
    :type tag: str
    :param report: filename of the Wildfire report or a file object.
    :type report: str or file
    :param pcap: filename of the pcap file to include or 'network' to
        retrive the pcap using Wildfire API via *tag*. If *None* pcap
        is not included in the resulting package.
    :type pcap: str
    :param evidence: can be used to retrieve only indicators associated to
        malicious behaviors with a score higher than this threshold
    :type evidence: float
    :returns: A MAEC Package object with Wildfire report contents.
    :rtype: maec.package.package.Package

    """
    # get malware subject from wf submodule
    subargs = {k: v for k, v in kwargs.iteritems()
               if k in ['hash', 'tag', 'report', 'pcap', 'evidence'] and
               kwargs[k] is not None}
    ms = wf.get_malware_subject_from_report(**subargs)

    # put it in a malwaresubjectlist
    msl = maec.package.malware_subject.MalwareSubjectList()
    msl.append(ms)

    maecpackage = maec.package.package.Package()
    maecpackage.add_malware_subject(ms)

    return maecpackage


def get_stix_package_from_wfreport(**kwargs):
    """Generate a STIX package from a Wildfire report.

    The Wildfire report is retrieved using Wildfire API if *hash* and
    *tag* keyword arguments are specified, or read from a file passed via
    *report* keyword argument. *report* can be a filename or a file object.

    :param hash: Hash of the sample.
    :type hash: str
    :param tag: pan-python tag used to retrieve the report.
    :type tag: str
    :param report: filename of the Wildfire report or a file object.
    :type report: str or file
    :param pcap: filename of the pcap file to include or 'network' to
        retrive the pcap using Wildfire API via *tag*. If *None* pcap
        is not included in the resulting package.
    :type pcap: str
    :param sample: filename of the sample file to include or 'network' to
        retrive the sample using Wildfire API via *tag*. If *None* sample
        is not included in the resulting package.
    :type sample: str
    :param evidence: can be used to retrieve only indicators associated to
        malicious behaviors with a score higher than this threshold
    :type evidence: float
    :param title: title of the package
    :type title: str
    :param short_description: short description of the package
    :type short_description: str
    :returns: A STIX Package object with Wildfire report contents.
    :rtype: stix.core.Package

    """
    LOG.debug(kwargs)

    # get malware subject from wf submodule
    subargs = {k: v for k, v in kwargs.iteritems()
               if k in ['hash', 'tag', 'report', 'pcap', 'evidence'] and
               kwargs[k] is not None}
    ms = wf.get_malware_subject_from_report(**subargs)
    hash = ms.malware_instance_object_attributes.properties.hashes.sha256

    # put it in a malwaresubjectlist
    msl = maec.package.malware_subject.MalwareSubjectList()
    msl.append(ms)

    maecpackage = maec.package.package.Package()
    maecpackage.add_malware_subject(ms)

    # create TTP
    mi = stix.extensions.malware.maec_4_1_malware.MAECInstance(maecpackage)
    ttp = stix.ttp.TTP(
        title="%s" % hash,
        description="Sample "+hash+" Artifacts and Characterization"
    )
    mb = stix.ttp.behavior.Behavior()
    mb.add_malware_instance(mi)
    ttp.behavior = mb

    # add TTP to STIX package
    short_description = kwargs.get('short_description', None)
    description = "Sample "+hash+" Artifacts and Characterization"
    if short_description is not None:
        description = short_description+'. '+description
    stix_package = stix.core.STIXPackage()
    stix_header = stix.core.STIXHeader(
        short_description=short_description,
        description=description,
        title=kwargs.get('title', hash)
    )
    stix_package.stix_header = stix_header
    stix_package.add_ttp(ttp)

    # and then add sample
    if 'sample' in kwargs:
        s = kwargs['sample']
        samplerao = None
        if s == 'network':
            if 'tag' not in kwargs:
                raise PanStixError('sample from network, but no tag specified')
            samplerao = wf.sample.get_raw_artifact_from_sample_hash(
                kwargs['tag'],
                hash
            )
        elif isinstance(s, basestring):
            f = open(s, "rb")
            sample = f.read()
            f.close()
            samplerao = wf.sample.get_raw_artifact_from_sample(sample)

        if samplerao is not None:
            i = stix.indicator.Indicator(title="Wildfire sample "+hash)
            o = cybox.core.Observable(
                description="Raw artifact object of wildfire sample "+hash,
                title="File "+hash
            )
            o.object_ = samplerao
            i.add_observable(o)
            i.add_indicated_ttp(stix.ttp.TTP(idref=ttp.id_))
            stix_package.add_indicator(i)

    return stix_package
