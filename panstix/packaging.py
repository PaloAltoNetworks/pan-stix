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

import lxml

import maec.package.package
import maec.package.malware_subject
import stix.extensions.malware.maec_4_1_malware
import stix.ttp
import cybox.core
import stix.indicator

from .exceptions import PanStixError
from . import wf
from . import threat

def get_stix_package_from_threat(t):
    stix_package = stix.core.STIXPackage()
    stix_header = stix.core.STIXHeader(title="Threat Incident", package_intents='Incident')
    stix_package.stix_header = stix_header

    stix_incident = threat.get_incident_from_threat(t)

    stix_package.add_incident(stix_incident)

    return stix_package

def get_maec_package_from_wfreport(**kwargs):
    # get malware subject from wf submodule
    subargs = {k: v for k,v in kwargs.iteritems() if k in ['hash', 'tag', 'report', 'pcap']}
    ms = wf.get_malware_subject_from_report(**subargs)
    hash = ms.malware_instance_object_attributes.properties.hashes.sha256

    # put it in a malwaresubjectlist
    msl = maec.package.malware_subject.MalwareSubjectList()
    msl.append(ms)

    maecpackage = maec.package.package.Package()
    maecpackage.add_malware_subject(ms)

    return maecpackage

def get_stix_package_from_wfreport(**kwargs):
    # get malware subject from wf submodule
    subargs = {k: v for k,v in kwargs.iteritems() if k in ['hash', 'tag', 'report', 'pcap']}
    ms = wf.get_malware_subject_from_report(**subargs)
    hash = ms.malware_instance_object_attributes.properties.hashes.sha256

    # put it in a malwaresubjectlist
    msl = maec.package.malware_subject.MalwareSubjectList()
    msl.append(ms)

    maecpackage = maec.package.package.Package()
    maecpackage.add_malware_subject(ms)

    # create TTP
    mi = stix.extensions.malware.maec_4_1_malware.MAECInstance(maecpackage)
    ttp = stix.ttp.TTP(title="%s"%hash, description="Sample "+hash+" Artifacts and Characterization")
    mb = stix.ttp.behavior.Behavior()
    mb.add_malware_instance(mi)
    ttp.behavior = mb

    # add TTP to STIX package
    stix_package = stix.core.STIXPackage()
    stix_header = stix.core.STIXHeader(description="Sample "+hash+" Artifacts and Characterization", title=hash)
    stix_package.stix_header = stix_header
    stix_package.add_ttp(ttp)

    # and then add sample
    if 'sample' in kwargs:
        s = kwargs['sample']
        samplerao = None
        if s == 'network':
            if not 'tag' in kwargs:
                raise PanStixError('sample from network, but no tag specified')
            samplerao = wf.sample.get_raw_artifact_from_sample_hash(kwargs['tag'], hash)
        elif isinstance(s, basestring):
            f = open(s, "rb")
            sample = f.read()
            f.close()
            samplerao = wf.sample.get_raw_artifact_from_sample(sample)

        if samplerao is not None:
            i = stix.indicator.Indicator(title="Wildfire sample "+hash)
            o = cybox.core.Observable(description="Raw artifact object of wildfire sample "+hash, title="File "+hash)
            o.object_ = samplerao
            i.add_observable(o)
            i.add_indicated_ttp(stix.ttp.TTP(idref=ttp.id_))
            stix_package.add_indicator(i)

    return stix_package
