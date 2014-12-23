import time
import datetime
import logging

# lxml
import lxml

# STIX, MAEC and CybOX imports
import maec.package.package
import maec.package.malware_subject
import maec.package.analysis
import maec.bundle.bundle
import maec.bundle.malware_action
import maec.bundle.process_tree
import maec.bundle.behavior
import cybox.core
import cybox.common
import cybox.objects.file_object
import cybox.objects.process_object
import cybox.utils
import maec.utils

from . import maecactions

def add_malware_analysis_from_report(csubject, report, pcap=None):
    def __add_process(pid, image=None):
        if not pid in processes:
            processes[pid] = {'pid': pid, 'child': [], 'parent': None, 'parent_action': None, 'image': None, 'actions': []}
        if image is not None:
            processes[pid]['image'] = image

    def __set_process_parent(cpid, ppid, pactionid = None):
        if pactionid is not None:
            processes[cpid]['parent_action'] = pactionid
        processes[cpid]['parent'] = ppid
        processes[ppid]['child'].append(cpid)

    def __add_process_action(pid, image, aid):
        __add_process(pid, image)
        processes[pid]['actions'].append(aid)

    # analysis
    wfanalysis = maec.package.analysis.Analysis(method="dynamic", type="triage")
    now = datetime.datetime.utcnow()
    wfanalysis.lastupdate_datetime = now.strftime("%Y-%m-%dT%H:%M:%S.000000+00:00") # 2014-02-20T09:00:00.000000

    # summary with verdict
    wfsummary = "Palo Alto Networks Wildfire dynamic analysis of the malware instance object."
    verdict = report.xpath('malware/text()')
    if len(verdict) > 0:
        verdict = verdict[0].strip()
        if verdict == 'yes':
            wfsummary += " Verdict: Malware"
        else:
            wfsummary += " Verdict: Benign"
    wfanalysis.summary = wfsummary

    # XXX ??? analysis environemnt ??? maybe to specify Wildfire sandbox contents
    wftool = cybox.common.ToolInformation()
    wftool.vendor = "http://www.paloaltonetworks.com"
    wftool.name = "Palo Alto Networks Wildfire"
    wftool.version = "0.1"
    wfanalysis.add_tool(wftool)

    # create the bundle
    wfbundle = maec.bundle.bundle.Bundle(defined_subject=False)
    processes = {} # to track processes and rebuild the process tree

    # add behaviors from report <summary> to <behavior>s
    summary = report.xpath('summary')
    if len(summary) == 0:
        logging.warning('no <summary> objects in report')
    else:
        summary = summary[0]
        for sentry in summary:
            cb = maec.bundle.behavior.Behavior(description=sentry.text.strip())
            wfbundle.add_behavior(cb)

    # add process activity
    processactions = report.xpath('process')
    if len(processactions) == 0:
        logging.warning('no <process> objects inside the report')
    else:
        wfbundle.add_named_action_collection("Process Activity")
        if len(processactions) > 1:
            logging.warning('invalid number of <process> objects in report, only the first one will be analyzed')
        processactions = processactions[0]
        for cpa in processactions:
            if cpa.tag == 'process_created':
                action = maecactions.process_create_action(cpa.get('child_pid'), cpa.get('child_process_image'))
                __add_process(cpa.get('child_pid'), cpa.get('child_process_image'))
                __add_process(cpa.get('parent_pid'), cpa.get('parent_process_image'))
                __set_process_parent(cpa.get('child_pid'), cpa.get('parent_pid'), action.id_)
                __add_process_action(cpa.get('parent_pid'), cpa.get('parent_process_image'), action.id_)
            elif cpa.tag == 'process_terminated':
                action = maecactions.process_terminate_action([{'type': 'process', 
                                                            'pid': cpa.get('child_pid'), 
                                                            'image_file': cpa.get('child_process_image')}])
                __add_process(cpa.get('parent_pid'), cpa.get('parent_process_image'))
                __add_process(cpa.get('child_pid'), cpa.get('child_process_image'))
                __set_process_parent(cpa.get('child_pid'), cpa.get('parent_pid'))
                # XXX meaning of pids in process_terminated ??? __add_process_action(cpa.get('parent_pid'), None, action.id_)
            else:
                logging.warning('unknown process activity %s - ignored'%cpa.tag)
                continue
            wfbundle.add_action(action, "Process Activity")

    # add file activity
    fileactions = report.xpath('file')
    if len(fileactions) == 0:
        logging.warning('no <file> objects in report')
    else:
        if len(fileactions) > 1:
            logging.warning('invalid number of <file> objects, only the first one will be analyzed')
        wfbundle.add_named_action_collection("File Activity")
        fileactions = fileactions[0]
        for cfa in fileactions:
            if cfa.tag == 'file_deleted':
                action = maecactions.file_delete_action(cfa.get('deleted_file'))
            elif cfa.tag == 'file_written':
                action = maecactions.file_write_action(cfa.get('written_file'))
            else:
                logging.warning('unknown file activity %s - ignored'%cfa.tag)
                continue
            __add_process_action(cfa.get('pid'), cfa.get('process_image'), action.id_)
            wfbundle.add_action(action, "File Activity")

    # add registry activity
    regactions = report.xpath('registry')
    if len(regactions) == 0:
        logging.warning('no <registry> objects in report')
    else:
        if len(regactions) > 1:
            logging.warning('invalid number of <registry> objects: %d'%len(regactions))
        wfbundle.add_named_action_collection("Registry Activity")
        regactions = regactions[0]
        for cra in regactions:
            if cra.tag == 'SetValueKey':
                action = maecactions.registry_modify_key_value_action(cra.get('reg_key'))
            elif cra.tag == 'DeleteValueKey':
                action = maecactions.registry_delete_key_value_action(cra.get('reg_key'))
            elif cra.tag == 'DeleteKey':
                action = maecactions.registry_delete_key_value_action(cra.get('reg_key'))                
            else:
                logging.warning('unknown registry activity %s - ignored'%cra.tag)
                continue
            __add_process_action(cra.get('pid'), cra.get('process_image'), action.id_)
            wfbundle.add_action(action, "Registry Activity")

    # add network activity
    networkactions = report.xpath('network')
    if len(networkactions) == 0:
        logging.warning('no <network> objects in report')
    else:
        if len(networkactions) > 1:
            logging.warning('invalid number of <network> objects: %d'%len(networkactions))
        wfbundle.add_named_action_collection("Network Activity")
        networkactions = networkactions[0]
        for cna in networkactions:
            if cna.tag == 'TCP':
                action = maecactions.network_tcp_action({'ip': cna.get('ip'), 
                                            'port': cna.get('port'), 
                                            'country': cna.get('country')})
            elif cna.tag == 'UDP':
                action = maecactions.network_udp_action({'ip': cna.get('ip'), 
                                            'port': cna.get('port'), 
                                            'country': cna.get('country')})                

            elif cna.tag == 'url':
                action = maecactions.network_url_action({'host': cna.get('host'), 
                                            'method': cna.get('method'),
                                            'uri': cna.get('uri'),
                                            'user_agent': cna.get('user_agent')})
            elif cna.tag == 'dns':
                action = maecactions.network_dns_query_action({'qname': cna.get('query'), 'qtype': cna.get('type')})
            else:
                logging.warning('unknown network activity %s - ignored'%cna.tag)
                continue
            # XXX no process info for net activity __add_process_action(cna.get('pid'), cna.get('process_image'), action.id_)
            wfbundle.add_action(action, 'Network Activity')
    
    # rebuild the process tree
    processtree = maec.bundle.process_tree.ProcessTree()
    frp = maec.bundle.process_tree.ProcessTreeNode()
    frp.pid = '-1'
    frp.name = 'Fake Root Process'
    for cp in processes:
        cproc = processes[cp]
        cproc['node'] = maec.bundle.process_tree.ProcessTreeNode()
        cproc['node'].pid = cproc['pid']
        if cproc['image'] is not None:
            cproc['node'].image_info = cybox.objects.process_object.ImageInfo()
            cproc['node'].image_info.file_name = cproc['image']
        if cproc['parent_action'] is not None:
            cproc['node'].set_parent_action(cproc['parent_action'])
        for a in cproc['actions']:
            cproc['node'].add_initiated_action(a)
    for cp in processes:
        cproc = processes[cp]
        if cproc['parent'] is None:
            frp.add_spawned_process(cproc['node'])
        else:
            processes[cproc['parent']]['node'].add_spawned_process(cproc['node'])
    processtree.set_root_process(frp)
    wfbundle.process_tree = processtree

    if pcap is not None:
        logging.info('pcap insertion not supported for wildfire reports v0.1')

    wfanalysis.set_findings_bundle(wfbundle.id_)
    csubject.add_analysis(wfanalysis)
    csubject.add_findings_bundle(wfbundle)
