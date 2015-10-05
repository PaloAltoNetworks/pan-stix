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

# XXX in registry, maybe we should set the correct HIVE instead of
#     using the full key path
# XXX in network connection IPv6 should be handled
# XXX in http session, host header should be split in host and port

import logging

import maec.bundle.malware_action
import maec.vocabs

import cybox.core
import cybox.common
import cybox.objects.file_object
import cybox.objects.process_object
import cybox.objects.win_registry_key_object
import cybox.objects.network_connection_object
import cybox.objects.socket_address_object
import cybox.objects.address_object
import cybox.objects.port_object
import cybox.objects.dns_query_object
import cybox.objects.uri_object
import cybox.objects.http_session_object
import cybox.objects.mutex_object
import cybox.objects.dns_record_object
import cybox.objects.win_service_object
import cybox.utils

LOG = logging.getLogger(__name__)


def __associated_object_process_factory(ao, aodict):
    ao.properties = cybox.objects.process_object.Process()
    if 'pid' in aodict:
        ao.properties.pid = aodict['pid']
    if 'image_file' in aodict:
        ao.properties.image_info = cybox.objects.process_object.ImageInfo()
        ao.properties.image_info.file_name = aodict['image_file']
    if 'command' in aodict:
        ao.properties.argument_list = \
            cybox.objects.process_object.ArgumentList()
        ao.properties.argument_list.append(aodict['command'])
    return ao


def __associated_object_file_factory(ao, aodict):
    ao.properties = cybox.objects.file_object.File()
    if 'file_name' in aodict:
        ao.properties.file_name = aodict['file_name']
    if 'md5' in aodict or 'sha1' in aodict or 'sha256' in aodict:
        ao.properties.hashes = cybox.common.HashList()
        if 'md5' in aodict:
            ao.properties.hashes.append(
                cybox.common.Hash(aodict['md5'], type_="MD5")
            )
        if 'sha256' in aodict:
            ao.properties.hashes.append(
                cybox.common.Hash(aodict['sha256'], type_="SHA256")
            )
        if 'sha1' in aodict:
            ao.properties.hashes.append(
                cybox.common.Hash(aodict['sha1'], type_="SHA1")
            )
    if 'size' in aodict:
        ao.properties.size_in_bytes = aodict['size']
    if 'file_format' in aodict:
        ao.properties.file_format = aodict['file_format']
    return ao


def __associated_object_registry_factory(ao, aodict):
    ao.properties = cybox.objects.win_registry_key_object.WinRegistryKey()
    if 'key' in aodict:
        ao.properties.key = aodict['key']
    if 'subkey' in aodict:
        ao.properties.subkeys = \
            cybox.objects.win_registry_key_object.RegistrySubkeys()
        sk = cybox.objects.win_registry_key_object.WinRegistryKey()
        sk.key = aodict['subkey']
        ao.properties.subkeys.append(sk)
    if 'hive' in aodict:
        ao.properties.hive = aodict['hive']
    if 'name' in aodict or 'data' in aodict:
        ao.properties.values = \
            cybox.objects.win_registry_key_object.RegistryValues()
        rv = cybox.objects.win_registry_key_object.RegistryValue()
        if 'name' in aodict:
            rv.name = aodict['name']
        if 'data' in aodict:
            rv.data = aodict['data']
        ao.properties.values.append(rv)
    return ao


def __associated_object_networkconnection_factory(ao, aodict):
    # XXX ??? how to specify country in address object ???
    ao.properties = \
        cybox.objects.network_connection_object.NetworkConnection()

    if 'l3protocol' in aodict:
        ao.properties.layer3_protocol = aodict['l3protocol']

    if 'l4protocol' in aodict:
        ao.properties.layer4_protocol = aodict['l4protocol']

    if 'ip' in aodict or 'port' in aodict:
        ao.properties.destination_socket_address = \
            cybox.objects.socket_address_object.SocketAddress()
        ao.properties.destination_socket_address.ip_address = \
            cybox.objects.address_object.Address()

        dsa = ao.properties.destination_socket_address.ip_address
        if 'ip' in aodict:
            dsa.address_value = aodict['ip']
            dsa.category = \
                cybox.objects.address_object.Address.CAT_IPV4
        if 'port' in aodict:
            dsa.port = cybox.objects.port_object.Port()
            dsa.port.port_value = aodict['port']
            if 'l4protocol' in aodict:
                dsa.layer4_protocol = aodict['l4protocol']

    return ao


def __associated_object_dnsquery_factory(ao, aodict):
    ao.properties = cybox.objects.dns_query_object.DNSQuery()
    if 'qname' in aodict or 'qtype' in aodict or 'qclass' in aodict:
        ao.properties.question = cybox.objects.dns_query_object.DNSQuestion()
        ao.properties.question.qname = cybox.objects.uri_object.URI()

        if 'qname' in aodict:
            ao.properties.question.qname.value = aodict['qname']
            ao.properties.question.qname.type_ = \
                cybox.objects.uri_object.URI.TYPE_DOMAIN

        if 'qtype' in aodict:
            ao.properties.question.qtype = aodict['qtype']

        if 'qclass' in aodict:
            ao.properties.question.qclass = aodict['qclass']

        if 'response' in aodict:
            ao.properties.answer_resource_records = \
                cybox.objects.dns_query_object.DNSResourceRecords()

            drr = cybox.objects.dns_record_object.DNSRecord()
            if 'qname' in aodict:
                drr.domain_name = cybox.objects.uri_object.URI()
                drr.domain_name.value = aodict['qname']
                drr.domain_name.type_ = \
                    cybox.objects.uri_object.URI.TYPE_DOMAIN

            if 'qtype' in aodict:
                drr.entry_type = aodict['qtype']

            # put the response value somewhere
            if 'qtype' in aodict:
                if aodict['qtype'] == 'A':
                    drr.ip_address = cybox.objects.address_object.Address()
                    drr.ip_address.address_value = aodict['response']
                    drr.ip_address.category = \
                        cybox.objects.address_object.Address.CAT_IPV4

                elif aodict['qtype'] == 'AAA':
                    drr.ip_address = cybox.objects.address_object.Address()
                    drr.ip_address.address_value = aodict['response']
                    drr.ip_address.category = \
                        cybox.objects.address_object.Address.CAT_IPV6

                else:
                    drr.record_data = aodict['response']
            else:
                drr.record_data = aodict['response']

            ao.properties.answer_resource_records.append(drr)
    return ao


def __associated_object_httpsession_factory(ao, aodict):
    ao.properties = cybox.objects.http_session_object.HTTPSession()
    hrr = cybox.objects.http_session_object.HTTPRequestResponse()
    hrr.http_client_request = \
        cybox.objects.http_session_object.HTTPClientRequest()

    if 'method' in aodict or 'uri' in aodict:
        hrr.http_client_request.http_request_line = \
            cybox.objects.http_session_object.HTTPRequestLine()
        hrrl = hrr.http_client_request.http_request_line

        if 'method' in aodict:
            hrrl.http_method = aodict['method']

        if 'uri' in aodict:
            hrrl.value = aodict['uri']

    if 'host' in aodict or 'user_agent' in aodict:
        hrr.http_client_request.http_request_header = \
            cybox.objects.http_session_object.HTTPRequestHeader()
        hrr.http_client_request.http_request_header.parsed_header = \
            cybox.objects.http_session_object.HTTPRequestHeaderFields()
        hrrph = hrr.http_client_request.http_request_header.parsed_header

        if 'user_agent' in aodict:
            hrrph.user_agent = aodict['user_agent']

        if 'host' in aodict:
            hrrph.host = cybox.objects.http_session_object.HostField()
            hrrph.host.domain_name = cybox.objects.uri_object.URI()
            hrrph.host.domain_name.value = aodict['host']
            hrrph.host.domain_name.type_ = \
                cybox.objects.uri_object.URI.TYPE_DOMAIN

    # just because there is a bug in the serialization method in cybox
    ao.properties.http_request_response = [hrr]

    return ao


def __associated_object_mutex_factory(ao, aodict):
    ao.properties = cybox.objects.mutex_object.Mutex()
    if 'name' in aodict:
        ao.properties.name = aodict['name']
    return ao


def __associated_object_service_factory(ao, aodict):
    ao.properties = cybox.objects.win_service_object.WinService()
    if 'name' in aodict:
        ao.properties.service_name = aodict['name']
    if 'startup_command_line' in aodict:
        ao.properties.startup_command_line = aodict['startup_command_line']
    return ao


def __associated_object_factory(aodict, atype):
    ao = cybox.core.AssociatedObject()
    if aodict['type'] == 'process':
        ao = __associated_object_process_factory(ao, aodict)
    elif aodict['type'] == 'file':
        ao = __associated_object_file_factory(ao, aodict)
    elif aodict['type'] == 'registry':
        ao = __associated_object_registry_factory(ao, aodict)
    elif aodict['type'] == 'networkconnection':
        ao = __associated_object_networkconnection_factory(ao, aodict)
    elif aodict['type'] == 'dnsquery':
        ao = __associated_object_dnsquery_factory(ao, aodict)
    elif aodict['type'] == 'httpsession':
        ao = __associated_object_httpsession_factory(ao, aodict)
    elif aodict['type'] == 'mutex':
        ao = __associated_object_mutex_factory(ao, aodict)
    elif aodict['type'] == 'service':
        ao = __associated_object_service_factory(ao, aodict)
    else:
        LOG.warning('unknown associated object type in factory: %s' %
                    aodict['type'])

    ao.association_type = maec.vocabs.ActionObjectAssociationType()
    ao.association_type.value = atype

    return ao


def process_create_action(child_pid=None, ifile=None, command=None):
    action = maec.bundle.malware_action.MalwareAction()

    action.name = maec.vocabs.ProcessActionName()
    action.name.value = "create process"

    action.associated_objects = cybox.core.AssociatedObjects()
    d = {
        'type': 'process'
    }
    if child_pid is not None:
        d['pid'] = child_pid
    if ifile is not None:
        d['image_file'] = ifile
    if command is not None:
        d['command'] = command
    ao1 = __associated_object_factory(d, 'output')
    action.associated_objects.append(ao1)

    return action


def process_terminate_action(args=None):
    action = maec.bundle.malware_action.MalwareAction()

    action.name = maec.vocabs.ProcessActionName()
    action.name.value = "kill process"

    action.associated_objects = cybox.core.AssociatedObjects()
    for a in args:
        ao = __associated_object_factory(a, 'input')
        action.associated_objects.append(ao)

    return action


def file_create_action(file_name, attrs=None):
    action = maec.bundle.malware_action.MalwareAction()

    action.name = maec.vocabs.FileActionName()
    action.name.value = "create file"

    action.associated_objects = cybox.core.AssociatedObjects()
    aodict = {'type': 'file', 'file_name': file_name}
    if attrs is not None:
        for k in attrs:
            aodict[k] = attrs[k]
    ao = __associated_object_factory(aodict, 'output')
    action.associated_objects.append(ao)

    return action


def file_delete_action(file_name, attrs=None):
    action = maec.bundle.malware_action.MalwareAction()

    action.name = maec.vocabs.FileActionName()
    action.name.value = "delete file"

    action.associated_objects = cybox.core.AssociatedObjects()
    aodict = {'type': 'file', 'file_name': file_name}
    if attrs is not None:
        for k in attrs:
            aodict[k] = attrs[k]
    ao = __associated_object_factory(aodict, 'input')
    action.associated_objects.append(ao)

    return action


def file_write_action(file_name):
    action = maec.bundle.malware_action.MalwareAction()

    action.name = maec.vocabs.FileActionName()
    action.name.value = "write to file"

    action.associated_objects = cybox.core.AssociatedObjects()
    ao = __associated_object_factory(
        {'type': 'file', 'file_name': file_name},
        'input'
    )
    action.associated_objects.append(ao)

    return action


def registry_create_key_action(reg_key, reg_subkey):
    action = maec.bundle.malware_action.MalwareAction()

    action.name = maec.vocabs.RegistryActionName()
    action.name.value = "create registry key"

    action.associated_objects = cybox.core.AssociatedObjects()
    aof_args = {
        'type': 'registry'
    }
    if reg_key.startswith('HKEY_'):
        aof_args['hive'] = reg_key
        aof_args['key'] = reg_subkey
    else:
        aof_args['key'] = reg_key
        aof_args['subkey'] = reg_subkey
    ao = __associated_object_factory(aof_args, 'output')
    action.associated_objects.append(ao)

    return action


def registry_modify_key_value_action(reg_key, reg_name=None, reg_data=None):
    action = maec.bundle.malware_action.MalwareAction()

    action.name = maec.vocabs.RegistryActionName()
    action.name.value = "modify registry key value"

    action.associated_objects = cybox.core.AssociatedObjects()
    aodict = {'type': 'registry', 'key': reg_key}
    if reg_name is not None:
        aodict['name'] = reg_name
    if reg_data is not None:
        aodict['data'] = reg_data
    ao = __associated_object_factory(aodict, 'input')
    action.associated_objects.append(ao)

    return action


def registry_delete_key_value_action(reg_key):
    action = maec.bundle.malware_action.MalwareAction()

    action.name = maec.vocabs.RegistryActionName()
    action.name.value = "delete registry key value"

    action.associated_objects = cybox.core.AssociatedObjects()
    ao = __associated_object_factory(
        {'type': 'registry', 'key': reg_key},
        'input'
    )
    action.associated_objects.append(ao)

    return action


def registry_delete_key_action(reg_key):
    action = maec.bundle.malware_action.MalwareAction()

    action.name = maec.vocabs.RegistryActionName()
    action.name.value = "delete registry key"

    action.associated_objects = cybox.core.AssociatedObjects()
    ao = __associated_object_factory(
        {'type': 'registry', 'key': reg_key},
        'input'
    )
    action.associated_objects.append(ao)

    return action


def mutex_create_action(mutex_name):
    action = maec.bundle.malware_action.MalwareAction()

    action.name = maec.vocabs.SynchronizationActionName()
    action.name.value = "create mutex"

    action.associated_objects = cybox.core.AssociatedObjects()
    ao = __associated_object_factory(
        {'type': 'mutex', 'name': mutex_name},
        'output'
    )
    action.associated_objects.append(ao)

    return action


def network_tcp_action(ncdict):
    action = maec.bundle.malware_action.MalwareAction()

    action.name = maec.vocabs.NetworkActionName()
    action.name.value = "connect to socket address"

    action.associated_objects = cybox.core.AssociatedObjects()
    ncdict['l3protocol'] = 'ip'
    ncdict['l4protocol'] = 'tcp'
    ncdict['type'] = 'networkconnection'
    ao = __associated_object_factory(ncdict, 'input')
    action.associated_objects.append(ao)

    return action


def network_udp_action(ncdict):
    action = maec.bundle.malware_action.MalwareAction()

    action.name = maec.vocabs.NetworkActionName()
    action.name.value = "connect to socket address"

    action.associated_objects = cybox.core.AssociatedObjects()
    ncdict['l3protocol'] = 'ip'
    ncdict['l4protocol'] = 'udp'
    ncdict['type'] = 'networkconnection'
    ao = __associated_object_factory(ncdict, 'input')
    action.associated_objects.append(ao)

    return action


def network_dns_query_action(dqdict):
    action = maec.bundle.malware_action.MalwareAction()

    action.name = maec.vocabs.DNSActionName()
    action.name.value = "send dns query"

    action.associated_objects = cybox.core.AssociatedObjects()
    dqdict['qclass'] = 'IN'
    dqdict['type'] = 'dnsquery'
    ao = __associated_object_factory(dqdict, 'input')
    action.associated_objects.append(ao)

    return action


def network_url_action(urldict):
    action = maec.bundle.malware_action.MalwareAction()

    action.name = maec.vocabs.NetworkActionName()
    action.name.value = "connect to url"

    action.associated_objects = cybox.core.AssociatedObjects()
    urldict['type'] = 'httpsession'
    ao = __associated_object_factory(urldict, 'input')
    action.associated_objects.append(ao)

    return action


def service_create_action(name, path):
    action = maec.bundle.malware_action.MalwareAction()

    action.name = maec.vocabs.ServiceActionName()
    action.name.value = "create service"

    action.associated_objects = cybox.core.AssociatedObjects()
    ao = __associated_object_factory(
        {'type': 'service', 'name': name, 'startup_command_line': path},
        'output'
    )
    action.associated_objects.append(ao)

    return action


def service_start_action(name, path):
    action = maec.bundle.malware_action.MalwareAction()

    action.name = maec.vocabs.ServiceActionName()
    action.name.value = "create service"

    action.associated_objects = cybox.core.AssociatedObjects()
    ao = __associated_object_factory(
        {'type': 'service', 'name': name, 'startup_command_line': path},
        'input'
    )
    action.associated_objects.append(ao)

    return action


def java_api_call_action(api, args):
    action = maec.bundle.malware_action.MalwareAction()

    action.name = maec.vocabs.LibraryActionName()
    action.name.value = "call library function"

    action.action_arguments = cybox.core.ActionArguments()
    aa = cybox.core.ActionArgument()
    aa.argument_name = "API"
    aa.argument_value = "Java"
    action.action_arguments.append(aa)
    aa = cybox.core.ActionArgument()
    aa.argument_name = "Function Name"
    aa.argument_value = api
    action.action_arguments.append(aa)
    aa = cybox.core.ActionArgument()
    aa.argument_name = "Options"
    aa.argument_value = args
    action.action_arguments.append(aa)

    return action
