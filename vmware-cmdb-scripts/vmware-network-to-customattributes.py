#!/usr/bin/env python

import ssl
import sys
import requests
import atexit
import collections
import argparse

from pyVim import connect
from pyVmomi import vim, vmodl


def get_customfield_key(service_instance, custom_field_name):
    fields = service_instance.content.customFieldsManager.field
    for field in fields:
        if field.name == custom_field_name:
            return field.key
    return None


def get_vm_customfield_value(vm, custom_field_key):
    for custom in vm['customValue']:
        if custom.key == custom_field_key:
            return custom.value


def set_vm_customfield_value(service_instance, vm_obj, custom_field_key, custom_field_value):
    service_instance.content.customFieldsManager.SetField(entity=vm_obj, key=custom_field_key, value=custom_field_value)


def get_container_view(service_instance, obj_type, container=None):
    if not container:
        container = service_instance.content.rootFolder

    view_ref = service_instance.content.viewManager.CreateContainerView(
        container=container,
        type=obj_type,
        recursive=True
    )
    return view_ref


def collect_properties(service_instance, view_ref, obj_type, path_set=None,
                       include_mors=False):
    """
    Collect properties for managed objects from a view ref
    Check the vSphere API documentation for example on retrieving
    object properties:
        - http://goo.gl/erbFDz
    Args:
        si          (ServiceInstance): ServiceInstance connection
        view_ref (pyVmomi.vim.view.*): Starting point of inventory navigation
        obj_type      (pyVmomi.vim.*): Type of managed object
        path_set               (list): List of properties to retrieve
        include_mors           (bool): If True include the managed objects
                                       refs in the result
    Returns:
        A list of properties for the managed objects
    """
    collector = service_instance.content.propertyCollector

    # Create object specification to define the starting point of
    # inventory navigation
    obj_spec = vmodl.query.PropertyCollector.ObjectSpec()
    obj_spec.obj = view_ref
    obj_spec.skip = True

    # Create a traversal specification to identify the path for collection
    traversal_spec = vmodl.query.PropertyCollector.TraversalSpec()
    traversal_spec.name = 'traverseEntities'
    traversal_spec.path = 'view'
    traversal_spec.skip = False
    traversal_spec.type = view_ref.__class__
    obj_spec.selectSet = [traversal_spec]

    # Identify the properties to the retrieved
    property_spec = vmodl.query.PropertyCollector.PropertySpec()
    property_spec.type = obj_type

    if not path_set:
        property_spec.all = True

    property_spec.pathSet = path_set

    # Add the object and property specification to the
    # property filter specification
    filter_spec = vmodl.query.PropertyCollector.FilterSpec()
    filter_spec.objectSet = [obj_spec]
    filter_spec.propSet = [property_spec]

    # Retrieve properties
    props = collector.RetrieveContents([filter_spec])

    data = []
    for obj in props:
        properties = {}
        for prop in obj.propSet:
            properties[prop.name] = prop.val

        if include_mors:
            properties['obj'] = obj.obj

        data.append(properties)
    return data


def create_filter_spec(pc, vms):
    objSpecs = []
    for vm in vms:
        objSpec = vmodl.query.PropertyCollector.ObjectSpec(obj=vm)
        objSpecs.append(objSpec)
    filterSpec = vmodl.query.PropertyCollector.FilterSpec()
    filterSpec.objectSet = objSpecs
    propSet = vmodl.query.PropertyCollector.PropertySpec(all=False)
    propSet.type = vim.VirtualMachine
    propSet.pathSet = ['runtime.powerState']
    filterSpec.propSet = [propSet]
    return filterSpec


def filter_results(result, property, value):
    vms = []
    for item in result:
        if item[property] == value:
            vms.append(item)
    return vms


def get_vm_network_conf(vm):
    ip_data = []
    dns_common_data = []
    route_data = []
    ip_str = ''
    dns_common_str = ''
    route_str = ''

    if vm['guest.net']:
        card_index = 1
        for card in vm['guest.net']:
            if card.network:
                card_data = collections.OrderedDict()
                card_ips = []
                if card.ipConfig:
                    if card.ipConfig.ipAddress:
                        for ipAddress in card.ipConfig.ipAddress:
                            card_ips.append('{}/{}{}'.format(ipAddress.ipAddress, ipAddress.prefixLength, convert_mask_cidr(ipAddress.prefixLength)))
                        card_data['IP{}'.format(card_index)] = ','.join(card_ips)
                card_data['MAC{}'.format(card_index)] = card.macAddress
                if card.dnsConfig and card.dnsConfig.ipAddress:
                    card_data['DNS{}'.format(card_index)] = ','.join(card.dnsConfig.ipAddress)
                card_data['VLAN{}'.format(card_index)] = card.network
                card_index = card_index + 1
                ip_data.append(card_data)

    if vm['guest.ipStack']:
        ipStack_index = 1
        for ipStack in vm['guest.ipStack']:
            ipStack_data = {}
            if ipStack.dnsConfig:
                ipStack_data = {'DNS_Common{}'.format(ipStack_index): ', '.join(ipStack.dnsConfig.ipAddress)}
            if ipStack.ipRouteConfig:
                for ipRoute in ipStack.ipRouteConfig.ipRoute:
                    if ipRoute.network:
                        try:
                            if vm['guest.net'][int(ipRoute.gateway.device)].network is None:
                                vNetwork = 'Non-vNic'
                            else:
                                vNetwork = vm['guest.net'][int(ipRoute.gateway.device)].network
                        except:
                            vNetwork = 'Non-vNic'

                        if ipRoute.gateway.ipAddress:
                            route_data.append('{}/{}->{}({})'.format(ipRoute.network, ipRoute.prefixLength, ipRoute.gateway.ipAddress, vNetwork))
                        else:
                            route_data.append('{}/{}->link-local({})'.format(ipRoute.network, ipRoute.prefixLength, vNetwork))

            ipStack_index = ipStack_index + 1
            dns_common_data.append(ipStack_data)

    if ip_data:
        ip_str = '; '.join(', '.join('{}:{}'.format(key, val) for key, val in d.items()) for d in ip_data)

    if dns_common_data:
        dns_common_str = '; '.join(', '.join('{}:{}'.format(key, val) for key, val in d.items()) for d in dns_common_data)

    if route_data:
        route_str = '; '.join(route_data)

    return {'ip': ip_str, 'dns': dns_common_str, 'route': route_str}


def convert_mask_cidr(mask):
    if mask > 32:
        return ''
    else:
        bits = 0
        for i in xrange(32 - mask, 32):
            bits |= (1 << i)
        return '({}.{}.{}.{})'.format((bits & 0xff000000) >> 24, (bits & 0xff0000) >> 16, (bits & 0xff00) >> 8, (bits & 0xff))


def create_cli():
    parser = argparse.ArgumentParser(description='Add virtual machine guest network configuration into custom fields')
    parser.add_argument('-s', '--server', type=str, required=True,
                        help='vCenter address')
    parser.add_argument('-u', '--username', type=str, required=True,
                        help='vCenter user username')
    parser.add_argument('-p', '--password', required=True,
                        help='vCenter user password')
    parser.add_argument('--port', default=443,
                        help='vCenter server port (defaults to %(default)i)')
    parser.add_argument('--dry-run', action='store_false',
                        help='Only show information. Do not change anything')
    return parser


def main():
    parser = create_cli()
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    args = parser.parse_args()
    service_instance = None
    requests.packages.urllib3.disable_warnings()
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    context.verify_mode = ssl.CERT_NONE
    try:
        service_instance = connect.SmartConnect(host=args.server,
                                                user=args.username,
                                                pwd=args.password,
                                                port=int(args.port),
                                                sslContext=context)
    except Exception:
        pass

    if not service_instance:
        print("Could not connect to the specified host using "
              "specified username and password")
        sys.exit(1)
    atexit.register(connect.Disconnect, service_instance)

    vm_properties = ["name", "runtime.powerState", "guest.net", "guest.ipStack", "customValue", "guest.toolsRunningStatus"]
    lastnetworkinfokey = get_customfield_key(service_instance, 'LastNetworkInfo')
    lastroutekey = get_customfield_key(service_instance, 'LastRouteTable')

    view = get_container_view(service_instance,
                              obj_type=[vim.VirtualMachine])
    vm_data = collect_properties(service_instance, view_ref=view,
                                 obj_type=vim.VirtualMachine,
                                 path_set=vm_properties,
                                 include_mors=True)

    vms = filter_results(vm_data, 'runtime.powerState', 'poweredOn')
    vms = filter_results(vms, 'guest.toolsRunningStatus', 'guestToolsRunning')

    for vm in vms:
        conf = get_vm_network_conf(vm)
        if conf['ip'] and conf['dns']:
            if get_vm_customfield_value(vm, lastnetworkinfokey) != '{}; {}'.format(conf['ip'], conf['dns']):
                print('Custom field value changed for: {}'.format(vm['name']))
                if args.dry_run:
                    set_vm_customfield_value(service_instance, vm['obj'], lastnetworkinfokey, '{}; {}'.format(conf['ip'], conf['dns']))
                if conf['route'] and get_vm_customfield_value(vm, lastroutekey) != conf['route']:
                    if args.dry_run:
                        set_vm_customfield_value(service_instance, vm['obj'], lastroutekey, conf['route'])
    connect.Disconnect(service_instance)


if __name__ == '__main__':
    main()
