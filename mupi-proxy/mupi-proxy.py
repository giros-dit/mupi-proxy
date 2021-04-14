# --------------------------------------------------------------------------------------------
#
# Name:        Multiple Upstream Interfaces Multicast Proxy (mupi-proxy)
#
# Description: Mupi-proxy is a proof of concept implementation of the extensions defined in 
#              IETF draft-asaeda-pim-multiif-igmpmldproxy-04 to support multiple upstream 
#              interfaces in IGMP/MLD proxies. It has been implemented for Linux using an 
#              SDN application running over Ryu controller that controls and Open vSwitch 
#              in charge of relaying the multicast data flows and IGMP/MLD traffic.
#
# Author:      Sandra Garcia (sandra.garcia.serrano at alumnos.upm.es)
#              David Fernández (david.fernandez at upm.es)
#              Raul Torres (raul.torres.garcia at alumnos.upm.es)
# --------------------------------------------------------------------------------------------
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#
# An online copy of the licence can be found at http://www.gnu.org/copyleft/gpl.html
# -----------------------------------------------------------------------------------

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser
from ryu.lib.dpid import dpid_to_str
from ryu.lib.packet import packet, ethernet, igmp, ipv4, udp, icmpv6, ipv6
from collections import defaultdict
from ryu import cfg
import json
#import dataset
#import sys
import re
import McastUpstreamRoutingTable

from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import Response
from ryu.app.wsgi import route
from ryu.app.wsgi import WSGIApplication


BASE_URL = '/mupi-proxy'

class MupiMcastProxy (app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(MupiMcastProxy, self).__init__(*args, **kwargs)
        self.logger.info('--------------------------------------') 
        self.logger.info('-- MupiMcastProxy.__init__ called') 
        # Variable initialization
        self.data = {}
        self.mac_to_port = {}
        self._to_hosts = {}
        self.switch_event = []
        self.murt = McastUpstreamRoutingTable.MURT(self.logger)
        self.data['main'] = self
        wsgi = kwargs['wsgi']
        wsgi.registory['MupiProxyApi'] = self.data
        wsgi.register(MupiProxyApi, self.data)

        # Read config params from DEFAULT section
        cfg.CONF.register_opts([
            #cfg.StrOpt('mac_to_port', default='Not configured', help = ('A string')),
            #cfg.StrOpt('to_hosts', default='Not configured', help = ('A string')),switch_event
            cfg.IntOpt('test_param1', default='0', help = ('A integer'))])
        #self.mac_to_port = json.loads(cfg.CONF.mac_to_port)
        #self._to_hosts = json.loads(cfg.CONF.to_hosts)
        test_param1 = cfg.CONF.test_param1
        #print('mac_to_port={}'.format(self.mac_to_port)) 
        #print('to_hosts={}'.format(self._to_hosts)) 
        self.logger.debug(f'test_param1={test_param1}') 

        # Create and configure murt (Multicast Upstream Routing Table)
        # by reading murt_entry lines from config file
        murt_group = cfg.oslo_config.cfg.OptGroup(name='murt')
        murt_opts= [ cfg.MultiStrOpt('murt_entry', default='', help='Multicast upstream routing table') ]
        cfg.CONF.register_group(murt_group)
        cfg.CONF.register_opts(murt_opts, group=murt_group)
        murt_cfg = cfg.CONF.murt.murt_entry

        for l in murt_cfg:
            #print(f'{l}')
            f = l.split(',')
            #print( '{:17} {:17} {:17} {:12} {:8}'.format(f[0].strip(), f[1].strip(), f[2].strip(), f[3].strip(), f[4].strip()) )
            e = [ f[0].strip(), f[1].strip(), f[2].strip(),f[3].strip(), int(f[4].strip()), int(f[5].strip())]
            #print (e)
            id = self.murt.add_entry(e)
            if id:
                self.logger.debug('Added entry {}'.format(id))
        self.logger.info('--------------------------------------') 
        self.murt.print_mcast_table(self.murt.mcast_upstream_routing, False)


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.switch_event = ev

        # Removes any flows that might have been stuck
        match = parser.OFPMatch()
        actions = []
        self.del_flow(datapath, 0, None, match, actions)

        # install table-miss flow entry
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):

        self.logger.info(f'add_flow called: match={match}, actions={actions}, priority={priority}')
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, command=ofproto.OFPFC_ADD,     
                                    priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    def del_flow(self, datapath, priority, out_port, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, command=ofproto.OFPFC_DELETE, 
                                    out_port=out_port, out_group=ofproto.OFPG_ANY, 
                                    priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, command=ofproto.OFPFC_DELETE, 
                                    out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY, 
                                    match=match, instructions=inst)
        datapath.send_msg(mod)


    def do_join(self, in_port, msg, provider, mcast_group, ipversion6):

        self.logger.debug(f'do_join called: in_port={in_port}, upstream_if={provider}, mcast_grp={mcast_group}')
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        self._to_hosts.setdefault(dpid, {})
        actions = []

        #To send both messages
        actions = [parser.OFPActionOutput(provider)]
        req = parser.OFPPacketOut(datapath, buffer_id=msg.buffer_id, data=msg.data, in_port=in_port, actions=actions)
        datapath.send_msg(req)
        actions = []

        if not self._to_hosts[dpid].get(mcast_group):
            self._to_hosts[dpid].setdefault(mcast_group, {'providers': {}})
        if not self._to_hosts[dpid][mcast_group]['providers'].get(provider):
            self._to_hosts[dpid][mcast_group]['providers'][provider] = {'ports': {}}
        if not self._to_hosts[dpid][mcast_group]['providers'][provider]['ports'].get(in_port):
            self._to_hosts[dpid][mcast_group]['providers'][provider]['ports'][in_port] = {'out': False}
            for port in self._to_hosts[dpid][mcast_group]['providers'][provider]['ports']:
                actions.append(parser.OFPActionOutput(port))
            if(ipversion6):
                match = parser.OFPMatch(eth_type=0x86DD, ip_proto=17, ipv6_dst=mcast_group, in_port=provider)
            else:
                match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, ipv4_dst=mcast_group, in_port=provider)
            self.add_flow(datapath, 1, match, actions, msg.buffer_id)
        if not self._to_hosts[dpid][mcast_group]['providers'][provider]['ports'][in_port]['out']:
            self._to_hosts[dpid][mcast_group]['providers'][provider]['ports'][in_port]['out'] = True
            self.logger.info(f"Flow added: in_port={in_port}, upstream_if={provider}, mcast_grp={mcast_group}")

    def do_leave(self, in_port, msg, provider, mcast_group, ipversion6):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        self._to_hosts.setdefault(dpid, {})
        actions = []

        #To send both messages
        actions = [parser.OFPActionOutput(provider)]
        req = parser.OFPPacketOut(datapath, buffer_id=msg.buffer_id, data=msg.data, in_port=in_port, actions=actions)
        datapath.send_msg(req)
        actions = []

        # It sends 2 Leave messages, the second must be ignored
        if len(self._to_hosts[dpid]) == 0:
            return
        if not self._to_hosts[dpid].get(mcast_group):
            return
        if not self._to_hosts[dpid][mcast_group]['providers'].get(provider):
            return
        if not self._to_hosts[dpid][mcast_group]['providers'][provider]['ports'].get(in_port):
            return

        if self._to_hosts[dpid][mcast_group]['providers'][provider]['ports'][in_port]['out']:
            self._to_hosts[dpid][mcast_group]['providers'][provider]['ports'][in_port]['out'] = False
        if self._to_hosts[dpid][mcast_group]['providers'][provider]['ports'].get(in_port):
            del self._to_hosts[dpid][mcast_group]['providers'][provider]['ports'][in_port]
            if(ipversion6):
                match = parser.OFPMatch(eth_type=0x86DD, ip_proto=17, ipv6_dst=mcast_group, in_port=provider)
            else:
                match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, ipv4_dst=mcast_group, in_port=provider)
            if len(self._to_hosts[dpid][mcast_group]['providers'][provider]['ports']) == 0:
                self.del_flow(datapath, 1, in_port, match, actions, msg.buffer_id)
            else:
                for port in self._to_hosts[dpid][mcast_group]['providers'][provider]['ports']:
                    actions.append(parser.OFPActionOutput(port))
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
        if len(self._to_hosts[dpid][mcast_group]['providers'][provider]['ports']) == 0:
            del self._to_hosts[dpid][mcast_group]['providers'][provider]['ports']
        if len(self._to_hosts[dpid][mcast_group]['providers'][provider]) == 0:
            del self._to_hosts[dpid][mcast_group]['providers'][provider]
        if len(self._to_hosts[dpid][mcast_group]['providers']) == 0:
            del self._to_hosts[dpid][mcast_group]['providers']
        if len(self._to_hosts[dpid][mcast_group]) == 0:
            del self._to_hosts[dpid][mcast_group]
        self.logger.info("Flow updated")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src

        is_udp = pkt.get_protocol(udp.udp)

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        
        #IPvX Version and Multicast Type
        mcast_in = False
        is_ipv4 = pkt.get_protocols(ipv4.ipv4)
        if is_ipv4:
            ipversion6 = False
            ip_in = is_ipv4[0]
            igmp_in = pkt.get_protocol(igmp.igmp)
            if (igmp_in and igmp_in.msgtype==0x22):
                self.logger.info("-- Multicast Listener Report received")
                self.logger.info("---- IGMPv3 Membership Report reveived")
                log = "SW=%s PORT=%d IGMP received. " % (dpid_to_str(dpid), in_port)
                mcast_in = igmp_in
        else:
            ipversion6 = True
            is_ipv6 = pkt.get_protocols(ipv6.ipv6)
            ip_in = is_ipv6[0]
            icmpv6_in = pkt.get_protocol(icmpv6.icmpv6)
            if(icmpv6_in and icmpv6_in.type_==143):
                self.logger.info("-- Multicast Listener Report received")
                self.logger.info("---- MLDv2 Multicast Listener Report received")
                log = "SW=%s PORT=%d ICMPv6-MLD received. " % (dpid_to_str(dpid), in_port)
                mcast_in = icmpv6_in.data

        #Multicast Request
        if(mcast_in):
            record = mcast_in.records[0]
            client_ip = ip_in.src
            mcast_group = record.address
            mcast_src_ip = record.srcs
            if mcast_src_ip==[]:   #It can be sent or not
                mcast_src_ip=None
            else:
                mcast_src_ip = record.srcs[0]
            #upstream_ifs = self.get_provider(client_ip, mcast_group, mcast_src_ip) # Returns the provider
            upstream_ifs, murt_entry_ids = self.murt.get_upstream_if(client_ip, mcast_group, mcast_src_ip, in_port) # Returns the upstream if and their IDs
            if upstream_ifs:
                for provider, murt_entry_id in zip(upstream_ifs, murt_entry_ids):
                    #Requested Flow + Associated Provider
                    new_flow = dict(murt_entry_id=murt_entry_id, client_ip=client_ip, downstream_if=in_port, mcast_group=mcast_group, mcast_src_ip=mcast_src_ip, upstream_if=provider)
                    #Unique ID: Flow + MurtEntry ID
                    id_flow = str(self.murt.dict_hash(new_flow))
                    #do_join operation done
                    operation = dict(id_flow=id_flow, in_port=in_port, msg=msg, provider=provider, mcast_group=mcast_group, ipversion6=ipversion6)

                    if((record.srcs==[] and record.type_==4) or (record.srcs!=[] and record.type_==3)):
                        self.logger.info("Join: " + log)
                        #Add do_join operation to operations dictionary
                        if murt_entry_id in self.murt.flows_per_murt_entry.keys():
                            self.murt.flows_per_murt_entry[murt_entry_id].append(operation)
                        else:
                            self.murt.flows_per_murt_entry[murt_entry_id] = []
                            self.murt.flows_per_murt_entry[murt_entry_id].append(operation)
                        #Add the new flow
                        self.murt.registered_flows[id_flow] = new_flow
                        #Perform Do_Join operation
                        self.do_join(in_port, msg, provider, mcast_group, ipversion6)
                    elif((record.srcs==[] and record.type_==3) or (record.srcs!=[] and record.type_==6)):
                        self.logger.info("Leave: " + log)
                        if id_flow in self.murt.registered_flows.keys():
                            #Registered operations for a specific murt entry ID
                            all_operations = self.murt.flows_per_murt_entry[murt_entry_id]
                            searched_index = -1
                            for idx, op in enumerate(all_operations):
                                if op['id_flow'] == id_flow:
                                    searched_index = idx
                            if searched_index != -1:
                                all_operations.pop(searched_index)
                                if len(all_operations) == 0:
                                    #Eliminate murt entry ID if there aren't operations
                                    del self.murt.flows_per_murt_entry[murt_entry_id]
                                else:
                                    #Save pending operations for a specific murt_entry_id
                                    self.murt.flows_per_murt_entry[murt_entry_id] = all_operations
                            del self.murt.registered_flows[id_flow]
                        self.do_leave(in_port, msg, provider, mcast_group, ipversion6)
            else: 
                self.logger.info(f'ERROR: no provider defined for query (client_ip={client_ip}, mcast_group={mcast_group}, mcast_src_ip={mcast_src_ip})')

        elif(is_udp and (dst[:8] == '33:33:00' or dst[:8] == '01:00:5e')): #Prints when no client is listening in the multicast group
            self.logger.info(f"Multicast packet received (src={ip_in.src}, dst_ip={ip_in.dst}), but no clients listening. Discarding...")

        else: #Normal switch - Example simple_switch_13.py
            self.logger.info("No ICMPv6-MLDv2, No IGMPv3 ---> NORMAL SWITCH")
            #learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = in_port
            self.logger.info(self.mac_to_port)
            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD
            actions = [parser.OFPActionOutput(out_port)]
            # install a flow to avoid packet_in next time
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions)
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)





###############################################
#             NORTHBOUND INTERFACE            #
#                   API REST                  #
###############################################
class MupiProxyApi(ControllerBase):
    # _LOGGER = None
    def __init__(self, req, link, data, **config):
        super(MupiProxyApi, self).__init__(req, link, data, **config)
        self.mupi_proxy = data['main']

###############################################
#REAL TIME FLOWS
###############################################
    # Show all used flows in real time
    @route('mupiproxy', BASE_URL + '/flows', methods=['GET'])
    def get_flows(self, req, **_kwargs):
        #table_flows = self.mupi_proxy.murt.print_flows_table(self.mupi_proxy.murt.registered_flows)
        body = json.dumps(self.mupi_proxy.murt.registered_flows, indent=4)
        return Response(content_type='application/json', status=200, body=body)

    # Show flows for a specific murt entry id
    @route('mupiproxy', BASE_URL + '/flows/{entry_id}', methods=['GET'])
    def get_flows_per_murt_entry(self, req, entry_id, **_kwargs):
        try:
            requested_id = str(entry_id)
            if requested_id in self.mupi_proxy.murt.flows_per_murt_entry.keys():
                operations = self.mupi_proxy.murt.flows_per_murt_entry[requested_id]
                searched_flows = {}
                for operation in operations:
                    searched_id = operation["id_flow"]
                    if searched_id in self.mupi_proxy.murt.registered_flows:
                        searched_flows[searched_id] = self.mupi_proxy.murt.registered_flows[searched_id]
                body = json.dumps(searched_flows, indent=4)
                table_flows = self.mupi_proxy.murt.print_flows_per_murt_table(searched_flows, requested_id)
            else:
                response = "No flows for murt entry with id: " + str(requested_id)
                body = json.dumps(response, indent=4)
            return Response(content_type='application/json', status=200, body=body)   
        except:
            response = "[ERROR] Wrong id: " + str(entry_id)
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=500, body=body)


###############################################
#MURT ENTRY
###############################################
    # Print mcast table
    @route('mupiproxy', BASE_URL + '/murtentries-table', methods=['GET'])
    def get_murt_table(self, req, **_kwargs):
        format = "json"
        body = self.mupi_proxy.murt.get_mcast_table(format, True)
        #table = self.mupi_proxy.murt.print_mcast_table(self.mupi_proxy.murt.mcast_upstream_routing, False)
        return Response(content_type='application/json', status=200, body=body)


    # List murt entries: lists the current entries in MURT
    @route('mupiproxy', BASE_URL + '/murtentries', methods=['GET'])
    def get_murt_entries(self, req, **_kwargs):
        try:
            murtentries = self.mupi_proxy.murt.retrieve_murt_entries()
            return Response(content_type='application/json', status=200, body=murtentries)
        except ValueError:
            response = "[ERROR]"
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=500, body=body)

    # Show murt entry: shows a MURT entry in detail
    @route('mupiproxy', BASE_URL + '/murtentries/{entry_id}', methods=['GET'])
    def get_murt_entry(self, req, entry_id, **_kwargs):
        try:
            murt_entry = self.mupi_proxy.murt.retrieve_murt_entry(entry_id)
            return Response(content_type='application/json', status=200, body=murt_entry)
        except:
            response = "[ERROR] Wrong id: " + str(entry_id)
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=500, body=body)

    # Add murt entry: adds a new entry in MURT
    @route('mupiproxy', BASE_URL + '/murtentries', methods=['POST'])
    def post_murt_entry(self, req, **_kwargs):
        try:
            new_entry = req.json if req.body else {}
        except ValueError:
            response = "[ERROR] Invalid data"
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=400, body=body)
        if (len(new_entry) != 6):
            response = "[ERROR] Invalid data, six parameters are required"
            body = json.dumps(response, indent=4)
            return Response(content_type='application/json', status=400, body=body)
        else:
            try:
                entry_added = self.mupi_proxy.murt.add_murt_entry(new_entry)
                if entry_added:
                    return Response(content_type='application/json', status=200, body=entry_added)
                else:
                    response = "[ERROR]"
                    body = json.dumps(response, indent=4)
                    return Response(content_type='application/json', status=400, body=body)
            except Exception as e:
                return Response(status=500)

    # Update murt entry: updates a MURT entry, reconfiguring the switch flow tables according to the modification
    @route('mupiproxy', BASE_URL + '/murtentries/{entry_id}', methods=['PUT'])
    def update_murt_entry(self, req, entry_id, **_kwargs):
        try:
            new_data = req.json if req.body else {}
        except ValueError:
            response = "[ERROR] Invalid data"
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=400, body=body)
        try:
            updated_murt_entry = self.mupi_proxy.murt.update_murt_entry(entry_id, new_data)
            return Response(content_type='application/json', status=200, body=updated_murt_entry)
        except:
            response = "[ERROR]"
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=500, body=body)

    # Delete murt entry: deletes an entry from MURT
    @route('mupiproxy', BASE_URL + '/murtentries/{entry_id}', methods=['DELETE'])
    def delete_murt_entry(self, req, entry_id, **_kwargs):
        try:
            requested_id = str(entry_id)
            #API Request
            result, flows_to_delete = self.mupi_proxy.murt.delete_murt_entry(entry_id)
            #Do leave operation to eliminate the flow installed in the switch
            self.perform_do_leave_operations(flows_to_delete)
            return Response(content_type='application/json', status=200, body=result)
        except:
            response = "[ERROR]"
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=500, body=body)

    # Clear murt entries: deletes all entries from MURT
    @route('mupiproxy', BASE_URL + '/murtentries', methods=['DELETE'])
    def delete_murt_entries(self, req, **_kwargs):
        try:
            #Reset tables
            event = self.mupi_proxy.switch_event
            self.mupi_proxy.switch_features_handler(event)
            #API Request
            result = self.mupi_proxy.murt.delete_murt_entries()
            return Response(content_type='application/json', status=200, body=result)
        except:
            response = "[ERROR]"
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=500, body=body)


###############################################
#PROVIDER
###############################################

    # Get Providers for an specific channel
    @route('mupiproxy', BASE_URL + '/channel/{channel_id}', methods=['GET'])
    def who_has_a_channel(self, req, channel_id, **_kwargs):
        try:
            providers = self.mupi_proxy.murt.who_has_a_channel(channel_id)
            if len(providers) != 0:
                table = self.mupi_proxy.murt.print_provider_table(providers)
                body = json.dumps(providers, indent=4)
            else:
                response = "There aren't providers who broadcast the requested channel: " + str(channel_id)
                body = json.dumps(response, indent=4)
            return Response(content_type='application/json', status=200, body=body)
        except:
            response = "[ERROR] Wrong id: " + str(channel_id)
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=500, body=body)

    # Print providers table
    @route('mupiproxy', BASE_URL + '/providers-table', methods=['GET'])
    def get_providers_table(self, req, **_kwargs):
        format = "json"
        extended = True
        body = self.mupi_proxy.murt.get_provider_table(format, extended)
        #table = self.mupi_proxy.murt.print_provider_table(self.mupi_proxy.murt.providers)
        return Response(content_type='application/json', status=200, body=body)

    # List content providers: lists the content providers added to the multicast proxy
    @route('mupiproxy', BASE_URL + '/providers', methods=['GET'])
    def get_providers(self, req, **_kwargs):
        try:
            providers = self.mupi_proxy.murt.retrieve_providers()
            return Response(content_type='application/json', status=200, body=providers)
        except ValueError:
            response = "[ERROR]"
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=500, body=body)

    # Show content provider: shows detailed information about a content provider such as IP address, upstream interface, among others
    @route('mupiproxy', BASE_URL + '/providers/{provider_id}', methods=['GET'])
    def get_provider(self, req, provider_id, **_kwargs):
        try:
            provider = self.mupi_proxy.murt.retrieve_provider(provider_id)
            return Response(content_type='application/json', status=200, body=provider)
        except:
            response = "[ERROR] Wrong id: " + str(provider_id)
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=500, body=body)

    # Add content provider: adds an IP multicast content provider
    @route('mupiproxy', BASE_URL + '/providers', methods=['POST'])
    def post_provider(self, req, **_kwargs):
        try:
            new_provider = req.json if req.body else {}
        except ValueError:
            response = "[ERROR] Invalid data"
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=400, body=body)
        if (len(new_provider) != 4):
            response = "[ERROR] Invalid data, four parameters are required"
            body = json.dumps(response, indent=4)
            return Response(content_type='application/json', status=400, body=body)
        else:
            try:
                provider_added = self.mupi_proxy.murt.add_provider(new_provider)
                if provider_added:
                    return Response(content_type='application/json', status=200, body=provider_added)
                else:
                    response = "[ERROR]"
                    body = json.dumps(response, indent=4)
                    return Response(content_type='application/json', status=400, body=body)
            except Exception as e:
                return Response(status=500)

    # Update content provider: updates functional parameters of a content provider
    @route('mupiproxy', BASE_URL + '/providers/{provider_id}', methods=['PUT'])
    def update_provider(self, req, provider_id, **_kwargs):
        try:
            new_data = req.json if req.body else {}
        except ValueError:
            response = "[ERROR] Invalid data"
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=400, body=body)
        try:
            updated_provider = self.mupi_proxy.murt.update_provider(provider_id, new_data)
            return Response(content_type='application/json', status=200, body=updated_provider)
        except:
            response = "[ERROR]"
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=500, body=body)

   
    # Delete content provider: deletes a content provider from the multicast proxy
    @route('mupiproxy', BASE_URL + '/providers/{provider_id}', methods=['DELETE'])
    def delete_provider(self, req, provider_id, **_kwargs):
        try:
            requested_id = str(provider_id)
            #API Request
            result, flows_to_delete = self.mupi_proxy.murt.delete_provider(provider_id)
            #Do leave operation to eliminate the flow installed in the switch
            self.perform_do_leave_operations(flows_to_delete)
            return Response(content_type='application/json', status=200, body=result)
        except:
            response = "[ERROR]"
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=500, body=body)

    # Clear content providers: deletes all the content providers from the multicast proxy
    @route('mupiproxy', BASE_URL + '/providers', methods=['DELETE'])
    def delete_providers(self, req, **_kwargs):
        try:
            #Reset tables
            event = self.mupi_proxy.switch_event
            self.mupi_proxy.switch_features_handler(event)
            result = self.mupi_proxy.murt.delete_providers()
            return Response(content_type='application/json', status=200, body=result)
        except:
            response = "[ERROR]"
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=500, body=body)

    # Activate a provider
    @route('mupiproxy', BASE_URL + '/providers/enable/{provider_id}', methods=['GET'])
    def enable_provider(self, req, provider_id, **_kwargs):
        try:
            enable_provider = self.mupi_proxy.murt.enable_provider(provider_id)
            return Response(content_type='application/json', status=200, body=enable_provider)
        except:
            response = "[ERROR] Wrong id: " + str(provider_id)
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=500, body=body)

    # Desactivate a provider
    @route('mupiproxy', BASE_URL + '/providers/disable/{provider_id}', methods=['GET'])
    def disable_provider(self, req, provider_id, **_kwargs):
        try:
            disable_provider, all_do_leave_operations, all_flows_to_takeover = self.mupi_proxy.murt.disable_provider(provider_id)
            #Re-evalute flows associated to a disabled provider (take-over)
            self.take_over_flows(all_flows_to_takeover, all_do_leave_operations)
            #Do leave operation to eliminate the flow installed in the switch
            self.perform_do_leave_operations(all_do_leave_operations)
            return Response(content_type='application/json', status=200, body=disable_provider)
        except:
            response = "[ERROR] Wrong id: " + str(provider_id)
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=500, body=body)




###############################################
#SDN CONTROLLER
###############################################
    # Print controllers table
    @route('mupiproxy', BASE_URL + '/controllers-table', methods=['GET'])
    def get_controllers_table(self, req, **_kwargs):
        format = "json"
        extended = True
        body = self.mupi_proxy.murt.get_controller_table(format, extended)
        #table = self.mupi_proxy.murt.print_controller_table(self.mupi_proxy.murt.controllers)
        return Response(content_type='application/json', status=200, body=body)


    # List SDN Controllers: lists the SDN Controllers added to the multicast proxy
    @route('mupiproxy', BASE_URL + '/controllers', methods=['GET'])
    def get_controllers(self, req, **_kwargs):
        try:
            controllers = self.mupi_proxy.murt.retrieve_controllers()
            return Response(content_type='application/json', status=200, body=controllers)
        except ValueError:
            response = "[ERROR]"
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=500, body=body)

    # Show main SDN controller: shows detailed information about the main SDN controller such as openflow version, TCP port, IP address, among others.
    @route('mupiproxy', BASE_URL + '/controllers/{controller_id}', methods=['GET'])
    def get_controller(self, req, controller_id, **_kwargs):
        try:
            controller = self.mupi_proxy.murt.retrieve_controller(controller_id)
            return Response(content_type='application/json', status=200, body=controller)
        except:
            response = "[ERROR] Wrong id: " + str(controller_id)
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=500, body=body)

    # Add main SDN controller: adds a main SDN controller. The local SDN controller of the multicast proxy is configured as secondary controller. In this light, a hierarchical multicast proxy structure is created
    @route('mupiproxy', BASE_URL + '/controllers', methods=['POST'])
    def post_controller(self, req, **_kwargs):
        try:
            new_controller = req.json if req.body else {}
        except ValueError:
            response = "[ERROR] Invalid data"
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=400, body=body)
        if (len(new_controller) != 4):
            response = "[ERROR] Invalid data, four parameters are required"
            body = json.dumps(response, indent=4)
            return Response(content_type='application/json', status=400, body=body)
        else:
            try:
                controller_added = self.mupi_proxy.murt.add_controller(new_controller)
                if controller_added:
                    return Response(content_type='application/json', status=200, body=controller_added)
                else:
                    response = "[ERROR]"
                    body = json.dumps(response, indent=4)
                    return Response(content_type='application/json', status=400, body=body)
            except Exception as e:
                return Response(status=500)

    # Update main SDN controller: updates functional parameters of the controller.
    @route('mupiproxy', BASE_URL + '/controllers/{controller_id}', methods=['PUT'])
    def update_controller(self, req, controller_id, **_kwargs):
        try:
            new_data = req.json if req.body else {}
        except ValueError:
            response = "[ERROR] Invalid data"
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=400, body=body)
        try:
            updated_controller = self.mupi_proxy.murt.update_controller(controller_id, new_data)
            return Response(content_type='application/json', status=200, body=updated_controller)
        except:
            response = "[ERROR]"
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=500, body=body)

    # Delete main SDN controller: deletes the main SDN controller. In this light, the hierarchical structure is also deleted
    @route('mupiproxy', BASE_URL + '/controllers/{controller_id}', methods=['DELETE'])
    def delete_controller(self, req, controller_id, **_kwargs):
        try:
            result = self.mupi_proxy.murt.delete_controller(controller_id)
            return Response(content_type='application/json', status=200, body=result)
        except:
            response = "[ERROR]"
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=500, body=body)

    # Clear SDN Controllers deletes all the SDN Controllers from the multicast proxy
    @route('mupiproxy', BASE_URL + '/controllers', methods=['DELETE'])
    def delete_controllers(self, req, **_kwargs):
        try:
            result = self.mupi_proxy.murt.delete_controllers()
            return Response(content_type='application/json', status=200, body=result)
        except:
            response = "[ERROR]"
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=500, body=body)


    # AUXILIAR FUNCTIONS 

    # Eliminate flows associated to a murt_entry which has been deleted or disabled
    def perform_do_leave_operations(self, operations):
        if operations != -1:
            for op in operations:
                operation = operations[op]
                in_port = operation["in_port"]
                msg = operation["msg"]
                provider = operation["provider"]
                mcast_group = operation["mcast_group"]
                ipversion6 = operation["ipversion6"]
                self.mupi_proxy.do_leave(in_port, msg, provider, mcast_group, ipversion6)

    # Find new providers for a client whose flow has been disabled due to a provider disable operation
    def take_over_flows(self, flows_to_takeover, all_do_leave_operations):
        for key in flows_to_takeover:
            flow = flows_to_takeover[key]
            # Deprecated Values
            id_flow_deleted = str(key)
            murt_entry_id_disabled = flow["murt_entry_id"]
            upstream_if_deleted = flow["upstream_if"]
            # Used values to search new providers
            client_ip = flow["client_ip"]
            mcast_group = flow["mcast_group"]
            mcast_src_ip = flow["mcast_src_ip"]
            in_port = flow["downstream_if"]
            # Searching for new providers
            upstream_ifs, murt_entry_ids = self.mupi_proxy.murt.get_upstream_if(client_ip, mcast_group, mcast_src_ip, in_port) # Returns the upstream if and their IDs
            if upstream_ifs:
                for provider, murt_entry_id in zip(upstream_ifs, murt_entry_ids):
                    #Requested Flow + Associated Provider
                    new_flow = dict(murt_entry_id=murt_entry_id, client_ip=client_ip, downstream_if=in_port, mcast_group=mcast_group, mcast_src_ip=mcast_src_ip, upstream_if=provider)
                    #Unique ID: Flow + MurtEntry ID
                    id_flow = str(self.mupi_proxy.murt.dict_hash(new_flow))

                    if id_flow in self.mupi_proxy.murt.registered_flows.keys():
                        print("Existing flow")
                    else:
                        operation_cache = all_do_leave_operations[id_flow_deleted]
                        msg = operation_cache["msg"]
                        ipversion6 = operation_cache["ipversion6"]
                        #do_join operation done
                        operation = dict(id_flow=id_flow, in_port=in_port, msg=msg, provider=provider, mcast_group=mcast_group, ipversion6=ipversion6)
                        #Add do_join operation to operations dictionary
                        if murt_entry_id in self.mupi_proxy.murt.flows_per_murt_entry.keys():
                            self.mupi_proxy.murt.flows_per_murt_entry[murt_entry_id].append(operation)
                        else:
                            self.mupi_proxy.murt.flows_per_murt_entry[murt_entry_id] = []
                            self.mupi_proxy.murt.flows_per_murt_entry[murt_entry_id].append(operation)
                        #Add the new flow
                        self.mupi_proxy.murt.registered_flows[id_flow] = new_flow
                        #Perform Do_Join operation
                        self.mupi_proxy.do_join(in_port, msg, provider, mcast_group, ipversion6)
                        print("Take-Over performed")
            else:
                print("No Providers Available")