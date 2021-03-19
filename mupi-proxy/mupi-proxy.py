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


mupi_proxy_instance_name = 'mupi_proxy_api_app'
BASE_URL = '/mupi-proxy'

class MupiMcastProxy (app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(MupiMcastProxy, self).__init__(*args, **kwargs)

        self.logger.info('--------------------------------------') 
        self.logger.info('-- MupiMcastProxy.__init__ called') 
        # Variable initialization
        self.mac_to_port = {}
        self._to_hosts = {}
        self.murt = McastUpstreamRoutingTable.MURT(self.logger)
        wsgi = kwargs['wsgi']
        wsgi.register(MupiProxyApi,{mupi_proxy_instance_name: self})

        # Read config params from DEFAULT section
        cfg.CONF.register_opts([
            #cfg.StrOpt('mac_to_port', default='Not configured', help = ('A string')),
            #cfg.StrOpt('to_hosts', default='Not configured', help = ('A string')),
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
                                    priority=priority, match=match,  
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
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

    # BORRAR O REVISAR DONDE COLOCAR, NO SE UTILIZA ACTUALMENTE
    def get_provider(self, client_ip, mcast_group, mcast_src_ip):
        self.clients_possible = {}
        self.providers = []
        db = dataset.connect('sqlite:///proxy-mcast.db')
        table_clients = db['clients']

        #Checks in the db the rows compatible with the condition and takes
        #the one with the highest priority
        result = db['clients'].all()
        for res in result:
            if(res['client'] == client_ip or res['client'] == None) and (res['group'] == mcast_group or res['group'] == None) and (res['source'] == mcast_src_ip or res['source'] == None):
                client = table_clients.find_one(id=res['id'])
                provider = client['provider']
                priority = client['priority']
                self.clients_possible.setdefault(priority, []).append(client)

        # With the row chosen, takes the provider value, and does join/leave
        #to that provider (server)
        if self.clients_possible != {}:
            max_key = max(self.clients_possible, key=int)

            if len(self.clients_possible[max_key]) > 1:
                for clients_max in self.clients_possible[max_key]:
                    prov = clients_max['provider']
                    self.providers.append(prov)
                return self.providers
            else:
                client_chosen = self.clients_possible[max_key][0]
                provider = client_chosen['provider']
                return provider
        else:
            self.logger.info('Not allowed - Not registered in the db') 
            return None

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        igmp_in = pkt.get_protocol(igmp.igmp)
        mld_in = False
        icmpv6_in = pkt.get_protocol(icmpv6.icmpv6)
        if(icmpv6_in):
            self.logger.info("-- ICMPv6 Packet Received")
            if(icmpv6_in.type_==143):
                mld_in = icmpv6_in.data

        #IPvX
        is_ipv6 = pkt.get_protocols(ipv6.ipv6)
        is_ipv4 = pkt.get_protocols(ipv4.ipv4)
        ipversion6 = False
        if(is_ipv6):
            ipv6_in = is_ipv6[0]
            ipversion6 = True
        elif(is_ipv4):
            ipv4_in = is_ipv4[0]
            ipversion6 = False
        else:
            self.logger.info("ERROR")


        is_udp = pkt.get_protocol(udp.udp)

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        
        #IPV6
        if(mld_in or (igmp_in and igmp_in.msgtype==0x22)):
            self.logger.info("-- Multicast Listener Report received")
            if(ipversion6):
                self.logger.info("---- MLDv2 Multicast Listener Report received")
                log = "SW=%s PORT=%d ICMPv6-MLD received. " % (dpid_to_str(dpid), in_port)
                mcast_in = mld_in
                ip_in = ipv6_in
            else:
                self.logger.info("---- IGMPv3 Membership Report reveived")
                log = "SW=%s PORT=%d IGMP received. " % (dpid_to_str(dpid), in_port)
                mcast_in = igmp_in
                ip_in = ipv4_in

            record = mcast_in.records[0]
            client_ip = ip_in.src
            mcast_group = record.address
            mcast_src_ip = record.srcs
            if mcast_src_ip==[]:   #It can be sent or not
                mcast_src_ip=None
            else:
                mcast_src_ip = record.srcs[0]
            #upstream_ifs = self.get_provider(client_ip, mcast_group, mcast_src_ip) # Returns the provider
            upstream_ifs = self.murt.get_upstream_if(client_ip, mcast_group, mcast_src_ip, in_port) # Returns the upstream if
            #prueba = self.murt.get_upstream_if_database(client_ip, mcast_group, mcast_src_ip, in_port)
            if upstream_ifs:
                for provider in upstream_ifs:
                    if((record.srcs==[] and record.type_==4) or (record.srcs!=[] and record.type_==3)):
                        self.logger.info("Join: " + log)
                        self.do_join(in_port, msg, provider, mcast_group, ipversion6)
                    elif((record.srcs==[] and record.type_==3) or (record.srcs!=[] and record.type_==6)):
                        self.logger.info("Leave: " + log)
                        self.do_leave(in_port, msg, provider, mcast_group, ipversion6)
            else: 
                self.logger.info(f'ERROR: no provider defined for query (client_ip={client_ip}, mcast_group={mcast_group}, mcast_src_ip={mcast_src_ip})')

        elif(is_udp and dst[:8] == '33:33:00'): #Prints when no client is listening in the multicast group
            self.logger.info(f"Multicast packet received (src={ipv6_in.src}, dst_ip={ipv6_in.dst}), but no clients listening. Discarding...")
        elif(is_udp and dst[:8] == '01:00:5e'): #Prints when no client is listening in the multicast group
            self.logger.info(f"Multicast packet received (src={ipv4_in.src}, dst_ip={ipv4_in.dst}), but no clients listening. Discarding...")

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
    def __init__(self, req, link, data, **config):
        super(MupiProxyApi, self).__init__(req, link, data, **config)
        self.mupi_proxy_api_rest = data[mupi_proxy_instance_name]


###############################################
#MURT ENTRY
###############################################
    @route('mupiproxy', BASE_URL + '/murtentries-table', methods=['GET'])
    def get_murt_table(self, req, **_kwargs):
        mupi_proxy = self.mupi_proxy_api_rest
        format = "json"
        extended = True
        body = mupi_proxy.murt.get_mcast_table(format, extended)
        table = mupi_proxy.murt.print_mcast_table(mupi_proxy.murt.mcast_upstream_routing, False)
        return Response(content_type='application/json', status=200, body=body)


    # List murt entries: lists the current entries in MURT
    @route('mupiproxy', BASE_URL + '/murtentries', methods=['GET'])
    def get_murt_entries(self, req, **_kwargs):
        mupi_proxy = self.mupi_proxy_api_rest
        try:
            murtentries = mupi_proxy.murt.retrieve_murt_entries()
            return Response(content_type='application/json', status=200, body=murtentries)
        except ValueError:
            response = "[ERROR]"
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=500, body=body)

    # Show murt entry: shows a MURT entry in detail
    @route('mupiproxy', BASE_URL + '/murtentries/{entry_id}', methods=['GET'])
    def get_murt_entry(self, req, entry_id, **_kwargs):
        mupi_proxy = self.mupi_proxy_api_rest
        try:
            murt_entry = mupi_proxy.murt.retrieve_murt_entry(entry_id)
            return Response(content_type='application/json', status=200, body=murt_entry)
        except:
            response = "[ERROR] Wrong id: " + str(entry_id)
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=500, body=body)

    # Add murt entry: adds a new entry in MURT
    @route('mupiproxy', BASE_URL + '/murtentries', methods=['POST'])
    def post_murt_entry(self, req, **_kwargs):
        mupi_proxy = self.mupi_proxy_api_rest
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
                entry_added = mupi_proxy.murt.add_murt_entry(new_entry)
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
        mupi_proxy = self.mupi_proxy_api_rest
        try:
            new_data = req.json if req.body else {}
        except ValueError:
            response = "[ERROR] Invalid data"
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=400, body=body)
        try:
            updated_murt_entry = mupi_proxy.murt.update_murt_entry(entry_id, new_data)
            return Response(content_type='application/json', status=200, body=updated_murt_entry)
        except:
            response = "[ERROR]"
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=500, body=body)

    # Delete murt entry: deletes an entry from MURT
    @route('mupiproxy', BASE_URL + '/murtentries/{entry_id}', methods=['DELETE'])
    def delete_murt_entry(self, req, entry_id, **_kwargs):
        mupi_proxy = self.mupi_proxy_api_rest
        try:
            result = mupi_proxy.murt.delete_murt_entry(entry_id)
            return Response(content_type='application/json', status=200, body=result)
        except:
            response = "[ERROR]"
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=500, body=body)

    # Clear murt entries: deletes all entries from MURT
    @route('mupiproxy', BASE_URL + '/murtentries', methods=['DELETE'])
    def delete_murt_entries(self, req, **_kwargs):
        mupi_proxy = self.mupi_proxy_api_rest
        try:
            result = mupi_proxy.murt.delete_murt_entries()
            return Response(content_type='application/json', status=200, body=result)
        except:
            response = "[ERROR]"
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=500, body=body)


###############################################
#PROVIDER
###############################################
    #
    @route('mupiproxy', BASE_URL + '/providers-table', methods=['GET'])
    def get_providers_table(self, req, **_kwargs):
        mupi_proxy = self.mupi_proxy_api_rest
        format = "json"
        extended = True
        body = mupi_proxy.murt.get_provider_table(format, extended)
        table = mupi_proxy.murt.print_provider_table(mupi_proxy.murt.providers)
        return Response(content_type='application/json', status=200, body=body)


    # List content providers: lists the content providers added to the multicast proxy
    @route('mupiproxy', BASE_URL + '/providers', methods=['GET'])
    def get_providers(self, req, **_kwargs):
        mupi_proxy = self.mupi_proxy_api_rest
        try:
            providers = mupi_proxy.murt.retrieve_providers()
            return Response(content_type='application/json', status=200, body=providers)
        except ValueError:
            response = "[ERROR]"
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=500, body=body)

    # Show content provider: shows detailed information about a content provider such as IP address, upstream interface, among others
    @route('mupiproxy', BASE_URL + '/providers/{provider_id}', methods=['GET'])
    def get_provider(self, req, provider_id, **_kwargs):
        mupi_proxy = self.mupi_proxy_api_rest
        try:
            provider = mupi_proxy.murt.retrieve_provider(provider_id)
            return Response(content_type='application/json', status=200, body=provider)
        except:
            response = "[ERROR] Wrong id: " + str(provider_id)
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=500, body=body)

    # Add content provider: adds an IP multicast content provider
    @route('mupiproxy', BASE_URL + '/providers', methods=['POST'])
    def post_provider(self, req, **_kwargs):
        mupi_proxy = self.mupi_proxy_api_rest
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
                provider_added = mupi_proxy.murt.add_provider(new_provider)
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
        mupi_proxy = self.mupi_proxy_api_rest
        try:
            new_data = req.json if req.body else {}
        except ValueError:
            response = "[ERROR] Invalid data"
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=400, body=body)
        try:
            updated_provider = mupi_proxy.murt.update_provider(provider_id, new_data)
            return Response(content_type='application/json', status=200, body=updated_provider)
        except:
            response = "[ERROR]"
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=500, body=body)

    # Delete content provider: deletes a content provider from the multicast proxy
    @route('mupiproxy', BASE_URL + '/providers/{provider_id}', methods=['DELETE'])
    def delete_provider(self, req, provider_id, **_kwargs):
        mupi_proxy = self.mupi_proxy_api_rest
        try:
            result = mupi_proxy.murt.delete_provider(provider_id)
            return Response(content_type='application/json', status=200, body=result)
        except:
            response = "[ERROR]"
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=500, body=body)

    # Clear content providers: deletes all the content providers from the multicast proxy
    @route('mupiproxy', BASE_URL + '/providers', methods=['DELETE'])
    def delete_providers(self, req, **_kwargs):
        mupi_proxy = self.mupi_proxy_api_rest
        try:
            result = mupi_proxy.murt.delete_providers()
            return Response(content_type='application/json', status=200, body=result)
        except:
            response = "[ERROR]"
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=500, body=body)



###############################################
#SDN CONTROLLER
###############################################
    @route('mupiproxy', BASE_URL + '/controllers-table', methods=['GET'])
    def get_controllers_table(self, req, **_kwargs):
        mupi_proxy = self.mupi_proxy_api_rest
        format = "json"
        extended = True
        body = mupi_proxy.murt.get_controller_table(format, extended)
        table = mupi_proxy.murt.print_controller_table(mupi_proxy.murt.controllers)
        return Response(content_type='application/json', status=200, body=body)


    # List SDN Controllers: lists the SDN Controllers added to the multicast proxy
    @route('mupiproxy', BASE_URL + '/controllers', methods=['GET'])
    def get_controllers(self, req, **_kwargs):
        mupi_proxy = self.mupi_proxy_api_rest
        try:
            controllers = mupi_proxy.murt.retrieve_controllers()
            return Response(content_type='application/json', status=200, body=controllers)
        except ValueError:
            response = "[ERROR]"
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=500, body=body)

    # Show main SDN controller: shows detailed information about the main SDN controller such as openflow version, TCP port, IP address, among others.
    @route('mupiproxy', BASE_URL + '/controllers/{controller_id}', methods=['GET'])
    def get_controller(self, req, controller_id, **_kwargs):
        mupi_proxy = self.mupi_proxy_api_rest
        try:
            controller = mupi_proxy.murt.retrieve_controller(controller_id)
            return Response(content_type='application/json', status=200, body=controller)
        except:
            response = "[ERROR] Wrong id: " + str(controller_id)
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=500, body=body)

    # Add main SDN controller: adds a main SDN controller. The local SDN controller of the multicast proxy is configured as secondary controller. In this light, a hierarchical multicast proxy structure is created
    @route('mupiproxy', BASE_URL + '/controllers', methods=['POST'])
    def post_controller(self, req, **_kwargs):
        mupi_proxy = self.mupi_proxy_api_rest
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
                controller_added = mupi_proxy.murt.add_controller(new_controller)
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
        mupi_proxy = self.mupi_proxy_api_rest
        try:
            new_data = req.json if req.body else {}
        except ValueError:
            response = "[ERROR] Invalid data"
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=400, body=body)
        try:
            updated_controller = mupi_proxy.murt.update_controller(controller_id, new_data)
            return Response(content_type='application/json', status=200, body=updated_controller)
        except:
            response = "[ERROR]"
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=500, body=body)

    # Delete main SDN controller: deletes the main SDN controller. In this light, the hierarchical structure is also deleted
    @route('mupiproxy', BASE_URL + '/controllers/{controller_id}', methods=['DELETE'])
    def delete_controller(self, req, controller_id, **_kwargs):
        mupi_proxy = self.mupi_proxy_api_rest
        try:
            result = mupi_proxy.murt.delete_controller(controller_id)
            return Response(content_type='application/json', status=200, body=result)
        except:
            response = "[ERROR]"
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=500, body=body)

    # Clear SDN Controllers deletes all the SDN Controllers from the multicast proxy
    @route('mupiproxy', BASE_URL + '/controllers', methods=['DELETE'])
    def delete_controllers(self, req, **_kwargs):
        mupi_proxy = self.mupi_proxy_api_rest
        try:
            result = mupi_proxy.murt.delete_controllers()
            return Response(content_type='application/json', status=200, body=result)
        except:
            response = "[ERROR]"
            body = json.dumps(response, indent=4)
            raise Response(content_type='application/json', status=500, body=body)