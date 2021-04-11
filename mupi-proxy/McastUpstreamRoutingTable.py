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
# Author:      David Fernández (david.fernandez at upm.es)
#              Sandra Garcia (sandra.garcia.serrano at alumnos.upm.es)
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
from netaddr import *
import secrets
import json
from pymongo import MongoClient
from bson import ObjectId
from typing import Dict, Any
import hashlib
from bson.son import SON
import pprint
from time import time

MONGO_DETAILS = "mongodb://192.168.122.1:27017"


class MURT:

    def __init__(self, logger):
        self.mcast_upstream_routing = {}
        self.providers = {}
        self.controllers = {}
        #To show flows in real time
        self.registered_flows = {}
        #To manage API Operations in Switch in Real Time
        self.flows_per_murt_entry = {}
        self.logger = logger
        self.client = MongoClient(MONGO_DETAILS)
        self.db= self.client.mupiproxy
        self.loadFromDatabase()

    # Hash fucntion to generate object IDs (to avoid duplicate entries in tables)
    def dict_hash(self, dictionary: Dict[str, Any]) -> str:
        dhash = hashlib.md5()
        encoded = json.dumps(dictionary, sort_keys=True).encode()
        dhash.update(encoded)
        return dhash.hexdigest()

    #Upload data stored in database
    def loadFromDatabase(self):
        #murt_entries
        murt_entries_array = list(self.db.murtentries.find())
        for entry in murt_entries_array:
            object_id = entry["_id"]
            id = str(object_id)
            self.mcast_upstream_routing[id] = entry
        #providers
        providers_array = list(self.db.providers.find())
        for provider in providers_array:
            object_id = provider["_id"]
            id = str(object_id)
            self.providers[id] = provider
        #controllers
        controllers_array = list(self.db.controllers.find())
        for controller in controllers_array:
            object_id = controller["_id"]
            id = str(object_id)
            self.controllers[id] = controller

    #HELPER FUNCTIONS
    #For parsing the results from a database query into a Python dict
    def provider_helper(self, provider) -> dict:
        return {
            "description": provider["description"],
            "mcast_src_ip": provider["mcast_src_ip"],
            "upstream_if": provider["upstream_if"],
            "mcast_groups": provider["mcast_groups"],
        }


    def murtentry_helper(self, murtentry) -> dict:
        return {
            "client_ip": murtentry["client_ip"],
            "downstream_if": murtentry["downstream_if"],
            "mcast_group": murtentry["mcast_group"],
            "mcast_src_ip": murtentry["mcast_src_ip"],
            "upstream_if": murtentry["upstream_if"],
            "priority": murtentry["priority"],
        }


    def sdncontroller_helper(self, sdncontroller) -> dict:
        return {
            "openflow_version": sdncontroller["openflow_version"],
            "tcp_port": sdncontroller["tcp_port"],
            "ip_address": sdncontroller["ip_address"],
            "description": sdncontroller["description"],
        }

    # Upstream Interface (Query to memory table)
    def get_upstream_if(self, client_ip, mcast_group, mcast_src_ip, downstream_if):
        # Dives the mcast-proxy routing table and gets the highest priority entries that match the query
        tiempo_inicial = time()
        self.logger.debug(f'get_upstream_if query: client_ip={client_ip}, mcast_group={mcast_group}, mcast_src_ip={mcast_src_ip}, downstream_if={downstream_if}')
        match_entries = {}
        upstream_ifs = []
        murt_entry_ids = []

        client_ip_num = str(IPAddress(client_ip))
        mcast_group_num = str(IPAddress(mcast_group))

        max_priority = -1
        #for e in self.mcast_upstream_routing:
        for key in self.mcast_upstream_routing.keys():
            e = self.mcast_upstream_routing[key]
            if ( mcast_src_ip != '' and mcast_src_ip != None ):
                mcast_src_ip_num = str(IPAddress(mcast_src_ip))
                if (      ( e['client_ip_first'] == ''    or ( client_ip_num    >= e['client_ip_first']    and client_ip_num    <= e['client_ip_last'] ) ) 
                      and ( e['mcast_group_first'] == ''  or ( mcast_group_num  >= e['mcast_group_first']  and mcast_group_num  <= e['mcast_group_last']  ))
                      and ( e['mcast_src_ip_first'] == '' or ( mcast_src_ip_num >= e['mcast_src_ip_first'] and mcast_src_ip_num <= e['mcast_src_ip_last'] ))
                      and ( e['downstream_if'] == '' or ( str(downstream_if) == e['downstream_if']) )):
                    match_entries[key] = e
                    if e['priority'] > max_priority:
                        max_priority = e['priority']
            else:
                if (      ( e['client_ip_first'] == ''    or ( client_ip_num    >= e['client_ip_first']    and client_ip_num    <= e['client_ip_last'] ) ) 
                        and ( e['mcast_group_first'] == ''  or ( mcast_group_num  >= e['mcast_group_first']  and mcast_group_num  <= e['mcast_group_last']  )) 
                        and ( e['downstream_if'] == '' or ( str(downstream_if) == e['downstream_if']) )):
                    match_entries[key] = e
                    if e['priority'] > max_priority:
                        max_priority = e['priority']


        self.logger.debug('Matching entries:')
        self.print_mcast_table(match_entries, False)
        # Return the upstream interfaces of the entries with the highest priority
        #for e in match_entries:
        for key in match_entries.keys():
            e = match_entries[key]
            if e['priority'] == max_priority:
                upstream_ifs.append(e['upstream_if'])
                murt_entry_ids.append(key)
        self.logger.debug(f'Upstream ifs selected: {upstream_ifs}')
        tiempo_final = time()
        tiempo_ejecucion = tiempo_final - tiempo_inicial
        print ('El tiempo de ejecucion fue:'+ str(tiempo_ejecucion))
        return upstream_ifs, murt_entry_ids

    # Database query, less efficient
    def get_upstream_if_database(self, client_ip, mcast_group, mcast_src_ip, downstream_if):
        self.logger.info("CONSULTA A LA BBDD")
        tiempo_inicial = time()
        # Dives the mcast-proxy routing table and gets the highest priority entries that match the query
        self.logger.debug(f'get_upstream_if query: client_ip={client_ip}, mcast_group={mcast_group}, mcast_src_ip={mcast_src_ip}, downstream_if={downstream_if}')
        match_entries = {}
        upstream_ifs = []
        client_ip_num = str(IPAddress(client_ip))
        mcast_group_num = str(IPAddress(mcast_group))
        downstream_if = str(downstream_if)
        if ( mcast_src_ip != '' and mcast_src_ip != None):
            mcast_src_ip_num = str(IPAddress(mcast_src_ip))
            database_match = list(self.db.murtentries.aggregate([{"$match":{"$or":[{"client_ip_first":{ "$eq":''}},{"$and":[{"client_ip_first":{ "$lte": client_ip_num}},{"client_ip_last":{ "$gte": client_ip_num}}]}]}},{"$match":{"$or":[{"mcast_group_first":{ "$eq":''}},{"$and":[{"mcast_group_first":{ "$lte": mcast_group_num}},{"mcast_group_last":{ "$gte": mcast_group_num}}]}]}},{"$match":{"$or":[{"mcast_src_ip_first":{ "$eq":''}},{"$and":[{"mcast_src_ip_first":{ "$lte": mcast_src_ip_num}},{"mcast_src_ip_last":{ "$gte": mcast_src_ip_num}}]}]}},{"$match":{"$or":[{"downstream_if":{ "$eq":''}},{"downstream_if":{"$eq": downstream_if}}]}},{"$group":{"_id":"$priority", "matched_entries":{"$push":"$$ROOT"}, "count":{"$sum":1}}},{"$sort": SON([("priority", -1)])},{"$limit":1}]))
        else:
            database_match = list(self.db.murtentries.aggregate([{"$match":{"$or":[{"client_ip_first":{ "$eq":''}},{"$and":[{"client_ip_first":{ "$lte": client_ip_num}},{"client_ip_last":{ "$gte": client_ip_num}}]}]}},{"$match":{"$or":[{"mcast_group_first":{ "$eq":''}},{"$and":[{"mcast_group_first":{ "$lte": mcast_group_num}},{"mcast_group_last":{ "$gte": mcast_group_num}}]}]}},{"$match":{"$or":[{"downstream_if":{ "$eq":''}},{"downstream_if":{"$eq": downstream_if}}]}},{"$group":{"_id":"$priority", "matched_entries":{"$push":"$$ROOT"}, "count":{"$sum":1}}},{"$sort": SON([("priority", -1)])},{"$limit":1}]))
        #pprint.pprint(database_match)
        if len(database_match) > 0:    
            result = database_match[0]["matched_entries"]
            for i in result:
                match_entries[i["_id"]] = i
                upstream_ifs.append(i['upstream_if'])
            self.logger.debug('Matching entries:')
            self.print_mcast_table(match_entries, False)
            self.logger.debug(f'Upstream ifs selected: {upstream_ifs}')
            tiempo_final = time()
            tiempo_ejecucion = tiempo_final - tiempo_inicial
            print ('El tiempo de ejecucion fue:'+ str(tiempo_ejecucion))
            return upstream_ifs
        else:
            return -1





#######################################################
#######################################################
#                API REST OPERATIONS                  #
#######################################################
#######################################################


###############################################
#MURT ENTRY
###############################################
    # List murt entries: lists the current entries in MURT
    def retrieve_murt_entries(self):
        murtentries = []
        for key in self.mcast_upstream_routing:
            murt_entry = self.mcast_upstream_routing[key]
            requested_entry = self.murtentry_helper(murt_entry)
            requested_entry["_id"]=key
            murtentries.append(requested_entry)
        if len(murtentries) != 0:
            body = json.dumps(murtentries, indent=4)
        else:
            response = "There aren't murt entries in database"
            body = json.dumps(response, indent=4)
        #return self.mcast_upstream_routing
        return body

    # Show murt entry: shows a MURT entry in detail
    def retrieve_murt_entry(self, id) -> dict:
        if id in self.mcast_upstream_routing:
            murtentry = self.mcast_upstream_routing[id]
            body = json.dumps(murtentry, indent=4)
        else:
            response = "No murt entry with id: " + str(id)
            body = json.dumps(response, indent=4)
        return body

    # Add murt entry: adds a new entry in MURT
    def add_murt_entry(self, entry) -> dict:

        # client_ip
        if ( entry["client_ip"] == '' ):
            client_ip = client_ip_first = client_ip_last = ''
        else:
            try:
                client_ip = entry["client_ip"]
                client_ip_first = str(IPAddress(IPNetwork(entry["client_ip"]).first))
                client_ip_last  = str(IPAddress(IPNetwork(entry["client_ip"]).last))
            except ValueError:
                self.logger.error(f'-- ERROR: {entry["client_ip"]} is not a valid IP address or network.')
                return -1

        # downstream interface
        if ( entry["downstream_if"] == '' ):
            downstream_if = ''
        else:
            try:
                downstream_if = entry["downstream_if"]
            except ValueError:
                self.logger.error(f'-- ERROR: {entry["downstream_if"]} is not a valid downstream interface')
                return -1

        # mcast_group
        if ( entry["mcast_group"] == '' ):
            mcast_group = mcast_group_first = mcast_group_last = ''
        else:
            try:
                mcast_group = entry["mcast_group"]
                mcast_group_first = str(IPAddress(IPNetwork(entry["mcast_group"]).first))
                mcast_group_last  = str(IPAddress(IPNetwork(entry["mcast_group"]).last))
            except ValueError:
                self.logger.error(f'-- ERROR: {entry["mcast_group"]} is not a valid IP address or network.')
                return -1

        # mcast_src_ip
        if ( entry["mcast_src_ip"] == '' ):
            mcast_src_ip = mcast_src_ip_first = mcast_src_ip_last = ''
        else:
            try:
                mcast_src_ip = entry["mcast_src_ip"]
                mcast_src_ip_first = str(IPAddress(IPNetwork(entry["mcast_src_ip"]).first))
                mcast_src_ip_last  = str(IPAddress(IPNetwork(entry["mcast_src_ip"]).last))
            except ValueError:
                self.logger.error(f'-- ERROR: {entry["mcast_src_ip"]} is not a valid IP address or network.')
                return -1
     
        new_entry = dict(client_ip=client_ip, client_ip_first=client_ip_first, client_ip_last=client_ip_last, downstream_if=downstream_if,\
                           mcast_group=mcast_group, mcast_group_first=mcast_group_first, mcast_group_last=mcast_group_last, \
                           mcast_src_ip=mcast_src_ip, mcast_src_ip_first=mcast_src_ip_first, mcast_src_ip_last=mcast_src_ip_last,
                           upstream_if=entry["upstream_if"], priority=entry["priority"])

        proposed_id = self.dict_hash(new_entry)
        if proposed_id in self.mcast_upstream_routing:
            response = "Duplicated entry"
            body = json.dumps(response, indent=4)
            return body
        else:
            new_entry["_id"]=proposed_id
            result = self.db.murtentries.insert_one(new_entry)
            #entry_id.acknowledged PARA COMPROBACIONES
            entry_id = str(result.inserted_id)
            self.mcast_upstream_routing[entry_id] = new_entry
            new_murtentry = self.retrieve_murt_entry(entry_id)
            return new_murtentry

    #Upload murt entries from a configuration file
    def add_entry(self, entry):

        # client_ip
        if ( entry[0] == '' ):
            client_ip = client_ip_first = client_ip_last = ''
        else:
            try:
                client_ip = entry[0]
                client_ip_first = str(IPAddress(IPNetwork(entry[0]).first))
                client_ip_last  = str(IPAddress(IPNetwork(entry[0]).last))
            except ValueError:
                self.logger.error(f'-- ERROR: {entry[0]} is not a valid IP address or network.')
                return -1

        # downstream interface
        if ( entry[1] == '' ):
            downstream_if = ''
        else:
            try:
                downstream_if = entry[1]
            except ValueError:
                self.logger.error(f'-- ERROR: {entry[1]} is not a valid downstream interface')
                return -1

        # mcast_group
        if ( entry[2] == '' ):
            mcast_group = mcast_group_first = mcast_group_last = ''
        else:
            try:
                mcast_group = entry[2]
                mcast_group_first = str(IPAddress(IPNetwork(entry[2]).first))
                mcast_group_last  = str(IPAddress(IPNetwork(entry[2]).last))
            except ValueError:
                self.logger.error(f'-- ERROR: {entry[2]} is not a valid IP address or network.')
                return -1

        # mcast_src_ip
        if ( entry[3] == '' ):
            mcast_src_ip = mcast_src_ip_first = mcast_src_ip_last = ''
        else:
            try:
                mcast_src_ip = entry[3]
                mcast_src_ip_first = str(IPAddress(IPNetwork(entry[3]).first))
                mcast_src_ip_last  = str(IPAddress(IPNetwork(entry[3]).last))
            except ValueError:
                self.logger.error(f'-- ERROR: {entry[3]} is not a valid IP address or network.')
                return -1


        new_entry = dict(client_ip=client_ip, client_ip_first=client_ip_first, client_ip_last=client_ip_last, downstream_if=downstream_if, \
                                   mcast_group=mcast_group, mcast_group_first=mcast_group_first, mcast_group_last=mcast_group_last, \
                                   mcast_src_ip=mcast_src_ip, mcast_src_ip_first=mcast_src_ip_first, mcast_src_ip_last=mcast_src_ip_last,
                                   upstream_if=entry[4], priority=entry[5])

        proposed_id = self.dict_hash(new_entry)
        if proposed_id in self.mcast_upstream_routing:
            duplicated = {"error":"yes"}
            return duplicated
        else:
            new_entry["_id"]=proposed_id
            result = self.db.murtentries.insert_one(new_entry)
            #entry_id.acknowledged PARA COMPROBACIONES
            entry_id = str(result.inserted_id)
            self.mcast_upstream_routing[entry_id] = new_entry
            return entry_id


    # Update murt entry: updates a MURT entry, reconfiguring the switch flow tables according to the modification
    def update_murt_entry(self, id, entry):
        # Return false if an empty request body is sent.
        if len(entry) < 1:
            return False
        if id in self.mcast_upstream_routing:
            murtentry = self.mcast_upstream_routing[id]
            # client_ip
            try:
                if ( entry["client_ip"] == '' ):
                    client_ip = client_ip_first = client_ip_last = ''
                else:
                    client_ip = entry["client_ip"]
                    client_ip_first = str(IPAddress(IPNetwork(entry["client_ip"]).first))
                    client_ip_last  = str(IPAddress(IPNetwork(entry["client_ip"]).last))
            except:
                client_ip = murtentry["client_ip"]
                client_ip_first = murtentry["client_ip_first"]
                client_ip_last  = murtentry["client_ip_last"]

            # downstream interface
            try:
                if ( entry["downstream_if"] == '' ):
                    downstream_if = ''
                else:
                    downstream_if = entry["downstream_if"]
            except:
                downstream_if = murtentry["downstream_if"]

            # mcast_group
            try:
                if ( entry["mcast_group"] == '' ):
                    mcast_group = mcast_group_first = mcast_group_last = ''
                else:
                    mcast_group = entry["mcast_group"]
                    mcast_group_first = str(IPAddress(IPNetwork(entry["mcast_group"]).first))
                    mcast_group_last  = str(IPAddress(IPNetwork(entry["mcast_group"]).last))
            except:
                mcast_group = murtentry["mcast_group"]
                mcast_group_first = murtentry["mcast_group_first"]
                mcast_group_last  = murtentry["mcast_group_last"]

            # mcast_src_ip
            try:
                if ( entry["mcast_src_ip"] == '' ):
                    mcast_src_ip = mcast_src_ip_first = mcast_src_ip_last = ''
                else:
                    mcast_src_ip = entry["mcast_src_ip"]
                    mcast_src_ip_first = str(IPAddress(IPNetwork(entry["mcast_src_ip"]).first))
                    mcast_src_ip_last  = str(IPAddress(IPNetwork(entry["mcast_src_ip"]).last))
            except:
                mcast_src_ip = murtentry["mcast_src_ip"]
                mcast_src_ip_first = murtentry["mcast_src_ip_first"]
                mcast_src_ip_last  = murtentry["mcast_src_ip_last"]

            # upstream interface
            try:
                if ( entry["upstream_if"] == '' ):
                    upstream_if = ''
                else:
                    upstream_if = entry["upstream_if"]
            except:
                upstream_if = murtentry["upstream_if"]

            # priority
            try:
                if ( entry["priority"] == '' ):
                    priority = ''
                else:
                    priority = entry["priority"]
            except:
                priority = murtentry["priority"]

            new_entry = dict(client_ip=client_ip, client_ip_first=client_ip_first, client_ip_last=client_ip_last, downstream_if=downstream_if,\
                                   mcast_group=mcast_group, mcast_group_first=mcast_group_first, mcast_group_last=mcast_group_last, \
                                   mcast_src_ip=mcast_src_ip, mcast_src_ip_first=mcast_src_ip_first, mcast_src_ip_last=mcast_src_ip_last,
                                   upstream_if=upstream_if, priority=priority)
         
            myquery = { "_id": id }
            self.db.murtentries.update(myquery, new_entry)    
            new_entry["_id"]=id
            self.mcast_upstream_routing[id] = new_entry
            updated_murtentry = self.retrieve_murt_entry(id)
            return updated_murtentry

    # Delete murt entry: deletes an entry from MURT
    def delete_murt_entry(self, id):
        if id in self.mcast_upstream_routing:
            murtentry = self.mcast_upstream_routing[id]
            requested_id = str(id)
            flows_to_delete = self.find_flows(id)
            if len(flows_to_delete) == 0:
                flows_to_delete = -1
            del self.mcast_upstream_routing[id]
            myquery = { "_id": id }
            self.db.murtentries.delete_one(myquery)
            response = "Deleted entry with id: " + str(id)
        else:
            response = "No murt entry with id: " + str(id)
            flows_to_delete = -1
        body = json.dumps(response, indent=4)
        return body, flows_to_delete

    # Clear murt entries: deletes all entries from MURT
    def delete_murt_entries(self):
        self.mcast_upstream_routing = {}
        self.registered_flows = {}
        self.flows_per_murt_entry = {}
        result = self.db.murtentries.delete_many({})
        if (len(self.mcast_upstream_routing) == 0 and result.deleted_count != 0):
            response = str(result.deleted_count) + " murt entries deleted."
        else:
            response = "Empty table"
        body = json.dumps(response, indent=4)
        return response

    # Print mcast table
    def print_mcast_table(self, mcast_table, extended):
        if extended:
            self.logger.info( '{:31} {:14} {:31} {:31} {:12} {:8} {:16}'.format('client_ip', 'downstream_if', 'mcast_group', 'mcast_src_ip', 'upstream_if', 'priority','id') )
            self.logger.info( '{:31} {:14} {:31} {:31} {:12} {:8} {:16}'.format('-------------------------------', '--------------', '-------------------------------', '-------------------------------', '------------', '--------', '----------------') )
            #for e in mcast_table:
            for key in mcast_table.keys():
                e = mcast_table[key]
                if e['client_ip_first'] != '':
                    client_ip = str(IPAddress(e['client_ip_first'])) + '-' + str(IPAddress(e['client_ip_last']))
                else:
                    client_ip = ''
                if e['mcast_group_first'] != '':
                    mcast_group = str(IPAddress(e['mcast_group_first'])) + '-' + str(IPAddress(e['mcast_group_last']))
                else:
                    mcast_group = ''
                if e['mcast_src_ip_first'] != '':
                    mcast_src_ip = str(IPAddress(e['mcast_src_ip_first'])) + '-' + str(IPAddress(e['mcast_src_ip_last']))
                else:
                    mcast_src_ip = ''
                self.logger.info( '{:31} {:^14} {:31} {:31} {:^12} {:^8} {}'.format(client_ip, e['downstream_if'], mcast_group, mcast_src_ip, e['upstream_if'], e['priority'], key ))
            self.logger.info( '{:31} {:14} {:31} {:31} {:12} {:8} {:16}'.format('-------------------------------', '--------------', '-------------------------------', '-------------------------------', '------------', '--------', '----------------') )


        else:
            self.logger.info( '{:25} {:14} {:25} {:25} {:12} {:8} '.format('client_ip', 'downstream_if', 'mcast_group', 'mcast_src_ip', 'upstream_if', 'priority') )
            self.logger.info( '{:25} {:14} {:25} {:25} {:12} {:8} '.format('-----------------', '--------------', '-----------------', '-----------------', '------------', '--------') )
            for key in mcast_table.keys():
                e = mcast_table[key]
                self.logger.info( '{:25} {:^14} {:25} {:25} {:^12} {:^8} '.format(e['client_ip'], e['downstream_if'], e['mcast_group'], e['mcast_src_ip'], e['upstream_if'], e['priority']) )
            self.logger.info( '{:25} {:14} {:25} {:25} {:12} {:8} '.format('-----------------', '--------------', '-----------------', '-----------------', '------------', '--------') )

    # Return mcast table
    def get_mcast_table(self, format, extended):
        if format == 'json':
            if extended:
                return json.dumps(self.mcast_upstream_routing, indent=4)
            else:
                mcast_table = {}
                for key in self.mcast_upstream_routing.keys():
                    e = self.mcast_upstream_routing[key]
                    mcast_table[key] = dict(client_ip=e['client_ip'], downstream_if=e['downstream_if'], mcast_group=e['mcast_group'],
                                            mcast_src_ip=e['mcast_src_ip'], upstream_if=e['upstream_if'], priority=e['priority'])
                return json.dumps(mcast_table, indent=4)




###############################################
#PROVIDER
###############################################
    # Example of how to use complex query in mongodb
    # Search providers who broadcast a requested channel
    def who_has_a_channel(self, id):
        result = {}
        providers = list(self.db.providers.aggregate([{"$unwind":"$mcast_groups"},{"$match":{"mcast_groups":id}}]))
        if len(providers) != 0:
            for provider in providers:
                result[provider["_id"]] = provider
        return result

    # List content providers: lists the content providers added to the multicast proxy
    def retrieve_providers(self):
        providers_table = []
        for key in self.providers:
            provider = self.providers[key]
            requested_provider = self.provider_helper(provider)
            requested_provider["_id"]=key
            providers_table.append(requested_provider)
        if len(providers_table) != 0:
            body = json.dumps(providers_table, indent=4)
        else:
            response = "There aren't providers in database"
            body = json.dumps(response, indent=4)
        #return self.providers
        return body

    # Show content provider: shows detailed information about a content provider such as IP address, upstream interface, among others
    def retrieve_provider(self, id) -> dict:
        if id in self.providers:
            provider = self.providers[id]
            body = json.dumps(provider, indent=4)
        else:
            response = "No provider with id: " + str(id)
            body = json.dumps(response, indent=4)
        return body

    # Add content provider: adds an IP multicast content provider
    def add_provider(self, provider) -> dict:

        # description
        if ( provider["description"] == '' ):
            description = 'providerName'
        else:
            try:
                description = provider["description"]
            except ValueError:
                self.logger.error(f'-- ERROR: {provider["description"]} is not a valid description for a content provider.')
                return -1

        # mcast_src_ip
        if ( provider["mcast_src_ip"] == '' ):
            mcast_src_ip = mcast_src_ip_first = mcast_src_ip_last = ''
        else:
            try:
                mcast_src_ip = provider["mcast_src_ip"]
                mcast_src_ip_first = str(IPAddress(IPNetwork(provider["mcast_src_ip"]).first))
                mcast_src_ip_last  = str(IPAddress(IPNetwork(provider["mcast_src_ip"]).last))
            except ValueError:
                self.logger.error(f'-- ERROR: {provider["mcast_src_ip"]} is not a valid IP address or network.')
                return -1

        # upstream interface
        if ( provider["upstream_if"] == '' ):
            upstream_if = ''
        else:
            try:
                upstream_if = provider["upstream_if"]
            except ValueError:
                self.logger.error(f'-- ERROR: {provider["upstream_if"]} is not a valid upstream interface')
                return -1

        # mcast_groups
        if ( provider["mcast_groups"] == '' or provider["mcast_groups"] == []):
            mcast_groups = []
        else:
            try:
                mcast_groups = provider["mcast_groups"]
                #mcast_group_first = str(IPAddress(IPNetwork(provider["mcast_group"]).first))
                #mcast_group_last  = str(IPAddress(IPNetwork(provider["mcast_group"]).last))
            except ValueError:
                self.logger.error(f'-- ERROR: {provider["mcast_groups"]} is not a valid IP address or network.')
                return -1

     
        new_provider = dict(description=description, mcast_src_ip=mcast_src_ip, mcast_src_ip_first=mcast_src_ip_first, mcast_src_ip_last=mcast_src_ip_last, \
                           upstream_if=upstream_if, mcast_groups=mcast_groups)

        proposed_id = self.dict_hash(new_provider)
        if proposed_id in self.providers:
            response = "Duplicated provider"
            body = json.dumps(response, indent=4)
            return body
        else:
            new_provider["_id"]=proposed_id
            result = self.db.providers.insert_one(new_provider)
            provider_id = str(result.inserted_id)
            self.providers[provider_id] = new_provider
            provider_added = self.retrieve_provider(provider_id)
            return provider_added


    # Update content provider: updates functional parameters of a content provider
    def update_provider(self, id, new_data):
        # Return false if an empty request body is sent.
        if len(new_data) < 1:
            return False
        if id in self.providers:
            provider = self.providers[id]

            # description
            try:
                if ( new_data["description"] == '' ):
                    description = 'providerName'
                else:
                    description = new_data["description"]
            except:
                description = provider["description"]

            # mcast_src_ip
            try:
                if ( new_data["mcast_src_ip"] == '' ):
                    mcast_src_ip = mcast_src_ip_first = mcast_src_ip_last = ''
                else:
                    mcast_src_ip = new_data["mcast_src_ip"]
                    mcast_src_ip_first = str(IPAddress(IPNetwork(new_data["mcast_src_ip"]).first))
                    mcast_src_ip_last  = str(IPAddress(IPNetwork(new_data["mcast_src_ip"]).last))
            except:
                mcast_src_ip = provider["mcast_src_ip"]
                mcast_src_ip_first = provider["mcast_src_ip_first"]
                mcast_src_ip_last  = provider["mcast_src_ip_last"]

            # upstream interface
            try:
                if ( new_data["upstream_if"] == '' ):
                    upstream_if = ''
                else:
                    upstream_if = new_data["upstream_if"]
            except:
                upstream_if = provider["upstream_if"]

            # mcast_groups
            try:
                if ( new_data["mcast_groups"] == '' or new_data["mcast_groups"] == []):
                    mcast_groups = []
                else:
                    mcast_groups = new_data["mcast_groups"]
            except:
                mcast_groups = provider["mcast_groups"]

            new_provider = dict(description=description, mcast_src_ip=mcast_src_ip, mcast_src_ip_first=mcast_src_ip_first, mcast_src_ip_last=mcast_src_ip_last, \
                           upstream_if=upstream_if, mcast_groups=mcast_groups)
         
            myquery = { "_id": id }
            self.db.providers.update(myquery, new_provider)    
            new_provider["_id"]=id
            self.providers[id] = new_provider
            updated_provider = self.retrieve_provider(id)
            return updated_provider

    # Delete content provider: deletes a content provider from the multicast proxy
    def delete_provider(self, id):
        if id in self.providers:
            provider = self.providers[id]
            upstream_if = provider["upstream_if"]
            del self.providers[id]
            myquery = { "_id": id }
            self.db.providers.delete_one(myquery)
            response = "Deleted provider with id: " + str(id)
            entries_to_delete = self.delete_associated_entries(upstream_if)
            all_operations = []
            for entry in entries_to_delete:
                response_tmp, ops = self.delete_murt_entry(entry["_id"])
                if ops != -1:
                    for operation in ops:
                        all_operations.append(operation)
        else:
            response = "No provider with id: " + str(id)
            all_operations = -1
        body = json.dumps(response, indent=4)
        return body, all_operations

    # Clear content providers: deletes all the content providers from the multicast proxy
    def delete_providers(self):
        self.providers = {}
        self.mcast_upstream_routing = {}
        self.registered_flows = {}
        self.flows_per_murt_entry = {}
        result = self.db.providers.delete_many({})
        if (len(self.providers) == 0 and result.deleted_count != 0):
            response = str(result.deleted_count) + " providers deleted."
        else:
            response = "Empty table"
        body = json.dumps(response, indent=4)
        return response

    # Print providers table
    def print_provider_table(self, provider_table):
        self.logger.info( '{:20} {:25} {:20} {:80} '.format('Description', 'mcast_src_ip', 'upstream_if', 'mcast_groups'))
        self.logger.info( '{:20} {:25} {:20} {:80} '.format('-----------------', '-------------------', '--------------------', '-----------------') )
        for key in provider_table.keys():
            e = provider_table[key]
            self.logger.info( '{:20} {:25} {:20} {:80} '.format(e['description'], e['mcast_src_ip'], e['upstream_if'], str(e['mcast_groups'])) )
        self.logger.info( '{:20} {:25} {:20} {:80} '.format('-----------------', '-------------------', '--------------------', '-----------------') )

    # Get providers table
    def get_provider_table(self, format, extended):
        if format == 'json':
            if extended:
                return json.dumps(self.providers, indent=4)
            else:
                providers_table = {}
                for key in self.providers.keys():
                    e = self.providers[key]
                    providers_table[key] = dict(description=e['description'], mcast_src_ip=e['mcast_src_ip'], upstream_if=e['upstream_if'], mcast_groups=e['mcast_groups'])
                return json.dumps(providers_table, indent=4)


###############################################
#SDN CONTROLLER
###############################################

    # List SDN Controllers: lists the SDN Controllers added to the multicast proxy
    def retrieve_controllers(self):
        controllers_table = []
        for key in self.controllers:
            controller = self.controllers[key]
            requested_controller = self.sdncontroller_helper(controller)
            requested_controller["_id"]=key
            controllers_table.append(requested_controller)
        if len(controllers_table) != 0:
            body = json.dumps(controllers_table, indent=4)
        else:
            response = "There aren't controllers in database"
            body = json.dumps(response, indent=4)
        #return self.controllers
        return body

    # Show main SDN controller: shows detailed information about the main SDN controller such as openflow version, TCP port, IP address, among others
    def retrieve_controller(self, id) -> dict:
        if id in self.controllers:
            controller = self.controllers[id]
            body = json.dumps(controller, indent=4)
        else:
            response = "No controller with id: " + str(id)
            body = json.dumps(response, indent=4)
        return body

    # Add main SDN controller: adds a main SDN controller. The local SDN controller of the multicast proxy is configured as secondary controller. In this light, a hierarchical multicast proxy structure is created 
    def add_controller(self, controller) -> dict:

        # description
        if ( controller["description"] == '' ):
            description = 'ControllerDescription'
        else:
            try:
                description = controller["description"]
            except ValueError:
                self.logger.error(f'-- ERROR: {controller["description"]} is not a valid description for a controller.')
                return -1

        # openflow_version
        if ( controller["openflow_version"] == '' ):
            openflow_version = 'OpenFlow13'
        else:
            try:
                openflow_version = controller["openflow_version"]
            except ValueError:
                self.logger.error(f'-- ERROR: {controller["openflow_version"]} is not a valid OpenFlow version.')
                return -1

        # tcp_port
        if ( controller["tcp_port"] == '' ):
            tcp_port = ''
        else:
            try:
                tcp_port = controller["tcp_port"]
            except ValueError:
                self.logger.error(f'-- ERROR: {controller["tcp_port"]} is not a valid tcp port')
                return -1

        # ip_address
        if ( controller["ip_address"] == ''):
            ip_address = ''
        else:
            try:
                ip_address = controller["ip_address"]
            except ValueError:
                self.logger.error(f'-- ERROR: {controller["ip_address"]} is not a valid IP address or network.')
                return -1

     
        new_controller = dict(description=description, openflow_version=openflow_version, tcp_port=tcp_port, ip_address=ip_address)

        proposed_id = self.dict_hash(new_controller)
        if proposed_id in self.controllers:
            response = "Duplicated controller"
            body = json.dumps(response, indent=4)
            return body
        else:
            new_controller["_id"]=proposed_id
            result = self.db.controllers.insert_one(new_controller)
            controller_id = str(result.inserted_id)
            self.controllers[controller_id] = new_controller
            controller_added = self.retrieve_controller(controller_id)
            return controller_added


    # Update main SDN controller: updates functional parameters of the controller
    def update_controller(self, id, new_data):
        # Return false if an empty request body is sent.
        if len(new_data) < 1:
            return False
        if id in self.controllers:
            controller = self.controllers[id]

            # description
            try:
                if ( new_data["description"] == '' ):
                    description = 'ControllerDescription'
                else:
                    description = new_data["description"]
            except:
                description = controller["description"]

            # openflow_version
            try:
                if ( new_data["openflow_version"] == '' ):
                    openflow_version = 'OpenFlow13'
                else:
                    openflow_version = new_data["openflow_version"]
            except:
                openflow_version = controller["mcast_src_ip"]

            # tcp_port
            try:
                if ( new_data["tcp_port"] == '' ):
                    tcp_port = ''
                else:
                    tcp_port = new_data["tcp_port"]
            except:
                tcp_port = controller["tcp_port"]

            # ip_address
            try:
                if ( new_data["ip_address"] == ''):
                    ip_address = ''
                else:
                    ip_address = new_data["ip_address"]
            except:
                ip_address = controller["ip_address"]

            new_controller = dict(description=description, openflow_version=openflow_version, tcp_port=tcp_port, ip_address=ip_address)
         
            myquery = { "_id": id }
            self.db.controllers.update(myquery, new_controller)    
            new_controller["_id"]=id
            self.controllers[id] = new_controller
            updated_controller = self.retrieve_controller(id)
            return updated_controller

    # Delete main SDN controller: deletes the main SDN controller. In this light, the hierarchical structure is also deleted
    def delete_controller(self, id):
        if id in self.controllers:
            controller = self.controllers[id]
            del self.controllers[id]
            myquery = { "_id": id }
            self.db.controllers.delete_one(myquery)
            response = "Deleted controller with id: " + str(id)
        else:
            response = "No controller with id: " + str(id)
        body = json.dumps(response, indent=4)
        return body

    # Clear SDN Controllers deletes all the SDN Controllers from the multicast proxy
    def delete_controllers(self):
        self.controllers = {}
        result = self.db.controllers.delete_many({})
        if (len(self.controllers) == 0 and result.deleted_count != 0):
            response = str(result.deleted_count) + " controllers deleted."
        else:
            response = "Empty table"
        body = json.dumps(response, indent=4)
        return response

    #Print controllers table
    def print_controller_table(self, controller_table):
        self.logger.info( '{:20} {:25} {:20} {:30} '.format('Description', 'OpenFlow-Version', 'TCP Port', 'IP Address'))
        self.logger.info( '{:20} {:25} {:20} {:30} '.format('-----------------', '-------------------', '--------------------', '-----------------') )
        for key in controller_table.keys():
            e = controller_table[key]
            self.logger.info( '{:20} {:25} {:20} {:30} '.format(e['description'], e['openflow_version'], e['tcp_port'], e['ip_address']) )
        self.logger.info( '{:20} {:25} {:20} {:30} '.format('-----------------', '-------------------', '--------------------', '-----------------') )

    #Return controllers table
    def get_controller_table(self, format, extended):
        if format == 'json':
            if extended:
                return json.dumps(self.controllers, indent=4)
            else:
                controllers_table = {}
                for key in self.controllers.keys():
                    e = self.controllers[key]
                    controllers_table[key] = dict(description=e['description'], openflow_version=e['openflow_version'], tcp_port=e['tcp_port'], ip_address=e['ip_address'])
                return json.dumps(controllers_table, indent=4)


###############################################
#FLOWS
###############################################
    #Print flows table
    def print_flows_table(self, registered_flows):
        self.logger.info("REAL TIME FLOWS CONFIGURED IN OVSWITCH")
        self.logger.info("----------------------------------------------------------------------------------------------------------------------------------------------")
        self.logger.info( '{:30} {:15} {:30} {:30} {:15}'.format('client_ip', 'downstream_if', 'mcast_group', 'mcast_src_ip', 'upstream_if'))
        self.logger.info( '{:30} {:15} {:30} {:30} {:15}'.format('-----------------------', '-------------', '-----------------------', '-----------------------', '-------------') )
        for key in registered_flows.keys():
            e = registered_flows[key]
            self.logger.info( '{:30} {:15} {:30} {:30} {:15}'.format(str(e['client_ip']), str(e['downstream_if']), str(e['mcast_group']), str(e['mcast_src_ip']),  str(e['upstream_if'])) )
        self.logger.info( '{:30} {:15} {:30} {:30} {:15}'.format('-----------------------', '-------------', '-----------------------', '-----------------------', '-------------') )


    # Show flows for a specific murt entry id
    def print_flows_per_murt_table(self, searched_flows, id):
        self.logger.info("REAL TIME FLOWS CONFIGURED IN OVSWITCH FOR MURT ENTRY ID: " + str(id))
        self.logger.info("----------------------------------------------------------------------------------------------------------------------------------------------")
        self.logger.info( '{:30} {:15} {:30} {:30} {:15}'.format('client_ip', 'downstream_if', 'mcast_group', 'mcast_src_ip', 'upstream_if'))
        self.logger.info( '{:30} {:15} {:30} {:30} {:15}'.format('-----------------------', '-------------', '-----------------------', '-----------------------', '-------------') )
        for key in searched_flows.keys():
            e = searched_flows[key]
            self.logger.info( '{:30} {:15} {:30} {:30} {:15}'.format(str(e['client_ip']), str(e['downstream_if']), str(e['mcast_group']), str(e['mcast_src_ip']),  str(e['upstream_if'])) )
        self.logger.info( '{:30} {:15} {:30} {:30} {:15}'.format('-----------------------', '-------------', '-----------------------', '-----------------------', '-------------') )


    #Find flows for a specific murt_entry_id. Create an array with all operations to do leave
    def find_flows(self, requested_id):
        flows_to_delete = []
        #Update flow tables
        #Registered operations for a specific murt entry ID
        if requested_id in self.flows_per_murt_entry.keys():
            do_leave_operations = self.flows_per_murt_entry[requested_id]
            for operation in do_leave_operations:
                id_flow = operation["id_flow"]
                if id_flow in self.registered_flows.keys():
                    del self.registered_flows[id_flow]
                flows_to_delete.append(operation)
                try:
                    del self.mupi_proxy.flows_per_murt_entry[requested_id]
                except:
                    error = True
        return flows_to_delete

    #Delete all entries associated to a deleted provider
    def delete_associated_entries(self, upstream_if):
        all_flows = []
        requested_if = str(upstream_if)
        for entry in self.mcast_upstream_routing:
            if requested_if == str(self.mcast_upstream_routing[entry]["upstream_if"]):
                all_flows.append(self.mcast_upstream_routing[entry])
        return all_flows