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

    mcast_upstream_routing = {}
    providers = {}

    def __init__(self, logger):
        mcast_upstream_routing = {}
        self.logger = logger
        self.client = MongoClient(MONGO_DETAILS)
        self.db= self.client.mupiproxy
        self.loadFromDatabase()

    #HASH FUNCTION TO GENERATE OBJECT_ID (AVOID DUPLICATE ENTRIES)
    def dict_hash(self, dictionary: Dict[str, Any]) -> str:
        dhash = hashlib.md5()
        encoded = json.dumps(dictionary, sort_keys=True).encode()
        dhash.update(encoded)
        return dhash.hexdigest()

    #Upload data stored in database
    def loadFromDatabase(self):
        murt_entries_array = list(self.db.murtentries.find())
        for entry in murt_entries_array:
            object_id = entry["_id"]
            id = str(object_id)
            self.mcast_upstream_routing[id] = entry           

    #Upload from a configuration file
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


    def get_upstream_if(self, client_ip, mcast_group, mcast_src_ip, downstream_if):
        # Dives the mcast-proxy routing table and gets the highest priority entries that match the query
        tiempo_inicial = time()
        self.logger.debug(f'get_upstream_if query: client_ip={client_ip}, mcast_group={mcast_group}, mcast_src_ip={mcast_src_ip}, downstream_if={downstream_if}')
        match_entries = {}
        upstream_ifs = []

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
                      and ( e['downstream_if'] == '' or ( downstream_if == e['downstream_if']) )):
                    match_entries[key] = e
                    if e['priority'] > max_priority:
                        max_priority = e['priority']
            else:
                if (      ( e['client_ip_first'] == ''    or ( client_ip_num    >= e['client_ip_first']    and client_ip_num    <= e['client_ip_last'] ) ) 
                        and ( e['mcast_group_first'] == ''  or ( mcast_group_num  >= e['mcast_group_first']  and mcast_group_num  <= e['mcast_group_last']  )) 
                        and ( e['downstream_if'] == '' or ( downstream_if == e['downstream_if']) )):
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
        self.logger.debug(f'Upstream ifs selected: {upstream_ifs}')
        tiempo_final = time()
        tiempo_ejecucion = tiempo_final - tiempo_inicial
        print ('El tiempo de ejecucion fue:'+ str(tiempo_ejecucion))
        return upstream_ifs

    def get_upstream_if_database(self, client_ip, mcast_group, mcast_src_ip, downstream_if):
        self.logger.info("CONSULTA A LA BBDD")
        tiempo_inicial = time()
        # Dives the mcast-proxy routing table and gets the highest priority entries that match the query
        self.logger.debug(f'get_upstream_if query: client_ip={client_ip}, mcast_group={mcast_group}, mcast_src_ip={mcast_src_ip}, downstream_if={downstream_if}')
        match_entries = {}
        upstream_ifs = []
        client_ip_num = str(IPAddress(client_ip))
        mcast_group_num = str(IPAddress(mcast_group))
        max_priority = -1
        if ( mcast_src_ip != '' and mcast_src_ip != None):
            mcast_src_ip_num = str(IPAddress(mcast_src_ip))
            database_match = list(self.db.murtentries.aggregate([{"$match":{"$or":[{"client_ip_first":{ "$eq":''}},{"$and":[{"client_ip_first":{ "$lte": client_ip_num}},{"client_ip_last":{ "$gte": client_ip_num}}]}]}},{"$match":{"$or":[{"mcast_group_first":{ "$eq":''}},{"$and":[{"mcast_group_first":{ "$lte": mcast_group_num}},{"mcast_group_last":{ "$gte": mcast_group_num}}]}]}},{"$match":{"$or":[{"mcast_src_ip_first":{ "$eq":''}},{"$and":[{"mcast_src_ip_first":{ "$lte": mcast_src_ip_num}},{"mcast_src_ip_last":{ "$gte": mcast_src_ip_num}}]}]}},{"$match":{"$or":[{"downstream_if":{ "$eq":''}},{"downstream_if":{"$eq": downstream_if}}]}},{"$group":{"_id":"$priority", "matched_entries":{"$push":"$$ROOT"}, "count":{"$sum":1}}},{"$sort": SON([("priority", -1)])},{"$limit":1}]))
        else:
            database_match = list(self.db.murtentries.aggregate([{"$match":{"$or":[{"client_ip_first":{ "$eq":''}},{"$and":[{"client_ip_first":{ "$lte": client_ip_num}},{"client_ip_last":{ "$gte": client_ip_num}}]}]}},{"$match":{"$or":[{"mcast_group_first":{ "$eq":''}},{"$and":[{"mcast_group_first":{ "$lte": mcast_group_num}},{"mcast_group_last":{ "$gte": mcast_group_num}}]}]}},{"$match":{"$or":[{"downstream_if":{ "$eq":''}},{"downstream_if":{"$eq": downstream_if}}]}},{"$group":{"_id":"$priority", "matched_entries":{"$push":"$$ROOT"}, "count":{"$sum":1}}},{"$sort": SON([("priority", -1)])},{"$limit":1}]))
        #FALTA AGRUPAR POR INTERFAZ Y CONTAR CUANTAS ENTRADAS DE MAXIMA PRIORIDAD HAY EN CADA INTERFAZ
        for i in database_match:
            match_entries[i["_id"]]=i
        pprint.pprint(database_match)
        self.logger.debug('Matching entries:')
        self.print_mcast_table(match_entries, False)
        tiempo_final = time()
        tiempo_ejecucion = tiempo_final - tiempo_inicial
        print ('El tiempo de ejecucion fue:'+ str(tiempo_ejecucion))

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




    #######################################################
    #######################################################
    #API REST OPERATIONS
    #######################################################
    #######################################################

    #HELPER FUNCTIONS
    #For parsing the results from a database query into a Python dict
    def provider_helper(self, provider) -> dict:
        return {
            "mcast_src_ip": provider["mcast_src_ip"],
            "upstream_if": provider["upstream_if"],
            "mcast_groups": provider["mcast_groups"],
            "description": provider["description"],
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



###############################################
#MURT ENTRY
###############################################
    # Retrieve all MURT Entries present in the database
    #VER CUANTA INFORMACION QUEREMOS DAR, SI TODA LO QUE SE GUARDA EN LA BBDD O SOLO LO PRINCIPAL
    def retrieve_murt_entries(self):
        murtentries = []
        for key in self.mcast_upstream_routing:
            murt_entry = self.mcast_upstream_routing[key]
            requested_entry = self.murtentry_helper(murt_entry)
            requested_entry["_id"]=key
            murtentries.append(requested_entry)
        #return self.mcast_upstream_routing
        return murtentries


    # Add a new MURT Entry into to the database
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
            duplicated = {"error":"yes"}
            return duplicated
        else:
            new_entry["_id"]=proposed_id
            result = self.db.murtentries.insert_one(new_entry)
            #entry_id.acknowledged PARA COMPROBACIONES
            entry_id = str(result.inserted_id)

            self.mcast_upstream_routing[entry_id] = new_entry
            
            new_murtentry = self.retrieve_murt_entry(entry_id)
            return new_murtentry


    # Retrieve a MURT Entry with a matching ID
    def retrieve_murt_entry(self, id) -> dict:
        if id in self.mcast_upstream_routing:
            murtentry = self.mcast_upstream_routing[id]
            return murtentry


    # Update a MURT Entry with a matching ID
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
                mcast_group = murtentry["client_ip"]
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
            return self.murtentry_helper(updated_murtentry)


    # Delete a MURT Entry from the database
    def delete_murt_entry(self, id):
        if id in self.mcast_upstream_routing:
            murtentry = self.mcast_upstream_routing[id]
            del self.mcast_upstream_routing[id]
            myquery = { "_id": id }
            self.db.murtentries.delete_one(myquery)
            return True


    # Delete all MURT Entries from the database
    def delete_murt_entries(self):
        self.mcast_upstream_routing = {}
        result = self.db.murtentries.delete_many({})
        if (len(self.mcast_upstream_routing) == 0):
            print(result.deleted_count, " documents deleted.")
            return True
        else:
            return False


###############################################
#PROVIDER
###############################################


###############################################
#SDN CONTROLLER
###############################################
