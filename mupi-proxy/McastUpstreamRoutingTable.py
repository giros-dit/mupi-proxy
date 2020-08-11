#!/usr/bin/python3

from netaddr import *
import secrets
import json


class MURT:

    mcast_upstream_routing = {}

    def __init__(self, logger):
        mcast_upstream_routing = {}
        self.logger = logger

    def add_entry(self, entry):
    
        #print(entry)

        # Create unique id for the new entry
        id = secrets.token_hex(8)
        # Check if it already exists and generate again till it is unique
        while id in self.mcast_upstream_routing:
            id = secrets.token_hex(8)

        # client_ip
        if ( entry[0] == '' ):
            client_ip = client_ip_first = client_ip_last = ''
        else:
            try:
                client_ip = entry[0]
                client_ip_first = IPNetwork(entry[0]).first
                client_ip_last  = IPNetwork(entry[0]).last
            except ValueError:
                self.logger.error(f'-- ERROR: {entry[0]} is not a valid IP address or network.')
                return -1

        # mcast_group
        if ( entry[1] == '' ):
            mcast_group = mcast_group_first = mcast_group_last = ''
        else:
            try:
                mcast_group = entry[1]
                mcast_group_first = IPNetwork(entry[1]).first
                mcast_group_last  = IPNetwork(entry[1]).last
            except ValueError:
                self.logger.error(f'-- ERROR: {entry[1]} is not a valid IP address or network.')
                return -1

        # mcast_src_ip
        if ( entry[2] == '' ):
            mcast_src_ip = mcast_src_ip_first = mcast_src_ip_last = ''
        else:
            try:
                mcast_src_ip = entry[2]
                mcast_src_ip_first = IPNetwork(entry[2]).first
                mcast_src_ip_last  = IPNetwork(entry[2]).last
            except ValueError:
                self.logger.error(f'-- ERROR: {entry[2]} is not a valid IP address or network.')
                return -1


        self.mcast_upstream_routing[id] = dict(client_ip=client_ip, client_ip_first=client_ip_first, client_ip_last=client_ip_last, \
                                   mcast_group=mcast_group, mcast_group_first=mcast_group_first, mcast_group_last=mcast_group_last, \
                                   mcast_src_ip=mcast_src_ip, mcast_src_ip_first=mcast_src_ip_first, mcast_src_ip_last=mcast_src_ip_last,
                                   upstream_if=entry[3], priority=entry[4])
        return id


    def del_entry_by_id(self, id):
        
        del self.mcast_upstream_routing[id]


    def del_entry_by_data(self, entry):
        
        self.logger.debug(entry)

        # client_ip
        if ( entry[0] == '' ):
            client_ip_first = ''
            client_ip_last  = ''
        else:
            try:
                client_ip_first = IPNetwork(entry[0]).first
                client_ip_last  = IPNetwork(entry[0]).last
            except ValueError:
                self.logger.error(f'-- ERROR: {entry[0]} is not a valid IP address or network.')
                return -1

        # mcast_group
        if ( entry[1] == '' ):
            mcast_group_first = ''
            mcast_group_last  = ''
        else:
            try:
                mcast_group_first = IPNetwork(entry[1]).first
                mcast_group_last  = IPNetwork(entry[1]).last
            except ValueError:
                self.logger.error(f'-- ERROR: {entry[1]} is not a valid IP address or network.')
                return -1

        # mcast_src_ip
        if ( entry[2] == '' ):
            mcast_src_ip_first = ''
            mcast_src_ip_last  = ''
        else:
            try:
                mcast_src_ip_first = IPNetwork(entry[2]).first
                mcast_src_ip_last  = IPNetwork(entry[2]).last
            except ValueError:
                self.logger.error(f'-- ERROR: {entry[2]} is not a valid IP address or network.')
                return -1

        for key in self.mcast_upstream_routing.keys():
            e = self.mcast_upstream_routing[key]
            if (      ( ( client_ip_first == ''   and e['client_ip_first'] == '' )  
                     or ( client_ip_first    == e['client_ip_first']    and client_ip_last    == e['client_ip_last'] ) ) 
                  and ( ( mcast_group_first == '' and e['mcast_group_first'] == '' ) 
                     or ( mcast_group_first  == e['mcast_group_first']  and mcast_group_last  == e['mcast_group_last']  ))
                  and ( ( mcast_src_ip_first == '' and e['mcast_src_ip_first'] == '' )
                     or ( mcast_src_ip_first >= e['mcast_src_ip_first'] and mcast_src_ip_last <= e['mcast_src_ip_last'] )) ):
                del self.mcast_upstream_routing[key]
                return key
        return -1


    def get_upstream_if(self, client_ip, mcast_group, mcast_src_ip):
        # Dives the mcast-proxy routing table and gets the highest priority entries that match the query
        self.logger.debug(f'get_upstream_if query: client_ip={client_ip}, mcast_group={mcast_group}. mcast_src_ip={mcast_src_ip}')
        match_entries = {}
        upstream_ifs = []

        client_ip_num = IPAddress(client_ip).value
        mcast_group_num = IPAddress(mcast_group).value
        if ( mcast_src_ip != '' and mcast_src_ip != None ):
            mcast_src_ip_num = IPAddress(mcast_src_ip).value

        max_priority = -1
        #for e in self.mcast_upstream_routing:
        for key in self.mcast_upstream_routing.keys():
            e = self.mcast_upstream_routing[key]
            if ( mcast_src_ip != '' and mcast_src_ip != None ):
                if (      ( e['client_ip_first'] == ''    or ( client_ip_num    >= e['client_ip_first']    and client_ip_num    <= e['client_ip_last'] ) ) 
                      and ( e['mcast_group_first'] == ''  or ( mcast_group_num  >= e['mcast_group_first']  and mcast_group_num  <= e['mcast_group_last']  ))
                      and ( e['mcast_src_ip_first'] == '' or ( mcast_src_ip_num >= e['mcast_src_ip_first'] and mcast_src_ip_num <= e['mcast_src_ip_last'] )) ):
                    match_entries[key] = e
                    if e['priority'] > max_priority:
                        max_priority = e['priority']
            else:
                if (      ( e['client_ip_first'] == ''    or ( client_ip_num    >= e['client_ip_first']    and client_ip_num    <= e['client_ip_last'] ) ) 
                        and ( e['mcast_group_first'] == ''  or ( mcast_group_num  >= e['mcast_group_first']  and mcast_group_num  <= e['mcast_group_last']  )) ):
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
        return upstream_ifs

    def print_mcast_table(self, mcast_table, extended):
        if extended:
            self.logger.info( '{:31} {:31} {:31} {:12} {:8} {:16}'.format('client_ip', 'mcast_group', 'mcast_src_ip', 'upstream_if', 'priority', 'id') )
            self.logger.info( '{:31} {:31} {:31} {:12} {:8} {:16}'.format('-------------------------------', '-------------------------------', '-------------------------------', '------------', '--------', '----------------') )
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
                self.logger.info( '{:31} {:31} {:31} {:^12} {:^8} {}'.format(client_ip, mcast_group, mcast_src_ip, e['upstream_if'], e['priority'], key ))
            self.logger.info( '{:31} {:31} {:31} {:12} {:8} {:16}'.format('-------------------------------', '-------------------------------', '-------------------------------', '------------', '--------', '----------------') )


        else:
            self.logger.info( '{:17} {:17} {:17} {:12} {:8}'.format('client_ip', 'mcast_group', 'mcast_src_ip', 'upstream_if', 'priority') )
            self.logger.info( '{:17} {:17} {:17} {:12} {:8}'.format('-----------------', '-----------------', '-----------------', '------------', '--------') )
            #for e in mcast_table:
            for key in mcast_table.keys():
                e = mcast_table[key]
                #self.logger.info(e)
                #if e['client_ip_first'] != '':
                #    client_ip = str(IPRange(e['client_ip_first'], e['client_ip_last']).cidrs()[0])
                #else:
                #    client_ip = ''
                #if e['mcast_group_first'] != '':
                #    mcast_group = str(IPRange(e['mcast_group_first'], e['mcast_group_last']).cidrs()[0])
                #else:
                #    mcast_group = ''
                #if e['mcast_src_ip_first'] != '':
                #    mcast_src_ip = str(IPRange(e['mcast_src_ip_first'], e['mcast_src_ip_last']).cidrs()[0])
                #else:
                #    mcast_src_ip = ''
                #self.logger.info( '{:17} {:17} {:17} {:^12} {:^8}'.format(client_ip, mcast_group, mcast_src_ip, e['upstream_if'], e['priority']) )
                self.logger.info( '{:17} {:17} {:17} {:^12} {:^8}'.format(e['client_ip'], e['mcast_group'], e['mcast_src_ip'], e['upstream_if'], e['priority']) )
            self.logger.info( '{:17} {:17} {:17} {:12} {:8}'.format('-----------------', '-----------------', '-----------------', '------------', '--------') )

    def get_mcast_table(self, format, extended):

        if format == 'json':
            if extended:
                return json.dumps(self.mcast_upstream_routing, indent=4)
            else:
                mcast_table = {}
                for key in self.mcast_upstream_routing.keys():
                    e = self.mcast_upstream_routing[key]
                    mcast_table[key] = dict(client_ip=e['client_ip'], mcast_group=e['mcast_group'], mcast_src_ip=e['mcast_src_ip'],
                                            upstream_if=e['upstream_if'], priority=e['priority'])
                return json.dumps(mcast_table, indent=4)

