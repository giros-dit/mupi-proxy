from ipaddress import *
from netaddr import *
from bson.son import SON
import pprint

def compare(ip_first, ip_last, ip_requested):
	if ((ip_requested > ip_first) and (ip_requested < ip_last)):
		print(ip_requested + " is IN range")
	else:
		print(ip_requested + " is OUT of Range")


def manage_ip_addresses(ip_requested: str):
	ip_first = str(IPAddress(IPNetwork(ip_requested).first))
	ip_last = str(IPAddress(IPNetwork(ip_requested).last))



#ANOTACIONES 



from bson.son import SON
>>> pipeline = [
...     {"$unwind": "$tags"},
...     {"$group": {"_id": "$tags", "count": {"$sum": 1}}},
...     {"$sort": SON([("count", -1), ("_id", -1)])}
... ]
>>> import pprint
>>> pprint.pprint(list(db.things.aggregate(pipeline)))
[{u'_id': u'cat', u'count': 3},
 {u'_id': u'dog', u'count': 2},
 {u'_id': u'mouse', u'count': 1}]

 

if ( mcast_src_ip != '' and mcast_src_ip != None and mcast_src_ip != '0.0.0.0'):
	db.murtentries.aggregate([
	 	{"$match":{"$or":[{"client_ip_first":{ "$eq":'0.0.0.0'}},{"$and":[{"client_ip_first":{ "$lt": client_ip_num}},{"client_ip_last":{ "$gt": client_ip_num}}]}]}},
	 	{"$match":{"$or":[{"mcast_group_first":{ "$eq":'0.0.0.0'}},{"$and":[{"mcast_group_first":{ "$lt": mcast_group_num}},{"mcast_group_last":{ "$gt": mcast_group_num}}]}]}},
	 	{"$match":{"$or":[{"mcast_src_ip_first":{ "$eq":'0.0.0.0'}},{"$and":[{"mcast_src_ip_first":{ "$lt": mcast_src_ip_num}},{"mcast_src_ip_last":{ "$gt": mcast_src_ip_num}}]}]}},
	 	{"$match":{"$or":[{"downstream_if":{ "$eq":'-1'}},{"downstream_if":{"$eq": downstream_if}}]}},
	 	{"$sort": SON([("priority", -1)])}
 	])
else:
	db.murtentries.aggregate([
	 	{"$match":{$or:[{client_ip_first:{ $eq:'0.0.0.0'}},{$and:[{client_ip_first:{ $lt: client_ip_num}},{client_ip_last:{ $gt: client_ip_num}}]}]}},
	 	{"$match":{$or:[{mcast_group_first:{ $eq:'0.0.0.0'}},{$and:[{mcast_group_first:{ $lt: mcast_group_num}},{mcast_group_last:{ $gt: mcast_group_num}}]}]}},
	 	{"$match":{$or:[{downstream_if:{ $eq:'-1'}},{downstream_if:{$eq: downstream_if}}]}}
 	])

var group = {"$group":{"_id":"$priority", fullDocument:{"$push":"$$ROOT"}, count:{"$sum":1}}}
var limit= {"$limit":1}
var sort = {"$sort"{"$group":{"_id":"$priority",:1}




    def get_upstream_if_database(self, client_ip, mcast_group, mcast_src_ip, downstream_if):
        self.logger.info("RAULLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL")
        # Dives the mcast-proxy routing table and gets the highest priority entries that match the query
        self.logger.debug(f'get_upstream_if query: client_ip={client_ip}, mcast_group={mcast_group}, mcast_src_ip={mcast_src_ip}, downstream_if={downstream_if}')
        match_entries = {}
        upstream_ifs = []
        client_ip_num = str(IPAddress(client_ip))
        mcast_group_num = str(IPAddress(mcast_group))
        max_priority = -1
        if ( mcast_src_ip != '' and mcast_src_ip != None and mcast_src_ip != '0.0.0.0'):
            mcast_src_ip_num = str(IPAddress(mcast_src_ip))
            database_match = list(self.db.murtentries.aggregate([{"$match":{"$or":[{"client_ip_first":{ "$eq":'0.0.0.0'}},{"$and":[{"client_ip_first":{ "$lt": client_ip_num}},{"client_ip_last":{ "$gt": client_ip_num}}]}]}},{"$match":{"$or":[{"mcast_group_first":{ "$eq":'0.0.0.0'}},{"$and":[{"mcast_group_first":{ "$lt": mcast_group_num}},{"mcast_group_last":{ "$gt": mcast_group_num}}]}]}},{"$match":{"$or":[{"mcast_src_ip_first":{ "$eq":'0.0.0.0'}},{"$and":[{"mcast_src_ip_first":{ "$lt": mcast_src_ip_num}},{"mcast_src_ip_last":{ "$gt": mcast_src_ip_num}}]}]}},{"$match":{"$or":[{"downstream_if":{ "$eq":'-1'}},{"downstream_if":{"$eq": downstream_if}}]}},{"$sort": SON([("priority", -1)])}]))
        else:
            database_match = list(self.db.murtentries.aggregate([{"$match":{"$or":[{"client_ip_first":{ "$eq":'0.0.0.0'}},{"$and":[{"client_ip_first":{ "$lt": client_ip_num}},{"client_ip_last":{ "$gt": client_ip_num}}]}]}},{"$match":{"$or":[{"mcast_group_first":{ "$eq":'0.0.0.0'}},{"$and":[{"mcast_group_first":{ "$lt": mcast_group_num}},{"mcast_group_last":{ "$gt": mcast_group_num}}]}]}},{"$match":{"$or":[{"downstream_if":{ "$eq":'-1'}},{"downstream_if":{"$eq": downstream_if}}]}},{"$sort": SON([("priority", -1)])}]))
        for i in database_match:
            match_entries[i["_id"]]=i
        self.logger.debug('Matching entries:')
        self.print_mcast_table(match_entries, False)


    def get_upstream_if(self, client_ip, mcast_group, mcast_src_ip, downstream_if):
        # Dives the mcast-proxy routing table and gets the highest priority entries that match the query
        self.logger.debug(f'get_upstream_if query: client_ip={client_ip}, mcast_group={mcast_group}, mcast_src_ip={mcast_src_ip}, downstream_if={downstream_if}')
        match_entries = {}
        upstream_ifs = []

        client_ip_num = str(IPAddress(client_ip))
        mcast_group_num = str(IPAddress(mcast_group))
        if ( mcast_src_ip != '' and mcast_src_ip != None and mcast_src_ip != '0.0.0.0'):
            mcast_src_ip_num = str(IPAddress(mcast_src_ip))

        max_priority = -1
        #for e in self.mcast_upstream_routing:
        for key in self.mcast_upstream_routing.keys():
            e = self.mcast_upstream_routing[key]
            if ( mcast_src_ip != '' and mcast_src_ip != None and mcast_src_ip != '0.0.0.0'):
                if (      ( e['client_ip_first'] == '0.0.0.0'    or ( client_ip_num    >= e['client_ip_first']    and client_ip_num    <= e['client_ip_last'] ) ) 
                      and ( e['mcast_group_first'] == '0.0.0.0'  or ( mcast_group_num  >= e['mcast_group_first']  and mcast_group_num  <= e['mcast_group_last']  ))
                      and ( e['mcast_src_ip_first'] == '0.0.0.0' or ( mcast_src_ip_num >= e['mcast_src_ip_first'] and mcast_src_ip_num <= e['mcast_src_ip_last'] ))
                      and ( e['downstream_if'] == '-1' or ( downstream_if == e['downstream_if']) )):
                    match_entries[key] = e
                    if e['priority'] > max_priority:
                        max_priority = e['priority']
            else:
                if (      ( e['client_ip_first'] == '0.0.0.0'    or ( client_ip_num    >= e['client_ip_first']    and client_ip_num    <= e['client_ip_last'] ) ) 
                        and ( e['mcast_group_first'] == '0.0.0.0'  or ( mcast_group_num  >= e['mcast_group_first']  and mcast_group_num  <= e['mcast_group_last']  )) 
                        and ( e['downstream_if'] == '-1' or ( downstream_if == e['downstream_if']) )):
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
