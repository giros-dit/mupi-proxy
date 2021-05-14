#!/bin/bash

COS="A B"

for l in $COS; do
    sudo vnx -f central-office-${l}.xml -v -P

    osm ns-delete vcpe-1${l}
    osm ns-delete vcpe-2${l}
    osm ns-delete mproxy${l}

    sudo ovs-vsctl --if-exist del-br ExtNet${l}
    sudo ovs-vsctl --if-exist del-br AccessNet${l}
    sudo ovs-vsctl --if-exist del-br dsw${l}
    sudo ovs-vsctl --if-exist del-br sw-mgmt
done


sudo vnx -f metro-internet.xml -v -P
