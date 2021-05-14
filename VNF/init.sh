#!/bin/bash

COS="$1"

for l in $COS; do
    sudo ovs-vsctl --if-exist del-br AccessNet$l
    sudo ovs-vsctl --if-exist del-br ExtNet$l
    sudo ovs-vsctl --if-exist del-br dsw$l
    sudo ovs-vsctl add-br AccessNet$l
    sudo ovs-vsctl add-br ExtNet$l
    sudo ovs-vsctl add-br dsw$l
done
sudo ovs-vsctl --if-exist del-br sw-mgmt
sudo ovs-vsctl add-br sw-mgmt
sudo ip link set dev sw-mgmt up
