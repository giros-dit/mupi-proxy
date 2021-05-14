#!/bin/bash

function pause(){
read -s -n 1 -p "Press any key to continue . . ."
echo ""
}

MPNAME=$1
IPEXTNET=$2
IP1=$3
IP2=$4
VNI1=$5
VNI2=$6

echo "-- MPNAME=$MPNAME"
echo "-- IPEXTNET=$IPEXTNET"
L="${MPNAME: -1}"   # Letter at the end of NS name (A, B, etc.)
echo "-- Mupi proxy $L"

VNF1="mn.dc1_$MPNAME-1-mproxy-1"
echo "-- VNF1=$VNF1"

IPCONTROLLER=`sudo docker exec -it $VNF1 hostname -I | tr " " "\n" | grep 172.17.0`

## 0. Iniciar el Servicio OpenVirtualSwitch en cada VNF:
echo "--"
echo "--OVS Starting..."
sudo docker exec -it $VNF1 /usr/share/openvswitch/scripts/ovs-ctl start

echo sudo ovs-docker add-port ExtNet$L eth1 $VNF1
sudo ovs-docker add-port ExtNet$L eth1 $VNF1
echo sudo ovs-docker add-port dsw$L eth2 $VNF1
sudo ovs-docker add-port dswA eth2 $VNF1

#pause

echo sudo docker exec -it $VNF1 ifconfig eth1 $IPEXTNET/24
sudo docker exec -it $VNF1 ifconfig eth1 $IPEXTNET/24

#pause

echo "--"
echo "-- Create VXLAN tunnels:"
echo docker exec -it $VNF1 ip link add vxlan1 type vxlan id $VNI1 remote $IP1 dstport 4789
sudo docker exec -it $VNF1 ip link add vxlan1 type vxlan id $VNI1 remote $IP1 dstport 4789
echo docker exec -it $VNF1 ip link add vxlan2 type vxlan id $VNI2 remote $IP2 dstport 4789
sudo docker exec -it $VNF1 ip link add vxlan2 type vxlan id $VNI2 remote $IP2 dstport 4789
sudo docker exec -it $VNF1 ip link set vxlan1 up
sudo docker exec -it $VNF1 ip link set vxlan2 up
sudo docker exec -it $VNF1 ip addr add 10.2.4.2/30 dev vxlan1
sudo docker exec -it $VNF1 ip addr add 10.2.4.6/30 dev vxlan2

#pause

echo "--"
echo "-- Create provider VLAN interfaces:"
sudo docker exec -it $VNF1 ip link add link eth2 name if-prov1 type vlan id 10
sudo docker exec -it $VNF1 ip link add link eth2 name if-prov2 type vlan id 20
sudo docker exec -it $VNF1 ip link add link eth2 name if-prov3 type vlan id 30
#sudo docker exec -it $VNF1 ip addr add 10.2.10.2/24 dev if-prov1
#sudo docker exec -it $VNF1 ip addr add 10.2.20.2/24 dev if-prov2
#sudo docker exec -it $VNF1 ip addr add 10.2.30.2/24 dev if-prov3
sudo docker exec -it $VNF1 ip link set dev if-prov1 up
sudo docker exec -it $VNF1 ip link set dev if-prov2 up
sudo docker exec -it $VNF1 ip link set dev if-prov3 up

#pause

echo "--"
echo "-- Create msw switch:"
sudo docker exec -it $VNF1 ovs-vsctl add-br msw
sudo docker exec -it $VNF1 ovs-vsctl set-fail-mode msw secure
sudo docker exec -it $VNF1 ovs-vsctl add-port msw if-prov1      # port 1
sudo docker exec -it $VNF1 ovs-vsctl add-port msw if-prov2      # port 2
sudo docker exec -it $VNF1 ovs-vsctl add-port msw if-prov3      # port 3
sudo docker exec -it $VNF1 ovs-vsctl add-port msw vxlan1        # port 4
sudo docker exec -it $VNF1 ovs-vsctl add-port msw vxlan2        # port 5
sudo docker exec -it $VNF1 ovs-vsctl set Bridge msw protocols=OpenFlow13
sudo docker exec -it $VNF1 ovs-vsctl set-controller msw tcp:$IPCONTROLLER:6633

#pause

sudo docker exec -it $VNF1 ip link set dev msw up
sudo docker exec -it $VNF1 ip addr add 10.2.10.2/24 dev msw
sudo docker exec -it $VNF1 ip addr add 10.2.20.2/24 dev msw
sudo docker exec -it $VNF1 ip addr add 10.2.30.2/24 dev msw

#ryu-manager flowmanager/flowmanager.py mupi-proxy/mupi-proxy.py --config-file mupi-proxy/conf/vcpes.conf
#sudo lxc-attach mproxyA -- ryu-manager /root/flowmanager/flowmanager.py /root/mupi-proxy/mupi-proxy.py --config-file /root/mupi-proxy/conf/vcpes.conf

