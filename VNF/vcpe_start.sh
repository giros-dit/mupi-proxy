#!/bin/bash

USAGE="
Usage:
    
vcpe_start <vcpe_name> <vnf_tunnel_ip> <home_tunnel_ip> <vcpe_private_ip> <vcpe_public_ip> <dhcpd_conf_file>
    being:
        <vcpe_name>: the name of the network service instance in OSM 
        <vnf_tunnel_ip>: the ip address for the vnf side of the tunnel
        <home_tunnel_ip>: the ip address for the home side of the tunnel
        <vcpe_private_ip>: the private ip address for the vcpe
        <vcpe_public_ip>: the public ip address for the vcpe (10.2.2.0/24)
        <dhcpd_conf_file>: the dhcp file for the vcpe to give private addresses to the home network
"

if [[ $# -ne 6 ]]; then
        echo ""       
    echo "ERROR: incorrect number of parameters"
    echo "$USAGE"
    exit 1
fi

VNF1="mn.dc1_$1-1-ubuntu-1"
VNF2="mn.dc1_$1-2-vyos-1"
L="${1: -1}"   # Letter at the end of NS name (A, B, etc.)
echo "-- Central office $L"

VNFTUNIP="$2"
HOMETUNIP="$3"
VCPEPRIVIP="$4"
VCPEPUBIP="$5"
DHCPDCONF="$6"

ETH11=`sudo docker exec -it $VNF1 ifconfig | grep eth1 | awk '{print $1}'`
ETH21=`sudo docker exec -it $VNF2 ifconfig | grep eth1 | awk '{print $1}'`
IP11=`sudo docker exec -it $VNF1 hostname -I | tr " " "\n" | grep 192.168.100`
IP21=`sudo docker exec -it $VNF2 hostname -I | tr " " "\n" | grep 192.168.100`

##################### VNFs Settings #####################
## 0. Iniciar el Servicio OpenVirtualSwitch en cada VNF:
echo "--"
echo "--OVS Starting..."
sudo docker exec -it $VNF1 /usr/share/openvswitch/scripts/ovs-ctl start
#sudo docker exec -it $VNF2 /usr/share/openvswitch/scripts/ovs-ctl start

echo "--"
echo "--Connecting vCPE service with AccessNet$L and ExtNet$L..."

sudo ovs-docker add-port AccessNet$L veth0 $VNF1
sudo ovs-docker add-port ExtNet$L eth2 $VNF2

echo "--"
echo "-- Setting VNF..."
echo "--"
echo "-- Bridge Creating..."

## 1. En VNF:vclass agregar un bridge y asociar interfaces.
sudo docker exec -it $VNF1 ovs-vsctl add-br br0
sudo docker exec -it $VNF1 ifconfig veth0 $VNFTUNIP/24
#sudo docker exec -it $VNF1 ovs-vsctl add-port br0 vxlan1 -- set interface vxlan1 type=vxlan options:remote_ip=$HOMETUNIP
#sudo docker exec -it $VNF1 ovs-vsctl add-port br0 vxlan2 -- set interface vxlan2 type=vxlan options:remote_ip=$IP21

echo "sudo docker exec -it $VNF1 ip link add vxlan1 type vxlan id 0 remote $HOMETUNIP dstport 4789"
sudo docker exec -it $VNF1 ip link add vxlan1 type vxlan id 0 remote $HOMETUNIP dstport 4789
echo "sudo docker exec -it $VNF1 ip link add vxlan2 type vxlan id 1 remote $IP21 dstport 4789"
sudo docker exec -it $VNF1 ip link add vxlan2 type vxlan id 1 remote $IP21 dstport 4789

echo "sudo docker exec -it $VNF1 ovs-vsctl add-port br0 vxlan1"
sudo docker exec -it $VNF1 ovs-vsctl add-port br0 vxlan1
echo "sudo docker exec -it $VNF1 ovs-vsctl add-port br0 vxlan2"
sudo docker exec -it $VNF1 ovs-vsctl add-port br0 vxlan2

echo "sudo docker exec -it $VNF1 ifconfig vxlan1 up"
sudo docker exec -it $VNF1 ifconfig vxlan1 up
echo "sudo docker exec -it $VNF1 ifconfig vxlan2 up"
sudo docker exec -it $VNF1 ifconfig vxlan2 up

## 2. En VNF:vcpe agregar un bridge y asociar interfaces.
#sudo docker exec -it $VNF2 ovs-vsctl add-br br1
#sudo docker exec -it $VNF2 /sbin/ifconfig br1 $VCPEPRIVIP/24
#sudo docker exec -it $VNF2 ovs-vsctl add-port br1 vxlan1 -- set interface vxlan1 type=vxlan options:remote_ip=$IP11
#sudo docker exec -it $VNF2 ifconfig br1 mtu 1400

## 3. En VNF:vcpe asignar dirección IP a interfaz de salida.
#sudo docker exec -it $VNF2 /sbin/ifconfig veth0 $VCPEPUBIP/24
#sudo docker exec -it $VNF2 ip route del 0.0.0.0/0 via 172.17.0.1
#sudo docker exec -it $VNF2 ip route add 0.0.0.0/0 via 10.2.3.254

## 4. Iniciar Servidor DHCP 
#echo "--"
#echo "--DHCP Server Starting..."
#if [ -f "$DHCPDCONF" ]; then
#    echo "--Using $DHCPDCONF for DHCP"
#    docker cp $DHCPDCONF $VNF2:/etc/dhcp/dhcpd.conf
#else
#    echo "--$DHCPCONF not found for DHCP, the container will use the default"
#fi
#sudo docker exec -it $VNF2 service isc-dhcp-server restart
#sleep 10

## 5. En VNF:vcpe activar NAT para dar salida a Internet 
#docker cp /usr/bin/vnx_config_nat  $VNF2:/usr/bin
#sudo docker exec -it $VNF2 /usr/bin/vnx_config_nat br1 veth0

