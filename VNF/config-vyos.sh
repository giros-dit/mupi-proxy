#!/bin/bash

VCPENAME=$1
HNAME=$2
EXTIP=$3
MCASTOVL=$4
VNI=$5
VXL1=$6
DEFROUTE=$7


echo "-- VCPENAME=$VCPENAME"
echo "-- EXTIP=$EXTIP"

VNF1="mn.dc1_$VCPENAME-1-ubuntu-1"
VNF2="mn.dc1_$VCPENAME-2-vyos-1"

IP1=$( sudo docker exec -it $VNF1 hostname -I | tr " " "\n" | grep 192.168.100 )

docker exec -ti $VNF2 /bin/vbash -c "
# AÑADIDO POR MI
sudo sysctl net.ipv6.conf.all.disable_ipv6=0

source /opt/vyatta/etc/functions/script-template
configure
set system host-name $HNAME

# External interface
set interfaces ethernet eth2 address $EXTIP/24
commit

configure
# VXLAN: vxlan0 to vclass
set interfaces vxlan vxlan0 address 192.168.255.1/24
set interfaces vxlan vxlan0 remote $IP1
set interfaces vxlan vxlan0 vni 1
set interfaces vxlan vxlan0 port 4789
# AÑADIDO POR MI
set interfaces vxlan vxlan0 address 2001:db8::1/64

# VXLAN: vxlan1 to mproxy
set interfaces vxlan vxlan1 address $MCASTOVL/30
set interfaces vxlan vxlan1 remote $VXL1
set interfaces vxlan vxlan1 vni $VNI
set interfaces vxlan vxlan1 port 4789
commit

# DHCP
set service dhcp-server shared-network-name dhcpexample authoritative
set service dhcp-server shared-network-name dhcpexample subnet 192.168.255.0/24 default-router 192.168.255.1
set service dhcp-server shared-network-name dhcpexample subnet 192.168.255.0/24 dns-server 192.168.255.1
set service dhcp-server shared-network-name dhcpexample subnet 192.168.255.0/24 lease 86400
set service dhcp-server shared-network-name dhcpexample subnet 192.168.255.0/24 range 0 start 192.168.255.10
set service dhcp-server shared-network-name dhcpexample subnet 192.168.255.0/24 range 0 stop 192.168.255.100

# AÑADIDO POR MI
# DHCPv6
set service dhcpv6-server
set service dhcpv6-server preference 0
set service dhcpv6-server shared-network-name dhcpexample6 subnet 2001:db8::/64 address-range start 2001:db8::100 stop 2001:db8::199
set service dhcpv6-server shared-network-name dhcpexample6 subnet 2001:db8::/64 name-server 2001:db8:111::ffff
set service dhcpv6-server shared-network-name dhcpexample6 subnet 2001:db8::/64 nis-server 2001:db8:111::ffff

# NAT
set nat source rule 20 outbound-interface eth2
set nat source rule 20 source address 192.168.255.0/24
set nat source rule 20 translation address $EXTIP

# AÑADIDO POR MI
set protocols static route 0.0.0.0/0 next-hop $DEFROUTE distance '1'
set interfaces ethernet eth0 disable

commit
save
exit
"

sleep 10

# Configure IGMP proxy
docker exec -ti $VNF2 /bin/bash -c "
source /opt/vyatta/etc/functions/script-template
configure

# IGMP PROXY
set protocols igmp-proxy interface vxlan0 role downstream
set protocols igmp-proxy interface vxlan1 role upstream
set protocols igmp-proxy interface vxlan1 alt-subnet 10.2.0.0/16

commit
save
exit
"

# Restart igmp proxy
#docker exec -ti $VNF2 /bin/bash -c "killall /usr/sbin/igmpproxy"
#sleep 5
#docker exec -ti $VNF2 /bin/bash -c "nohup /usr/sbin/igmpproxy /etc/igmpproxy.conf"

