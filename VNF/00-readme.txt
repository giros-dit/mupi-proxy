Recetas de arranque y parada del escenario (24/4/21):
-----------------------------------------------------

Arranque:

0 - Creacion de imagenes VNFs

- Carga de la imagen base de VyOS

wget http://idefix.dit.upm.es/download/vnx/examples/mupi-proxy/vyos-rolling-1.3.tar.gz
docker image load -i vyos-rolling-1.3.tar.gz

Comprobar que se ha cargado la imagen con:

docker images | grep vyos
vyos/rolling                1.3                  446da95c7c7c        12 months ago       770MB

- Creacion de imagenes de las VNFs

./create-vnf-images.sh 


1 - Registro en OSM de los descriptores de VNF y NS

./register-vnfd-nsd.sh


2 - Arranque del escenario VNX e instanciacion de los NSs

./start_all.sh


3 - Arranque del mproxy

# ARRANCAR BASE DE DATOS EN EL CONTROLLER
docker exec -ti mn.dc1_mproxyA-1-mproxy-1 /bin/bash
mongod

docker exec -ti mn.dc1_mproxyB-1-mproxy-1 /bin/bash
mongod


#IPS CONTROLLERS PARA GESTIÓN SIMULTÁNEA
	- PROXY-A: 172.17.0.6
	- PROXY-B: 172.17.0.11 o .9


docker exec -ti mn.dc1_mproxyA-1-mproxy-1 ryu-manager /root/flowmanager/flowmanager.py /root/mupi-proxy/mupi-proxy.py --config-file /root/mupi-proxy/conf/vcpes.conf

ryu-manager /root/flowmanager/flowmanager.py /root/mupi-proxy/mupi-proxy.py --config-file /root/mupi-proxy/conf/vcpes.conf --wsapi-host 172.17.0.6



docker exec -ti mn.dc1_mproxyB-1-mproxy-1 ryu-manager /root/flowmanager/flowmanager.py /root/mupi-proxy/mupi-proxy.py --config-file /root/mupi-proxy/conf/vcpes.conf

ryu-manager /root/flowmanager/flowmanager.py /root/mupi-proxy/mupi-proxy.py --config-file /root/mupi-proxy/conf/vcpes.conf --wsapi-host 172.17.0.11

4 - Prueba sencilla de envio

sudo lxc-attach provider1 -- mcsender -t10 -ieth1 224.10.10.2:1234
sudo lxc-attach -n h11A -- mcfirst -4 -I eth1 224.10.10.2 1234 -c 100






PARADA:

1 - Parada de escenarios VNX y NSs

./stop_all.sh
sudo ip link del dev metro-dswA-1
sudo ip link del dev metro-dswB-1
sudo ovs-vsctl del-br metro

2 - Desregistro vnfds y nsd:

./unregister-vnfd-nsd.sh



#####################
COMANDOS INTERESANTES
#####################
# check if the emulator is running in the container
docker exec vim-emu vim-emu datacenter list

# list vims
osm vim-list

# You can now check OSM's Launchpad to see the VNFs and NS in the catalog. Or:
osm vnfd-list

osm nsd-list

osm vnf-list

osm ns-list

docker exec vim-emu vim-emu compute list
+--------------+------------------------+-------------------+------------------+-------------------------+
| Datacenter   | Container              | Image             | Interface list   | Datacenter interfaces   |
+==============+========================+===================+==================+=========================+
| dc1          | dc1_vcpe-1A-1-ubuntu-1 | vnf-img:latest    | eth1-0           | dc1.s1-eth2             |
+--------------+------------------------+-------------------+------------------+-------------------------+
| dc1          | dc1_vcpe-1A-2-vyos-1   | vnf-vyos:latest   | eth1-1           | dc1.s1-eth3             |
+--------------+------------------------+-------------------+------------------+-------------------------+
| dc1          | dc1_vcpe-2A-1-ubuntu-1 | vnf-img:latest    | eth1-2           | dc1.s1-eth4             |
+--------------+------------------------+-------------------+------------------+-------------------------+
| dc1          | dc1_vcpe-2A-2-vyos-1   | vnf-vyos:latest   | eth1-3           | dc1.s1-eth5             |
+--------------+------------------------+-------------------+------------------+-------------------------+
| dc1          | dc1_mproxyA-1-mproxy-1 | vnf-mproxy:latest | eth1-4           | dc1.s1-eth6             |
+--------------+------------------------+-------------------+------------------+-------------------------+
| dc1          | dc1_vcpe-1B-1-ubuntu-1 | vnf-img:latest    | eth1-5           | dc1.s1-eth7             |
+--------------+------------------------+-------------------+------------------+-------------------------+
| dc1          | dc1_vcpe-1B-2-vyos-1   | vnf-vyos:latest   | eth1-6           | dc1.s1-eth8             |
+--------------+------------------------+-------------------+------------------+-------------------------+
| dc1          | dc1_mproxyB-1-mproxy-1 | vnf-mproxy:latest | eth1-7           | dc1.s1-eth9             |
+--------------+------------------------+-------------------+------------------+-------------------------+
| dc1          | dc1_vcpe-2B-1-ubuntu-1 | vnf-img:latest    | eth1-8           | dc1.s1-eth10            |
+--------------+------------------------+-------------------+------------------+-------------------------+
| dc1          | dc1_vcpe-2B-2-vyos-1   | vnf-vyos:latest   | eth1-9           | dc1.s1-eth11            |
+--------------+------------------------+-------------------+------------------+-------------------------+

# connect to ping VNF container:
docker exec -it mn.dc1_test-nsi.ping.1.ubuntu /bin/bash





Otras notas:

Multicast:

- Para ver los grupos a los que estas unido:
netstat -ng
ip maddr
cat /proc/net/igmp

- To join and leave a multicast group use -j and -l commands:
smcroute -j eth0 239.0.0.1
smcroute -l eth0 239.0.0.1

mcfirst -4 -I eth1 224.10.10.2 1234 -c 100
socat STDIO UDP4-RECV:1234,ip-add-membership=232.10.10.2:eth1
mcsender -t10 -ieth1 224.10.10.2:1234

- Acceder a las consolas de las vnfs (vclass y vcpe) con:

docker exec -ti mn.dc1_vcpe-1-1-ubuntu-1 bash
docker exec -ti mn.dc1_vcpe-1-2-vyos-1 bash -c 'su - vyos'
docker exec -ti mn.dc1_vcpe-2-1-ubuntu-1 bash
docker exec -ti mn.dc1_vcpe-2-2-vyos-1 bash -c 'su - vyos'








-------------------------------------
Configuracion de QoS (incompleta):

+ En vclass:
ovs-vsctl set Bridge br0 protocols=OpenFlow13
ovs-vsctl set-manager ptcp:6632
ovs-vsctl set-controller br0 tcp:127.0.0.1:6633
export SWDPID1=$( ovs-vsctl get Bridge br0 datapath_id | sed 's/"//g' )
echo $SWDPID1

ryu-manager ryu.app.rest_qos ryu.app.qos_simple_switch_13 ryu.app.rest_conf_switch
ryu-manager /flowmanager/flowmanager.py ryu.app.rest_qos ryu.app.qos_simple_switch_13 ryu.app.rest_conf_switch

tail -f /var/log/ryu/ryu.log 

curl -X PUT -d '"tcp:127.0.0.1:6632"' http://localhost:8080/v1.0/conf/switches/$SWDPID1/ovsdb_addr
curl -X GET http://localhost:8080/v1.0/conf/switches/$SWDPID1/ovsdb_addr

# upstream interface
curl -X POST -d '{"port_name": "vxlan2", "type": "linux-htb", "max_rate": "2000000", "queues": [{"max_rate": "2000000"},{"max_rate": "1000000"}]}' http://localhost:8080/qos/queue/$SWDPID1 | python3 -m json.tool
curl -X POST -d '{"match": {"nw_src": "192.168.255.10", "nw_proto": "TCP"}, "actions":{"queue": "0"}}' http://localhost:8080/qos/rules/$SWDPID1 | python3 -m json.tool

# downstream interface
curl -X POST -d '{"port_name": "vxlan1", "type": "linux-htb", "max_rate": "2000000", "queues": [{"max_rate": "2000000"},{"max_rate": "1000000"}]}' http://localhost:8080/qos/queue/$SWDPID1 | python3 -m json.tool
curl -X POST -d '{"match": {"nw_dst": "192.168.255.10", "nw_proto": "TCP"}, "actions":{"queue": "0"}}' http://localhost:8080/qos/rules/$SWDPID1 | python3 -m json.tool


Para ver la configuracion de QoS:

# queues
curl -X GET http://localhost:8080/qos/queue/$SWDPID1 | python3 -m json.tool

# rules
curl -X GET http://localhost:8080/qos/rules/$SWDPID1 | python3 -m json.tool

