Multiple Upstream Interfaces Multicast Proxy (mupi-proxy)
=========================================================

Mupi-proxy (Multiple UPstream Interfaces multicast Proxy) is a proof of concept implementation of the extensions defined in IETF [draft-asaeda-pim-multiif-igmpmldproxy-04](https://datatracker.ietf.org/doc/draft-asaeda-pim-multiif-igmpmldproxy/) to support multiple upstream interfaces in IGMP/MLD proxies. It has been implemented for Linux using an SDN application running over Ryu controller that controls and Open vSwitch in charge of relaying the multicast data flows and IGMP/MLD traffic.

The generic working scenario of mupi-proxy is presented in the figure, where several IP multicast flow providers are connected to upstream interfaces and several clients that consume the multicast flows are connected to downstream interfaces.

![Fig1](https://github.com/giros-dit/mupi-proxy/blob/master/figures/mupi-proxy-fig1.png)

In this scenario, mupi-proxy is in charge of relaying the control and data multicast flows among clients and providers. Basically it:
- Relays the IGMP/MLD control requests sent by the clients to the providers following the selection policies configured. For that purpose, mupi-proxy includes a Multicast Upstream Routing Table (MURT) that allows to specify how the upstream interface is selected in terms of the client's IP address, the multicast group and the IP address of the multicast flow source.  
- Relays the multicast data traffic sent by the providers to the clients.

Mupi-proxy works as a standard Ethernet switch for unicast traffic. 

The main task to carry out when configuring mupi-proxy is the definition of the MURT. Each entry of the MURT is a 5-tuple with the following format:

```(client_ip, mcast_group, mcast_src_ip, upstream_if, priority)```

Being:
- **client_ip**: an IP address or prefix used to define the range of clients IP addresses the entry applies to.
- **mcast_group**: an IP multicast group or a prefix of multicast groups the entry applies to.
- **mcast_src_ip**: an IP address or prefix used to define the range of mcast source IP addresses the entry applies to.
- **upstream_if**: the number of the upstream interface to be used. 
- **priority**: the priority of the table entry. 

The first three fields (client_ip, mcast_group and mcast_src_ip) can be empty. An empty value in these fields is equivalent to 0.0.0.0/0.

When a request to join an IP multicast group is received from a client, the mupi-proxy extracts the client source IP address, the IP multicast group and, if specified, the multicast source IP address. With these three values, it iterates over the MURT entries to find the ones that match the request values, selecting the one with the highest priority and relaying the IGMP/MLD request to the upstream interface specified in the selected entry.

In case two or more entries with the same priority are selected, the request is sent to all the upstream interfaces specified in the MURT entries.

For example, if the MURT is configured with the following values:

|   |client_ip        |mcast_group      |mcast_src_ip     |upstream_if |priority |
|---|:----------------|:----------------|:----------------|------------|---------|
| 1 |10.100.0.0/26    |224.0.122.5      |10.100.0.21      |    7       |   30    |
| 2 |                 |224.0.122.5      |                 |    8       |   20    |
| 3 |0.0.0.0/0        |224.0.0.0/4      |0.0.0.0/0        |    9       |   0     |

the following queries would be directed to the upstream interfaces specified below:

- Q1: (10.100.0.20, 224.0.122.5, 10.100.0.21) -> 7     # matching entries: 1,2
- Q2: (10.100.0.70, 224.0.122.5, 10.100.0.21) -> 8     # matching entries: 2,3
- Q3: (10.100.0.70, 224.0.122.6, 10.100.0.21) -> 9     # matching entries: 3


Testing mupi-proxy
------------------

A [Virtual Networks over LinuX (VNX)](http://vnx.dit.upm.es) virtual testbed scenario is distributed to easily test mupi-proxy. The test scenario is made of:
- A Linux container (LXC) named controller which runs the Ryu controller and the mupi-proxy application.
- An Open vSwitch (OVS) which is in charge of forwarding the traffic and it is OpenFlow-controlled from the SDN controller.
- Three containers (provider1-3) which act as IP multicast flow providers.
- Six containers (client1-6) which act as clients that request IP multicast flows to the different providers.

![Fig2](https://github.com/giros-dit/mupi-proxy/blob/master/figures/mupi-proxy-fig2.png)

To start using the mupi-proxy test scenario:

1. Download and install the latest version of the VNXSDNLAB virtual machine from:

```https://idefix.dit.upm.es/download/vnx/vnx-vm/VNXSDNLAB2020-v1.ova```

  Alternatevely, the scenario can be started from a Linux computer with VNX installed (see
  http://vnx.dit.upm.es/ for installation details).

2. Start the VNXSDNLAB virtual machine and clone this github repository:

```git clone https://github.com/giros-dit/mupi-proxy.git```

3. Download the test scenario containers image:

```cd test/filesystems
vnx_download_rootfs -r vnx_rootfs_lxc_ubuntu64-18.04-v025-vnxlab2.tgz
cd .. 
```

4. Start the test scenario with:

```vnx -f mupi-proxy-test1.xml -v --create```

5. Start mupi-proxy in controller container with:

```ssh controller
ryu-manager /root/ryu/flowmanager/flowmanager.py /root/mupi-proxy/mupi-proxy.py --config-file /root/mupi-proxy/conf/<config-file>
```

being <config-file> the name of the mupi-proxy configuration file (see examples under mupi-proxy/conf/ directory).

6. Once the scenario is started, you can connect to:
..* the providers to program them to start sending IP multicast flows. For example, the command:

```mcsender -t3 -ieth1 224.100.10.10:1234```

...starts to send one ip multicast packet each three seconds to 224.100.10.10:1234 through interface eth1
..* the clients to join to the multicast groups sent by the providers. For example, the command: 

```mcfirst -4 -I eth1 224.100.10.10 1234 -c 10```

...request to join to multicast group 224.100.10.10 and loops till it receives 10 packets sent to 224.100.10.10:1234 through interface eth1.


Example configurations
----------------------
