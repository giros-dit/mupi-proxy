FROM ubuntu:bionic
# install required packages
RUN apt-get clean
RUN export DEBIAN_FRONTEND=noninteractive \ 
    && apt-get update \
    && apt-get install -y  git \
    net-tools \
    aptitude \
    build-essential \
    python-setuptools \
    python-dev \
    python-pip \
    software-properties-common \
    ansible \
    curl \
    iptables \
    iputils-ping \
    sudo \
    nano \
    bridge-utils \
    isc-dhcp-client \
    isc-dhcp-server \
    tcpdump \
    openvswitch-switch \
    iperf3 \
    vim \
    aptsh \
    iproute2 \
    ryu-bin \
    python3-pip \ 
    wget 

# 
RUN sed '/OFPFlowMod(/,/)/s/)/, table_id=1)/' /usr/lib/python3/dist-packages/ryu/app/simple_switch_13.py > /usr/lib/python3/dist-packages/ryu/app/qos_simple_switch_13.py

RUN pip3 install requests
RUN pip3 install jq
RUN pip3 install pymongo
RUN pip3 install netaddr
RUN pip3 install roundrobin

RUN wget -qO - https://www.mongodb.org/static/pgp/server-4.4.asc | apt-key add -
RUN echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu bionic/mongodb-org/4.4 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-4.4.list
RUN apt-get update
RUN apt-get install -y mongodb-org

ENV MONGO_DETAILS=mongodb://127.0.0.1:27017

RUN cd root; git clone https://github.com/martimy/flowmanager.git

RUN sudo mkdir -p /data/db

RUN sudo chown -R root /data/db

RUN mongod &

EXPOSE 27017