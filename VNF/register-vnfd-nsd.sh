#!/bin/bash

osm vnfd-create pck/vnf-vclass.tar.gz
osm vnfd-create pck/vnf-vcpe.tar.gz
osm vnfd-create pck/vnf-mproxy.tar.gz
osm nsd-create pck/ns-vcpe.tar.gz
osm nsd-create pck/ns-mproxy.tar.gz

