#!/bin/bash

osm nsd-delete vCPE
osm nsd-delete mproxy

osm vnfd-delete vclass
osm vnfd-delete vcpe
osm vnfd-delete mproxy
