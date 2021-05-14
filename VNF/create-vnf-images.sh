#!/bin/bash


for i in vnf-img vnf-mproxy vnf-vyos; do 

    echo "--"
    echo "-- Creating image $i..."
    echo "--"
    cd img/$i
    ./make
    cd ../..
    pwd
    echo ""

done
