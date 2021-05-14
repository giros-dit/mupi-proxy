#!/bin/bash

function pause(){
read -s -n 1 -p "Press any key to continue . . ."
echo ""
}

COS="A B"

for l in $COS; do
    osm ns-create --nsd_name vCPE --ns_name vcpe-1$l --vim_account emu-vim
    osm ns-create --nsd_name vCPE --ns_name vcpe-2$l --vim_account emu-vim
    osm ns-create --nsd_name mproxy --ns_name mproxy$l --vim_account emu-vim
done

pause

for l in $COS; do
    ./init.sh $l
done

#pause

sudo vnx -f metro-internet.xml -v -t

#pause

for l in $COS; do
    sudo vnx -f central-office-$l.xml -v -t
done

#pause

for l in $COS; do
    VNF2="mn.dc1_vcpe-1${l}-2-vyos-1 mn.dc1_vcpe-2${l}-2-vyos-1"
    for d in $VNF2; do 
        while [  "$( docker container inspect -f '{{.State.Running}}' $d )" != true ]; do
            echo "Waiting for docker $d to start..."; sleep 5;
        done
    done
done

#pause
./vcpe1A.sh
#pause
./vcpe2A.sh
#pause
./config-vyos1A.sh
#pause
./config-vyos2A.sh

#pause
./config-mproxyA.sh


#pause
./vcpe1B.sh
#pause
./vcpe2B.sh
#pause
./config-vyos1B.sh
#pause
./config-vyos2B.sh

#pause
./config-mproxyB.sh
