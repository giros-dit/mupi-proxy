#!/bin/bash
# LAUNCH API SERVER
# MUPI-PROXY

#Start MongoDB
sudo systemctl start mongod

#Start API Server
python3 app/main.py