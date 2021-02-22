#!/bin/bash
# LAUNCH API SERVER
# MUPI-PROXY

export DEBUG_MODE=True
export DB_URL="mongodb://localhost:27017"
export DB_NAME="mupiproxy"

#Start MongoDB
sudo systemctl start mongod

#Start API Server
uvicorn main:app --reload