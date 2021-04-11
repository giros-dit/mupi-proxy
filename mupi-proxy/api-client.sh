#!/bin/bash

#API REST CLIENT
#EASY REQUESTS

USAGE="
Usage:

Make your api requests to configure mupi-proxy controller

Select:
	- [1] MURT ENTRY
	- [2] PROVIDER
	- [3] SDN CONTROLLER
	- [4] FLOWS
	- [X] EXIT
"

MURT_OPERATION="

###########################################################
#                   MURT-ENTRY OPERATION                  #
###########################################################
Select:
	- [1] Retrieve all MURT Entries present in the database
	- [2] Add a new MURT Entry into the database
	- [3] Retrieve a MURT Entry with a matching ID
	- [4] Update a MURT Entry with a matching ID
	- [5] Delete a MURT Entry from the database
	- [6] Delete all MURT Entries from the database
	- [7] Show MURT Table
	- [B] Back

"

PROVIDER_OPERATION="

###########################################################
#                    PROVIDER OPERATION                   #
###########################################################
Select:
	- [1] Retrieve all Providers present in the database
	- [2] Add a new Provider into the database
	- [3] Retrieve a Provider with a matching ID
	- [4] Update a Provider with a matching ID
	- [5] Delete a Provider from the database
	- [6] Delete all Providers from the database
	- [7] Show Providers Table
	- [8] Give providers for a specific channel
	- [B] Back

"

CONTROLLER_OPERATION="

###########################################################
#                   CONTROLLER OPERATION                  #
###########################################################
Select:
	- [1] Retrieve all Controllers present in the database
	- [2] Add a new Controller into the database
	- [3] Retrieve a Controller with a matching ID
	- [4] Update a Controller with a matching ID
	- [5] Delete a Controller from the database
	- [6] Delete all Controllers from the database
	- [7] Show Controllers Table
	- [B] Back

"

FLOWS_OPERATION="

###########################################################
#                     FLOWS OPERATION                     #
###########################################################
Select:
	- [1] Retrieve all Flows installed in the switch
	- [2] Retrieve all Flows for a specific Murt Entry ID
	- [B] Back

"

echo "

###########################################################
#                                                         #
#                    MUPI-PROXY CLIENT                    #
#                                                         #
###########################################################

"

if [[ $# -ne 0 ]]; then
        echo ""       
    echo "ERROR: incorrect number of parameters"
    echo "$USAGE"
    exit 1
fi

echo "$USAGE"



while [ True ]

do
	read -p "Select your option: 1, 2, 3 or 4 ---> " CONFIGURATION
	echo "" 
	OPTION="$CONFIGURATION"

	if [ "$OPTION" = 1 ]
	then
	   echo "MURT ENTRY"
	   echo "$MURT_OPERATION"

	   

	   while [ True ]
	   do

		   read -p "Select your operation: 1, 2, 3, 4, 5, 6 or 7 ---> " MURT_OPERATION_SELECTED
		   echo "" 
		   OPERATION="$MURT_OPERATION_SELECTED"


		   if [ "$OPERATION" = 1 ]
			then
			   echo "Retrieve all MURT Entries present in the database"
			   curl -X  GET http://127.0.0.1:8080/mupi-proxy/murtentries
			   echo ""
			   read -p ""
			   echo "$MURT_OPERATION"

			elif [ "$OPERATION" = 2  ]
			then
			   echo "Add a new MURT Entry into to the database"
			   read -p "client_ip: ------> " CLIENT_IP
			   read -p "downstream_if: --> " DOWNSTREAM_IF
			   read -p "mcast_group: ----> " MCAST_GROUP
			   read -p "mcast_src_ip: ---> " MCAST_SRC_IP
			   read -p "upstream_if: ----> " UPSTREAM_IF
			   read -p "priority: -------> " PRIORITY

			   NEW_ENTRY='{"client_ip":"'$CLIENT_IP'", "downstream_if":"'$DOWNSTREAM_IF'","mcast_group":"'$MCAST_GROUP'", "mcast_src_ip":"'$MCAST_SRC_IP'", "upstream_if":'$UPSTREAM_IF', "priority":'$PRIORITY'}'

			   echo "$NEW_ENTRY"
			   read -p "Type YES to confirm your entry: " CONFIRMATION
			   if [ "$CONFIRMATION" = "YES" ]
			    then
			    	echo "CONFIRMED"
			    	curl -X POST -d "$NEW_ENTRY" http://127.0.0.1:8080/mupi-proxy/murtentries
			    	#curl -X POST -d '{"client_ip":"'$CLIENT_IP'", "mcast_group":"'$MCAST_GROUP'", "mcast_src_ip":"'$MCAST_SRC_IP'", "upstream_if":'$UPSTREAM_IF', "priority":'$PRIORITY', "downstream_if":"'$DOWNSTREAM_IF'"}' http://127.0.0.1:8080/mupi-proxy/murtentries
			    	echo ""
			    	read -p ""
			   		echo "$MURT_OPERATION"
			   else
			   	echo "CANCELLED"
			   	echo ""
			   	read -p ""
			   	echo "$MURT_OPERATION"
			   fi


			elif [ "$OPERATION" = 3  ]
			then
			   echo "Retrieve a MURT Entry with a matching ID"
			   read -p "Write the murt entry ID requested --> " MURT_ENTRY_ID
			   ID="$MURT_ENTRY_ID"
			   curl -X  GET http://127.0.0.1:8080/mupi-proxy/murtentries/$ID
			   echo ""
			   read -p ""
			   echo "$MURT_OPERATION"


			elif [ "$OPERATION" = 4  ]
			then
			   echo "Update a MURT Entry with a matching ID"
			   read -p "Write the murt entry ID requested --> " MURT_ENTRY_ID
			   ID="$MURT_ENTRY_ID"
			   curl -X  GET http://127.0.0.1:8080/mupi-proxy/murtentries/$ID
			   echo ""
			   echo "Type the field to update: {\"key\":\"value\",...}"
			   read -p "" UPDATED_ENTRY
			   echo "$UPDATED_ENTRY"
			   read -p "Confirm typing YES: --> " CONFIRMATION
			   if [ "$CONFIRMATION" = "YES" ]
			   	then
			   		curl -X PUT -d "$UPDATED_ENTRY" http://127.0.0.1:8080/mupi-proxy/murtentries/$ID
			   fi
			   read -p ""
			   echo "$MURT_OPERATION"


			elif [ "$OPERATION" = 5  ]
			then
			   echo "Delete a MURT Entry from the database"
			   read -p "Write the murt entry ID requested --> " MURT_ENTRY_ID
			   ID="$MURT_ENTRY_ID"
			   curl -X DELETE http://127.0.0.1:8080/mupi-proxy/murtentries/$ID
			   echo ""
			   read -p ""
			   echo "$MURT_OPERATION"

			elif [ "$OPERATION" = 6  ]
			then
			   echo "Delete all MURT Entries from the database"
			   read -p "Write YES to confirm the operation --> " CONFIRMATION
			   if [ "$CONFIRMATION" = "YES" ]
			   	then
			   		curl -X DELETE http://127.0.0.1:8080/mupi-proxy/murtentries
			   		echo ""
			   		read -p ""
			    	echo "$MURT_OPERATION"
			   else
			   		echo "OPERATION CANCELLED"
			   		echo ""
			   		read -p ""
			   		echo "$MURT_OPERATION"
			   fi
			elif [ "$OPERATION" = 7  ]
			then
			   echo "MURT ENTRY TABLE"
			   curl -X  GET http://127.0.0.1:8080/mupi-proxy/murtentries-table
			   echo ""
			   read -p ""
			   echo "$MURT_OPERATION"
			elif [ "$OPERATION" = "B"  ]
			then
			   echo "Back"
			   echo "$USAGE"
			   break
			else
				echo ""       
			    echo "ERROR: invalid operation"
			    echo "$MURT_OPERATION"
		   fi
		done


	elif [ "$OPTION" = 2 ]
	then
	   echo "PROVIDER"
	   echo "$PROVIDER_OPERATION"

	   while [ True ]
	   do

		   read -p "Select your operation: 1, 2, 3, 4, 5, 6, 7 or 8 ---> " PROVIDER_OPERATION_SELECTED
		   echo "" 
		   OPERATION="$PROVIDER_OPERATION_SELECTED"


		   if [ "$OPERATION" = 1 ]
			then
			   echo "Retrieve all Providers present in the database"
			   curl -X  GET http://127.0.0.1:8080/mupi-proxy/providers
			   echo ""
			   read -p ""
			   echo "$PROVIDER_OPERATION"

			elif [ "$OPERATION" = 2  ]
			then
			   echo "Add a new Provider into to the database"
			   read -p "Description: ------> " DESCRIPTION
			   read -p "mcast_src_ip: ---> " MCAST_SRC_IP
			   read -p "upstream_if: ----> " UPSTREAM_IF
			   read -p "mcast_groups [\"ip1\", \"ip2\", ...]: ----> " MCAST_GROUPS
			   NEW_PROVIDER='{"description":"'$DESCRIPTION'", "mcast_src_ip":"'$MCAST_SRC_IP'", "upstream_if":"'$UPSTREAM_IF'", "mcast_groups": '$MCAST_GROUPS'}'

			   echo "$NEW_PROVIDER"
			   read -p "Type YES to confirm your entry: " CONFIRMATION
			   if [ "$CONFIRMATION" = "YES" ]
			    then
			    	echo "CONFIRMED"
			    	curl -X POST -d "$NEW_PROVIDER" http://127.0.0.1:8080/mupi-proxy/providers
			    	#curl -X POST -d '{"client_ip":"'$CLIENT_IP'", "mcast_group":"'$MCAST_GROUP'", "mcast_src_ip":"'$MCAST_SRC_IP'", "upstream_if":'$UPSTREAM_IF', "priority":'$PRIORITY', "downstream_if":"'$DOWNSTREAM_IF'"}' http://127.0.0.1:8080/mupi-proxy/murtentries
			    	echo ""
			    	read -p ""
			   		echo "$PROVIDER_OPERATION"
			   else
			   	echo "CANCELLED"
			   	echo ""
			   	read -p ""
			   	echo "$PROVIDER_OPERATION"
			   fi


			elif [ "$OPERATION" = 3  ]
			then
			   echo "Retrieve a Provider with a matching ID"
			   read -p "Write the provider ID requested --> " PROVIDER_ID
			   ID="$PROVIDER_ID"
			   curl -X  GET http://127.0.0.1:8080/mupi-proxy/providers/$ID
			   echo ""
			   read -p ""
			   echo "$PROVIDER_OPERATION"

			elif [ "$OPERATION" = 4  ]
			then
			   echo "Update a Provider with a matching ID"
			   read -p "Write the Provider ID requested --> " PROVIDER_ID
			   ID="$PROVIDER_ID"
			   curl -X  GET http://127.0.0.1:8080/mupi-proxy/providers/$ID
			   echo ""
			   echo "Type the field to update: {\"key\":\"value\",...}"
			   read -p "" UPDATED_PROVIDER
			   echo "$UPDATED_PROVIDER"
			   read -p "Confirm typing YES: --> " CONFIRMATION
			   if [ "$CONFIRMATION" = "YES" ]
			   	then
			   		curl -X PUT -d "$UPDATED_PROVIDER" http://127.0.0.1:8080/mupi-proxy/providers/$ID
			   fi
			   read -p ""
			   echo "$PROVIDER_OPERATION"


			elif [ "$OPERATION" = 5  ]
			then
			   echo "Delete a Provider from the database"
			   read -p "Write the Provider ID requested --> " PROVIDER_ID
			   ID="$PROVIDER_ID"
			   curl -X DELETE http://127.0.0.1:8080/mupi-proxy/providers/$ID
			   echo ""
			   read -p ""
			   echo "$PROVIDER_OPERATION"

			elif [ "$OPERATION" = 6  ]
			then
			   echo "Delete all Providers from the database"
			   read -p "Write YES to confirm the operation --> " CONFIRMATION
			   if [ "$CONFIRMATION" = "YES" ]
			   	then
			   		curl -X DELETE http://127.0.0.1:8080/mupi-proxy/providers
			   		echo ""
			   		read -p ""
			    	echo "$PROVIDER_OPERATION"
			   else
			   		echo "OPERATION CANCELLED"
			   		echo ""
			   		read -p ""
			   		echo "$PROVIDER_OPERATION"
			   fi
			elif [ "$OPERATION" = 7  ]
			then
			   echo "PROVIDERS TABLE"
			   curl -X  GET http://127.0.0.1:8080/mupi-proxy/providers-table
			   echo ""
			   read -p ""
			   echo "$PROVIDER_OPERATION"

			elif [ "$OPERATION" = '8'  ]
			then
			   echo "Who broadcast this channel?"
			   read -p "Write the channel ID requested --> " CHANNEL_ID
			   ID="$CHANNEL_ID"
			   curl -X  GET http://127.0.0.1:8080/mupi-proxy/channel/$ID
			   echo ""
			   read -p ""
			   echo "$PROVIDER_OPERATION"

			elif [ "$OPERATION" = "B"  ]
			then
			   echo "Back"
			   echo "$USAGE"
			   break
			else
				echo ""       
			    echo "ERROR: invalid operation"
			    echo "$PROVIDER_OPERATION"
		   fi
		done


	elif [ "$OPTION" = 3 ]
	then
	   echo "SDN CONTROLLER"
	   echo "$CONTROLLER_OPERATION"

	   while [ True ]
	   do

		   read -p "Select your operation: 1, 2, 3, 4, 5, 6 or 7 ---> " CONTROLLER_OPERATION_SELECTED
		   echo "" 
		   OPERATION="$CONTROLLER_OPERATION_SELECTED"


		   if [ "$OPERATION" = 1 ]
			then
			   echo "Retrieve all Controllers present in the database"
			   curl -X  GET http://127.0.0.1:8080/mupi-proxy/controllers
			   echo ""
			   read -p ""
			   echo "$CONTROLLER_OPERATION"

			elif [ "$OPERATION" = 2  ]
			then
			   echo "Add a new Controller into to the database"
			   read -p "OpenFlow Version: ------> " OPENFLOW_VERSION
			   read -p "TCP PORT: ---> " TCP_PORT
			   read -p "IP ADDRESS: ----> " IP_ADDRESS
			   read -p "DESCRIPTION ----> " DESCRIPTION
			   NEW_CONTROLLER='{"description":"'$DESCRIPTION'", "openflow_version":"'$OPENFLOW_VERSION'", "tcp_port":"'$TCP_PORT'", "ip_address": "'$IP_ADDRESS'"}'

			   echo "$NEW_CONTROLLER"
			   read -p "Type YES to confirm your entry: " CONFIRMATION
			   if [ "$CONFIRMATION" = "YES" ]
			    then
			    	echo "CONFIRMED"
			    	curl -X POST -d "$NEW_CONTROLLER" http://127.0.0.1:8080/mupi-proxy/controllers
			    	#curl -X POST -d '{"client_ip":"'$CLIENT_IP'", "mcast_group":"'$MCAST_GROUP'", "mcast_src_ip":"'$MCAST_SRC_IP'", "upstream_if":'$UPSTREAM_IF', "priority":'$PRIORITY', "downstream_if":"'$DOWNSTREAM_IF'"}' http://127.0.0.1:8080/mupi-proxy/murtentries
			    	echo ""
			    	read -p ""
			   		echo "$CONTROLLER_OPERATION"
			   else
			   	echo "CANCELLED"
			   	echo ""
			   	read -p ""
			   	echo "$CONTROLLER_OPERATION"
			   fi


			elif [ "$OPERATION" = 3  ]
			then
			   echo "Retrieve a Controller with a matching ID"
			   read -p "Write the Controller ID requested --> " CONTROLLER_ID
			   ID="$CONTROLLER_ID"
			   curl -X  GET http://127.0.0.1:8080/mupi-proxy/controllers/$ID
			   echo ""
			   read -p ""
			   echo "$CONTROLLER_OPERATION"


			elif [ "$OPERATION" = 4  ]
			then
			   echo "Update a Controller with a matching ID"
			   read -p "Write the Controller ID requested --> " CONTROLLER_ID
			   ID="$CONTROLLER_ID"
			   curl -X  GET http://127.0.0.1:8080/mupi-proxy/controllers/$ID
			   echo ""
			   echo "Type the field to update: {\"key\":\"value\",...}"
			   read -p "" UPDATED_CONTROLLER
			   echo "$UPDATED_CONTROLLER"
			   read -p "Confirm typing YES: --> " CONFIRMATION
			   if [ "$CONFIRMATION" = "YES" ]
			   	then
			   		curl -X PUT -d "$UPDATED_CONTROLLER" http://127.0.0.1:8080/mupi-proxy/controllers/$ID
			   fi
			   read -p ""
			   echo "$CONTROLLER_OPERATION"


			elif [ "$OPERATION" = 5  ]
			then
			   echo "Delete a Controller from the database"
			   read -p "Write the Controller ID requested --> " CONTROLLER_ID
			   ID="$CONTROLLER_ID"
			   curl -X DELETE http://127.0.0.1:8080/mupi-proxy/controllers/$ID
			   echo ""
			   read -p ""
			   echo "$CONTROLLER_OPERATION"

			elif [ "$OPERATION" = 6  ]
			then
			   echo "Delete all Controllers from the database"
			   read -p "Write YES to confirm the operation --> " CONFIRMATION
			   if [ "$CONFIRMATION" = "YES" ]
			   	then
			   		curl -X DELETE http://127.0.0.1:8080/mupi-proxy/controllers
			   		echo ""
			   		read -p ""
			    	echo "$CONTROLLER_OPERATION"
			   else
			   		echo "OPERATION CANCELLED"
			   		echo ""
			   		read -p ""
			   		echo "$CONTROLLER_OPERATION"
			   fi
			elif [ "$OPERATION" = 7  ]
			then
			   echo "CONTROLLERS TABLE"
			   curl -X  GET http://127.0.0.1:8080/mupi-proxy/controllers-table
			   echo ""
			   read -p ""
			   echo "$CONTROLLER_OPERATION"
			elif [ "$OPERATION" = "B"  ]
			then
			   echo "Back"
			   echo "$USAGE"
			   break
			else
				echo ""       
			    echo "ERROR: invalid operation"
			    echo "$CONTROLLER_OPERATION"
		   fi
		done

	elif [ "$OPTION" = 4 ]
	then
	   echo "FLOWS"
	   echo "$FLOWS_OPERATION"

	   

	   while [ True ]
	   do

		   read -p "Select your operation: 1 or 2  ---> " FLOW_OPERATION_SELECTED
		   echo "" 
		   OPERATION="$FLOW_OPERATION_SELECTED"


		   if [ "$OPERATION" = 1 ]
			then
			   echo "FLOWS TABLE"
			   curl -X  GET http://127.0.0.1:8080/mupi-proxy/flows
			   echo ""
			   read -p ""
			   echo "$FLOWS_OPERATION"

			elif [ "$OPERATION" = 2  ]
			then
			   echo "Retrieve the flows with a matching MURT Entry ID"
			   read -p "Write the murt entry ID requested --> " MURT_ENTRY_ID
			   ID="$MURT_ENTRY_ID"
			   curl -X  GET http://127.0.0.1:8080/mupi-proxy/flows/$ID
			   echo ""
			   read -p ""
			   echo "$FLOWS_OPERATION"

			elif [ "$OPERATION" = "B"  ]
			then
			   echo "Back"
			   echo "$USAGE"
			   break
			else
				echo ""       
			    echo "ERROR: invalid operation"
			    echo "$FLOWS_OPERATION"
		   fi
		done
	
	elif [ "$OPTION" = "X" ]
	then
	   echo "Bye"
	   echo ""
	   exit 0
	   
	else
	    echo ""       
	    echo "ERROR: invalid option"
	    echo "$USAGE"
	fi
done