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
	- [X] EXIT
"

MURT_OPERATION="

###########################################################
#                   MURT-ENTRY OPERATION                  #
###########################################################
Select:
	- [1] Retrieve all MURT Entries present in the database
	- [2] Add a new MURT Entry into to the database
	- [3] Retrieve a MURT Entry with a matching ID
	- [4] Update a MURT Entry with a matching ID
	- [5] Delete a MURT Entry from the database
	- [6] Delete all MURT Entries from the database
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
	read -p "Select your option: 1, 2 or 3 ---> " CONFIGURATION
	echo "" 
	OPTION="$CONFIGURATION"

	if [ $OPTION == 1 ]
	then
	   echo "MURT ENTRY"
	   echo "$MURT_OPERATION"

	   

	   while [ True ]
	   do

		   read -p "Select your operation: 1, 2, 3, 4, 5 or 6 ---> " MURT_OPERATION_SELECTED
		   echo "" 
		   OPERATION="$MURT_OPERATION_SELECTED"


		   if [ $OPERATION == 1 ]
			then
			   echo "Retrieve all MURT Entries present in the database"
			   echo "Requesting..."
			   curl -X  GET http://127.0.0.1:8080/mupi-proxy/murtentries
			   echo ""
			   read -p ""
			   echo "$MURT_OPERATION"

			elif [ $OPERATION == 2  ]
			then
			   echo "Add a new MURT Entry into to the database"
			   read -p "client_ip: ------> " CLIENT_IP
			   read -p "mcast_group: ----> " MCAST_GROUP
			   read -p "mcast_src_ip: ---> " MCAST_SRC_IP
			   read -p "upstream_if: ----> " UPSTREAM_IF
			   read -p "priority: -------> " PRIORITY
			   read -p "downstream_if: --> " DOWNSTREAM_IF

			   NEW_ENTRY='{"client_ip":"'$CLIENT_IP'", "mcast_group":"'$MCAST_GROUP'", "mcast_src_ip":"'$MCAST_SRC_IP'", "upstream_if":"'$UPSTREAM_IF'", "priority":"'$PRIORITY'", "downstream_if":"'$DOWNSTREAM_IF'"}'

			   echo "$NEW_ENTRY"
			   read -p "Type YES to confirm your entry: " CONFIRMATION
			   if [ $CONFIRMATION == "YES" ]
			    then
			    	echo "CONFIRMED"
			    	#curl -X POST -d $NEW_ENTRY http://127.0.0.1:8080/mupi-proxy/murtentries
			    	curl -X POST -d '{"client_ip":"'$CLIENT_IP'", "mcast_group":"'$MCAST_GROUP'", "mcast_src_ip":"'$MCAST_SRC_IP'", "upstream_if":'$UPSTREAM_IF', "priority":'$PRIORITY', "downstream_if":"'$DOWNSTREAM_IF'"}' http://127.0.0.1:8080/mupi-proxy/murtentries
			    	echo ""
			    	read -p ""
			   		echo "$MURT_OPERATION"
			   else
			   	echo "CANCELLED"
			   	echo ""
			   	read -p ""
			   	echo "$MURT_OPERATION"
			   fi


			elif [ $OPERATION == 3  ]
			then
			   echo "Retrieve a MURT Entry with a matching ID"
			   read -p "Write the murt entry ID requested --> " MURT_ENTRY_ID
			   ID="$MURT_ENTRY_ID"
			   curl -X  GET http://127.0.0.1:8080/mupi-proxy/murtentries/$ID
			   echo ""
			   read -p ""
			   echo "$MURT_OPERATION"


			elif [ $OPERATION == 4  ]
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
			   if [ $CONFIRMATION == "YES" ]
			   	then
			   		curl -X PUT -d $UPDATED_ENTRY http://127.0.0.1:8080/mupi-proxy/murtentries/$ID
			   fi
			   read -p ""
			   echo "$MURT_OPERATION"


			elif [ $OPERATION == 5  ]
			then
			   echo "Delete a MURT Entry from the database"
			   read -p "Write the murt entry ID requested --> " MURT_ENTRY_ID
			   ID="$MURT_ENTRY_ID"
			   curl -X DELETE http://127.0.0.1:8080/mupi-proxy/murtentries/$ID
			   echo ""
			   read -p ""
			   echo "$MURT_OPERATION"

			elif [ $OPERATION == 6  ]
			then
			   echo "Delete all MURT Entries from the database"
			   read -p "Write YES to confirm the operation --> " CONFIRMATION
			   if [ $CONFIRMATION == "YES" ]
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
			elif [ $OPERATION == "B"  ]
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


	elif [ $OPTION == 2 ]
	then
	   echo "PROVIDER"
	   echo ""
	   echo "$USAGE"
	elif [ $OPTION == 3 ]
	then
	   echo "SDN CONTROLLER"
	   echo ""
	   echo "$USAGE"
	elif [ $OPTION == "X" ]
	then
	   echo "Goodbye"
	   echo ""
	   exit 0
	   
	else
	    echo ""       
	    echo "ERROR: invalid option"
	    echo "$USAGE"
	fi
done