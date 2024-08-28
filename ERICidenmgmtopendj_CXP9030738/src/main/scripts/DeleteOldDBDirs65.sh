#!/bin/bash

##################################################
# THIS SCRIPT WILL BE CALLED AS DEAMON PROCESS
# ONLY DURING UPGRADE FROM 6.5 to 7.x BY THE
# FIRST OPENDJ THAT IS UPGRADED.
# ITS WORK OF REMOVING THE OLD ADMIN DIRECTORIES
# WILL BE DONE DURING THE UPGRADE
# OF THE SECOND OPENDJ.
# TO WORK IT REQUIRES SOME ENVIRONMENT VARIABLE
# THAT CAN BE EXPORT BEFORE CALL IT.
##################################################

#######################################
# Function: RemoveOldAdminDataDB
#
# Description: This function checks:
#              - the local doesn't have the admin backend anymore
#              - there are still the two directory to be remove
#
# Action: Remove the directory admin data and ads-truststore from the first upgraded opendj
#
# Arguments:
#   None
#
# Returns:
#   0 - success
#   1 - failure
#######################################
RemoveOldAdminDataDB(){

REMOVED=false
REM_1=false
REM_2=false
echo $OPENDJ_ROOT
echo $DSCONFIG
echo
while [ $REMOVED == false ]; do

  sleep 240

    $DSCONFIG get-backend-prop --backend-name adminRoot --hostname localhost -p $ADMIN_CONNECTOR_PORT -D "$DM_DN" -X -w "$DM_PWD" -n
    # $DSCONFIG --offline get-backend-prop --backend-name adminRoot -n
    ret=$?
    if [ $ret == 32 ]; then
        echo "INFO: Starting RemoveOldAdminDataDB ..."
        if [ -d $OPENDJ_ROOT/db/adminRoot ] ; then
            rm -Rf $OPENDJ_ROOT/db/adminRoot
            if [ $? == 0 ] ; then
               REM_1=true
               echo "INFO: Successfully removed /../opendj/db/adminRoot dir."
            fi
        else
          REM_1=true
          echo "INFO: dir /../opendj/db/adminRoot alredy removed."
        fi
        if [ -d $OPENDJ_ROOT/db/ads-truststore ] ; then
            rm -Rf  $OPENDJ_ROOT/db/ads-truststore
            if [ $? == 0 ] ; then
               REM_2=true
               echo "INFO: Successfully removed /../opendj/db/ads-truststore dir."
            fi
        else
          REM_2=true
          echo "INFO: dir /../opendj/db/ads-truststore alredy removed."
        fi
    fi
    if [ $REM_1 == true ] && [ $REM_2 == true ]; then
       REMOVED=true
    fi

done
echo "INFO: RemoveOldAdminDataDB completed ..."
return 0

}

RemoveOldAdminDataDB
exit 0
