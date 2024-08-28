#!/bin/bash

################################################################################
# Copyright (c) 2014 Ericsson, Inc. All Rights Reserved.
# This script enables / initializes LDAP replication
# Author: Ben Deng
# ESN 38137
################################################################################

IDENMGMT_ROOT=/opt/ericsson/com.ericsson.oss.security/idenmgmt
NEW_OPENDJ_MAJOR_VERSION=$(cat $IDENMGMT_ROOT/opendj/config/version | cut -d. -f1)
if [ $NEW_OPENDJ_MAJOR_VERSION -ge 7 ]; then
    echo "The opendj version is $NEW_OPENDJ_MAJOR_VERSION"
    echo "then the configuration of the replication is not required"
    exit 0
fi

# optional parameter, if present the script will not manage the lock file
# (to be used only in manual mode)
MANUAL_MODE=false
if [ ! -z "$1" ] ; then
   if [ "$1" == "manual-no-lock" ] ; then
      echo "MANUAL MODE: no lock file check"
      MANUAL_MODE=true
   fi
fi

GREP='/bin/grep -w'
CUT=/bin/cut
PING=/bin/ping
OPENSSL=/usr/bin/openssl
HOST_NAME=/bin/hostname
RM=/bin/rm

# PurgeDelay Setting
REPLICATION_PURGE_DELAY_CLOUD="24h"
REPLICATION_PURGE_DELAY_pENM="24h"

LOG_DIR="/var/log/opendj"
LOG_FILE="$LOG_DIR/opendj-replication-config-`/bin/date "+%F:%H:%M:%S%:z"`.log"

# global properties that are either required by SSO or defined in the SED.
GLOBAL_PROPERTY_FILE=/ericsson/tor/data/global.properties
. $GLOBAL_PROPERTY_FILE >/dev/null 2>&1

# deployment paths
IDENMGMT_ROOT=/opt/ericsson/com.ericsson.oss.security/idenmgmt

source $IDENMGMT_ROOT/opendj/bin/common.sh
if [ $? -ne 0 ]; then
   echo "ERROR: Failed to source $IDENMGMT_ROOT/opendj/bin/common.sh"
   exit 1
fi

IsOnCloud
if [ $? == 0 ] ; then
   OPENDJ_ROOT=/ericsson/opendj/opendj
   OPENDJ_ROOT_PARENT=/ericsson/opendj
else
   OPENDJ_ROOT=/opt/opendj
   OPENDJ_ROOT_PARENT=/opt/
fi
                            
# OpenDJ tools
DSREPLICATION=$OPENDJ_ROOT/bin/dsreplication
DSCONFIG=$OPENDJ_ROOT/bin/dsconfig
DSSTATUS=$OPENDJ_ROOT/bin/status

# get datastore.properties settings
PROPS_FILE=$IDENMGMT_ROOT/config/datastore.properties
LDAP_PORT=`$GREP ldapPort $PROPS_FILE | $CUT -d= -f2`
DM_DN=`$GREP rootUserDN  $PROPS_FILE | $CUT -d= -f2-`
BASE_DN=`$GREP orgName $PROPS_FILE | $CUT -d= -f2-`
ADMIN_CONNECTOR_PORT=`$GREP adminConnectorPort $PROPS_FILE | $CUT -d= -f2`
REPLICATION_PORT=`$GREP replicationPort $PROPS_FILE | $CUT -d= -f2`
REPLICATION_ADMIN_UID=`$GREP replicationAdminUid $PROPS_FILE | $CUT -d= -f2`


# settings in global.properties
# NOTE: This is hardcoded in TORInst inventory.functions.lib and used by both SSO and LDAP.
COM_INF_LDAP_PORT=`$GREP COM_INF_LDAP_PORT $GLOBAL_PROPERTY_FILE | $CUT -d "=" -f2 | awk '{print $1;}'`

# rename settings in global.properties
# NOTE: BASE_DN needs to be dc=<something>,dc=com for now
BASE_DN=$COM_INF_LDAP_ROOT_SUFFIX
CONTAINER_BASE=`echo $BASE_DN | cut -f1 -d, | cut -f2 -d=`
SSO_USER=$COM_INF_LDAP_ADMIN_ACCESS
SSO_USER_DN=$COM_INF_LDAP_ADMIN_CN

DM_PWD=""

LOCAL_LDAP_HOST="opendjhost0"
REMOTE_LDAP_HOST="opendjhost1"
DB1_HOSTNAME=`cat /etc/hosts | grep db-1 | awk '{print $1}'`
DB2_HOSTNAME=`cat /etc/hosts | grep db-2 | awk '{print $1}'`

# two aliases for the same opendj instance on db-1 on cloud environment
CLOUD_LOCAL_LDAP_HOST="ldap-local"
CLOUD_REMOTE_LDAP_HOST="ldap-remote"

# two aliases for ENM On Cloud
ENM_CLOUD_1="opendj-1"
ENM_CLOUD_2="opendj-2"

# this part calculates hosts aliases. it is replicated in other scripts
DB_HOSTNAME=`$HOST_NAME -i`
IsOnCloud
if [ $? == 0 ] ; then
   #This fragment is used for ENM On Cloud
   LOCAL_LDAP_HOST=$ENM_CLOUD_1
   REMOTE_LDAP_HOST=$ENM_CLOUD_2
else
   IsSingleOpendj
   if [ $? == 0 ] ; then
      LDAP_HOST=$CLOUD_LOCAL_LDAP_HOST
   else
      echo $DB_HOSTNAME | $GREP $(getent hosts $LOCAL_LDAP_HOST | cut -d' ' -f1) > /dev/null
      if [ $? != 0 ] ; then
         LDAP_HOST=$REMOTE_LDAP_HOST
      else
         LDAP_HOST=$LOCAL_LDAP_HOST
      fi
   fi
fi

CURL=/usr/bin/curl
OPENDJ_PASSKEY=/ericsson/tor/data/idenmgmt/opendj_passkey
ROOTCA_CERT=/ericsson/tor/data/certificates/rootCA.pem


lockfile=/ericsson/tor/data/replock.lock
################################################################################
# Function: checkLockFile
# Description: check if we could be able to write on lock file
# Parameters: it uses the MANUAL_MODE variable
# Return: 0 (success: lock acquired)
#         1 (success: lock already taken)
#         2 (success: no check)
#         9 (fail: no able to write the file)         
################################################################################
LOCK_ACQUIRED=0
LOCK_OTHER=1
LOCK_NOCHECK=2
LOCK_FAIL=9
function checkLockFile(){
    LogMessageDotEcho "INFO: checkLockFile"

    if [ $MANUAL_MODE == true ]
    then
       LogMessageDotEcho "INFO: checkLockFile no check "
       return $LOCK_NOCHECK
    else
       if ( set -o noclobber; echo "locked" > "$lockfile") 2> /dev/null; then
            #write correctly
            LogMessageDotEcho "INFO: checkLockFile lock ok "
            return $LOCK_ACQUIRED
       else
           if [ -f $lockfile ]; then
              #file exist: written by someone else
              LogMessageDotEcho "INFO: checkLockFile lock already exist"
              return $LOCK_OTHER
           else
              #generic error
              LogMessageDotEcho "INFO: checkLockFile no able to write "
              return $LOCK_FAIL
           fi
       fi
    fi
 }

function rmLockfile(){

    if [ $MANUAL_MODE != true ]
    then
       LogMessageDotEcho "INFO: remove lock file "
       $RM -f $lockfile
    fi
}


################################################################################
# Function: checkOpenDJHostsInterfaces
# Description: This function checks the opendjhost0 and opendjhost1 OpenDJ hosts
#              interfaces and verifies the existence and reponsiveness of these 
#              interfaces.This check gives an extra assurance prior to enabling 
#              the OpenDJ replication functionality in subsequent phases.
# Parameters: none
# Return: 0 (Succeed)
#         1 (Failed)
################################################################################
function checkOpenDJHostsInterfaces(){
    LogMessageDotEcho "INFO: checkOpenDJHostsInterfaces request is received...... Processing request"
    

    # pinging the local and remote OpenDJ interfaces and collecting the return code for each ping
    
    $PING -c 1 $LOCAL_LDAP_HOST >>$LOG_FILE  2>&1
    localLdapPing=${PIPESTATUS[0]}
    $PING -c 1 $REMOTE_LDAP_HOST >>$LOG_FILE  2>&1
    remoteLdapPing=${PIPESTATUS[0]}
    LogMessageDotEcho "INFO: The $LOCAL_LDAP_HOST host ping exit status is: $localLdapPing." 
    LogMessageDotEcho "INFO: The $REMOTE_LDAP_HOST host ping exit status is: $remoteLdapPing"

    # setting the max attempting time interval to 120 sec
    now_ts=$(date +%s)
    later_ts=$((now_ts + 120))

    # loop if one or both interface are not pingable for a max of 120 sec
    until [[ $localLdapPing -eq 0 && $remoteLdapPing -eq 0 ]]; do
       if [ $(date +%s) -gt $later_ts ]; then
          LogMessageDotEcho "ERROR: One or more of the ldap interfaces could not be pinged successfully after 120 seconds."
          return 1
       fi
       sleep 5
       $PING -c 1 $LOCAL_LDAP_HOST >>$LOG_FILE  2>&1
       localLdapPing=${PIPESTATUS[0]}
       $PING -c 1 $REMOTE_LDAP_HOST >>$LOG_FILE  2>&1
       remoteLdapPing=${PIPESTATUS[0]}
    
       LogMessageDotEcho "INFO: The $LOCAL_LDAP_HOST host ping exit status is: $localLdapPing." 
       LogMessageDotEcho "INFO: The $REMOTE_LDAP_HOST host ping exit status is: $remoteLdapPing"
    done

   LogMessageDotEcho "INFO: checkOpenDJHostsInterfaces completed successfully"
   return 0
}


#############################################################################################
# Function: checkOpenDJInstances
# Description: This function checks the local and remote OpenDJ instances
#              and verifies the existence and reponsiveness of these instances. 
#              This check gives an extra assurance prior to enabling the OpenDJ 
#              replication functionality in subsequent phases.
#              A max of 180 sec time is set to iteratively check and verify these instances
#              before giving up and returning an error.
# Parameters: none
# Return: 0 (Succeed)
#         1 (Failed)
#############################################################################################
function checkOpenDJInstances(){
    LogMessageDotEcho "INFO: checkOpenDJInstances request is received...... Processing request"


    # checking the local and remote OpenDJ instances and collecting the return code for each check

    $CURL --cacert ${ROOTCA_CERT} ldaps://$LOCAL_LDAP_HOST:${COM_INF_LDAP_PORT}/${COM_INF_LDAP_ROOT_SUFFIX} 1>>$LOG_FILE  2>&1
    localLdapRet=${PIPESTATUS[0]}

    $CURL --cacert ${ROOTCA_CERT} ldaps://$REMOTE_LDAP_HOST:${COM_INF_LDAP_PORT}/${COM_INF_LDAP_ROOT_SUFFIX} 1>>$LOG_FILE  2>&1
    remoteLdapRet=${PIPESTATUS[0]}
    LogMessageDotEcho "INFO: The $LOCAL_LDAP_HOST ldap instance check exit status is: $localLdapRet."
    LogMessageDotEcho "INFO: The $REMOTE_LDAP_HOST ldap instance check exit status is: $remoteLdapRet"

    # setting the max attempting time interval to 180 sec
    now_ts=$(date +%s)
    later_ts=$((now_ts + 180))

    # loop if one or both instances could not be verified a max of 180 sec
    until [[ $localLdapRet -eq 0 && $remoteLdapRet -eq 0 ]]; do
       if [ $(date +%s) -gt $later_ts ]; then
          LogMessageDotEcho "ERROR: One or more of the ldap instances has failed the check after 180 seconds."
          return 1
       fi
       sleep 30
       $CURL --cacert ${ROOTCA_CERT} ldaps://$LOCAL_LDAP_HOST:${COM_INF_LDAP_PORT}/${COM_INF_LDAP_ROOT_SUFFIX} 1>>$LOG_FILE  2>&1
       localLdapRet=${PIPESTATUS[0]}

       $CURL --cacert ${ROOTCA_CERT} ldaps://$REMOTE_LDAP_HOST:${COM_INF_LDAP_PORT}/${COM_INF_LDAP_ROOT_SUFFIX} 1>>$LOG_FILE  2>&1
       remoteLdapRet=${PIPESTATUS[0]}

       LogMessageDotEcho "INFO: The $LOCAL_LDAP_HOST ldap instance check exit status is: $localLdapRet."
       LogMessageDotEcho "INFO: The $REMOTE_LDAP_HOST ldap instance check exit status is: $remoteLdapRet"
    done

   LogMessageDotEcho "INFO: checkOpenDJInstances completed successfully"
   return 0
}

################################################################################
# Function: enableOpendjReplication
# Description: Enable opendj replication. After calling this function, opendj
#              replication functionality is enabled. However, for replication
#              to work,  the contents of the base DNs should be initialized
# Parameters: none
# Return: 0 (Succeed)
#         1 (Failed)
################################################################################
function enableOpendjReplication(){
    LogMessageDotEcho "INFO: enableOpendjReplication request is received...... Processing request"


   $DSREPLICATION configure --host1 $LOCAL_LDAP_HOST \
                          --port1 $ADMIN_CONNECTOR_PORT \
                          --bindDN1 "$DM_DN" \
                          --bindPassword1 "$DM_PWD" \
                          --replicationPort1 $REPLICATION_PORT  \
                          --secureReplication1 \
                          --host2 $REMOTE_LDAP_HOST \
                          --port2 $ADMIN_CONNECTOR_PORT \
                          --bindDN2 "$DM_DN" \
                          --bindPassword2 "$DM_PWD" \
                          --replicationPort2 $REPLICATION_PORT \
                          --secureReplication2 \
                          --adminUID $REPLICATION_ADMIN_UID \
                          --adminPassword "$DM_PWD" \
                          --baseDN "$BASE_DN" -X -n >>$LOG_FILE  2>&1
    rr=${PIPESTATUS[0]}
    if [ $rr != 0 ]
    then
        LogMessageDotEcho "ERROR: Failed to enable Opendj replication and the error code from DS is [$rr]"
        return 1
    fi

    LogMessageDotEcho "INFO: enableOpendjReplication completed successfully"
    return 0
}


################################################################################
# Function: initializeOpendjReplication
# Description: Initialize opendj replication. After calling this function, user 
#              data in both sides are replicas
# Parameters: none
# Return: 0 (Succeed)
#         1 (Failed)
################################################################################
function initializeOpendjReplication (){
    LogMessageDotEcho "INFO: initializeOpendjReplication request is received ...... Processing request"
    # inilize replication
    $DSREPLICATION initialize --baseDN "$BASE_DN" \
                              --adminUID $REPLICATION_ADMIN_UID \
                              --adminPassword "$DM_PWD" \
                              --hostSource $LOCAL_LDAP_HOST \
                              --portSource $ADMIN_CONNECTOR_PORT \
                              --hostDestination $REMOTE_LDAP_HOST \
                              --portDestination $ADMIN_CONNECTOR_PORT -X -n >>$LOG_FILE  2>&1

    rr=${PIPESTATUS[0]}
    if [ $rr != 0 ]
    then
        LogMessageDotEcho "ERROR: Failed to initialize Opendj replication and the error code from DS is [$rr]"
        return 1
    fi
    
    LogMessageDotEcho "INFO: initializeOpendjReplication completed successfully"
    return 0
}



###############################################################################
# Function: checkDbInstance
# Description: checks env type. Replicated also in disable_replication
#              
# Parameters: none
# Return: 0 (ok: on physical)
#         2 (one db environment)
###############################################################################
checkDbInstance(){
# had to be modified to avoid overwriting the right variables value on cloud
IsSingleOpendj
if [ $? == 0 ] ; then
   REMOTE_LDAP_HOST=$CLOUD_REMOTE_LDAP_HOST
   LOCAL_LDAP_HOST=$CLOUD_LOCAL_LDAP_HOST
   LogMessageDotEcho "INFO: one db node env"
   return 2
fi

return 0
}


########################################################
# Function: Reconfigure OpenDJ Replication for 3pp upversioning
# Arguments: None
# Returns:
#   0      Success
#   1      Failure
########################################################
ReconfigureOpendj()
{
   LogMessageDotEcho "INFO: Starting OpenDJ reconfiguration, processing request......"
   if [ "$LDAP_HOST" != "$CLOUD_LOCAL_LDAP_HOST" ]; then
      SOURCE_ADDR_PROP=`$DSCONFIG get-replication-server-prop -h $DB_HOSTNAME -p $ADMIN_CONNECTOR_PORT -D "$DM_DN" -w "$DM_PWD" --trustAll --provider-name "Multimaster Synchronization" --property source-address -E | awk '{print $3}' | sed '3!d'`
      if [ "$SOURCE_ADDR_PROP" != "$LDAP_HOST" ]; then
         if [ "$DB_HOSTNAME" == "$DB2_HOSTNAME" ]; then
               if [ "$LDAP_HOST" == "$REMOTE_LDAP_HOST" ]; then
                    $DSCONFIG -h $DB1_HOSTNAME -p $ADMIN_CONNECTOR_PORT -D "$DM_DN" -w "$DM_PWD" --trustAll -n set-replication-server-prop --provider-name "Multimaster Synchronization" --set source-address:"$LOCAL_LDAP_HOST"
                    $DSCONFIG -h $DB2_HOSTNAME -p $ADMIN_CONNECTOR_PORT -D "$DM_DN" -w "$DM_PWD" --trustAll -n set-replication-server-prop --provider-name "Multimaster Synchronization" --set source-address:"$REMOTE_LDAP_HOST"
                    LogMessageDotEcho "INFO: Source address on $DB1_HOSTNAME set to $LOCAL_LDAP_HOST, on $DB2_HOSTNAME to $REMOTE_LDAP_HOST"
               elif [ "$LDAP_HOST" == "$LOCAL_LDAP_HOST" ]; then
                    $DSCONFIG -h $DB1_HOSTNAME -p $ADMIN_CONNECTOR_PORT -D "$DM_DN" -w "$DM_PWD" --trustAll -n set-replication-server-prop --provider-name "Multimaster Synchronization" --set source-address:"$REMOTE_LDAP_HOST"
                    $DSCONFIG -h $DB2_HOSTNAME -p $ADMIN_CONNECTOR_PORT -D "$DM_DN" -w "$DM_PWD" --trustAll -n set-replication-server-prop --provider-name "Multimaster Synchronization" --set source-address:"$LOCAL_LDAP_HOST"
                    LogMessageDotEcho "INFO: Source address on $DB1_HOSTNAME set to $REMOTE_LDAP_HOST, on $DB2_HOSTNAME to $LOCAL_LDAP_HOST"
               fi
         elif [ "$DB_HOSTNAME" == "$DB1_HOSTNAME" ]; then
                if [ "$LDAP_HOST" == "$LOCAL_LDAP_HOST" ]; then
                    $DSCONFIG -h $DB1_HOSTNAME -p $ADMIN_CONNECTOR_PORT -D "$DM_DN" -w "$DM_PWD" --trustAll -n set-replication-server-prop --provider-name "Multimaster Synchronization" --set source-address:"$LOCAL_LDAP_HOST"
                    $DSCONFIG -h $DB2_HOSTNAME -p $ADMIN_CONNECTOR_PORT -D "$DM_DN" -w "$DM_PWD" --trustAll -n set-replication-server-prop --provider-name "Multimaster Synchronization" --set source-address:"$REMOTE_LDAP_HOST"
                    LogMessageDotEcho "INFO: Source address on $DB1_HOSTNAME set to $LOCAL_LDAP_HOST, on $DB2_HOSTNAME to $REMOTE_LDAP_HOST"
                elif [ "$LDAP_HOST" == "$REMOTE_LDAP_HOST" ]; then
                    $DSCONFIG -h $DB1_HOSTNAME -p $ADMIN_CONNECTOR_PORT -D "$DM_DN" -w "$DM_PWD" --trustAll -n set-replication-server-prop --provider-name "Multimaster Synchronization" --set source-address:"$REMOTE_LDAP_HOST"
                    $DSCONFIG -h $DB2_HOSTNAME -p $ADMIN_CONNECTOR_PORT -D "$DM_DN" -w "$DM_PWD" --trustAll -n set-replication-server-prop --provider-name "Multimaster Synchronization" --set source-address:"$LOCAL_LDAP_HOST"
                    LogMessageDotEcho "INFO: Source address on $DB1_HOSTNAME set to $REMOTE_LDAP_HOST, on $DB2_HOSTNAME to $LOCAL_LDAP_HOST"
                fi
         fi
      else
         LogMessageDotEcho "INFO: source-address property already configured"
      fi
   else
      LogMessageDotEcho "INFO: Vapp install, no additional configuration required"
      return 0
   fi

   LogMessageDotEcho "INFO: ReconfigureOpendj completed"
   return 0
}

########################################################
# Function: Configure Multimaster Sync properties
# Arguments: None
# Returns:
#   0      Success
#   1      Failure
########################################################
ConfigureMultimasterProps()
{

   LogMessageDotEcho "INFO: Starting Multimaster Sync properties configuration, processing request......"

   $DSCONFIG -h $LOCAL_LDAP_HOST -p $ADMIN_CONNECTOR_PORT -D "$DM_DN" -w "$DM_PWD" --trustAll -n set-replication-server-prop --provider-name "Multimaster Synchronization" --set source-address:"$LOCAL_LDAP_HOST"

   $DSCONFIG -h $REMOTE_LDAP_HOST -p $ADMIN_CONNECTOR_PORT -D "$DM_DN" -w "$DM_PWD" --trustAll -n set-replication-server-prop --provider-name "Multimaster Synchronization" --set source-address:"$REMOTE_LDAP_HOST"

   #Reconfigure OpenDJ Disk Thresholds for Replication Server
   $DSCONFIG -h $LOCAL_LDAP_HOST -p $ADMIN_CONNECTOR_PORT -D "$DM_DN" -w "$DM_PWD" --trustAll -n set-replication-server-prop --provider-name "Multimaster Synchronization" --set "disk-low-threshold:200 MB" --set "disk-full-threshold:100 MB"

   $DSCONFIG -h $REMOTE_LDAP_HOST -p $ADMIN_CONNECTOR_PORT -D "$DM_DN" -w "$DM_PWD" --trustAll -n set-replication-server-prop --provider-name "Multimaster Synchronization" --set "disk-low-threshold:200 MB" --set "disk-full-threshold:100 MB"

    #Changelog-enabled option set to disabled
    $DSCONFIG set-replication-server-prop -h $LOCAL_LDAP_HOST -p $ADMIN_CONNECTOR_PORT -D "$DM_DN" -w "$DM_PWD" --trustAll -n --provider-name "Multimaster Synchronization" --set changelog-enabled:disabled --no-prompt

    $DSCONFIG set-replication-server-prop -h $REMOTE_LDAP_HOST -p $ADMIN_CONNECTOR_PORT -D "$DM_DN" -w "$DM_PWD" --trustAll -n --provider-name "Multimaster Synchronization" --set changelog-enabled:disabled --no-prompt

    # Set purge delay:
   if [ "${DDC_ON_CLOUD}" == TRUE ] || [ "${cENM_DEPLOYMENT}" == TRUE ] ; then
      LogMessage "INFO: Setting PurgeDelay for CLOUD : $REPLICATION_PURGE_DELAY_CLOUD"
      $DSCONFIG set-replication-server-prop -h localhost -p $ADMIN_CONNECTOR_PORT -D "$DM_DN" -w "$DM_PWD" --trustAll -n --provider-name "Multimaster Synchronization" --set replication-purge-delay:$REPLICATION_PURGE_DELAY_CLOUD --no-prompt
      $DSCONFIG set-replication-server-prop -h localhost -p $ADMIN_CONNECTOR_PORT -D "$DM_DN" -w "$DM_PWD" --trustAll -n --provider-name "Multimaster Synchronization" --set replication-purge-delay:$REPLICATION_PURGE_DELAY_CLOUD --no-prompt
   else
      LogMessage "INFO: Setting PurgeDelay for pENM : $REPLICATION_PURGE_DELAY_pENM"
      $DSCONFIG set-replication-server-prop -h localhost -p $ADMIN_CONNECTOR_PORT -D "$DM_DN" -w "$DM_PWD" --trustAll -n --provider-name "Multimaster Synchronization" --set replication-purge-delay:$REPLICATION_PURGE_DELAY_pENM --no-prompt
      $DSCONFIG set-replication-server-prop -h localhost -p $ADMIN_CONNECTOR_PORT -D "$DM_DN" -w "$DM_PWD" --trustAll -n --provider-name "Multimaster Synchronization" --set replication-purge-delay:$REPLICATION_PURGE_DELAY_pENM --no-prompt
   fi

   LogMessageDotEcho "INFO: ConfigureMultimasterProps completed"
   return 0
}

###############################################################################
# Main Program
# Parameters: None
###############################################################################

SetLogFile $LOG_DIR $LOG_FILE
if [ $? != 0 ]; then
    echo "ERROR: SetLogFile failed"
    error "SetLogFile failed"
    exit 1
fi

checkLockFile
checkRes=$?
if [ $checkRes == $LOCK_ACQUIRED ] || [ $checkRes == $LOCK_NOCHECK ]; then

    LogMessageNewLine "INFO: Opendj replication Configuration started..."
    info "Opendj replication Configuration started..."

    IsOnCloud
    if [ $? == 0 ] ; then
      #Comment next two lines to avoid the dependency with lock file for create backup
      #LogMessage "INFO: Copy admin-backend-ldif file to recover the status if Replication will not finish with success"
      #/bin/cp $OPENDJ_ROOT/db/admin-backend.ldif   $OPENDJ_ROOT/admin-backend.ldif_saved 
      LogMessageDotEcho "INFO: mkdir replication setup is in progress"
      info "mkdir replication setup is in progress"
      mkdir $OPENDJ_ROOT/replication_in_progress
    fi

#  in common.sh
#              it needs the following variables:
#                OPENDJ_PASSKEY
#                LDAP_ADMIN_PASSWORD (in GLOBAL.PROPERTIES)
#                GLOBAL_PROPERTY_FILE
#                DM_PWD (exported)
#
    decryptOpendjPasswd
    if [ $? != 0 ]; then
        LogMessageNewLine "ERROR: decryptOpendjPasswd failed"
        error "decryptOpendjPasswd failed"
        rmLockfile
        exit 1
    fi


    if [ $MANUAL_MODE == true ]
    then
       LogMessageDotEcho "INFO: enable backend "
       $DSCONFIG set-backend-prop --backend-name userRoot --set enabled:true -h $LOCAL_LDAP_HOST -p $ADMIN_CONNECTOR_PORT --trustAll --bindDN "cn=Directory Manager" -w "$DM_PWD" -n
       if [ $? != 0 ]; then
          LogMessageNewLine "ERROR: enable backend failed"
          error "enable backend failed"
          exit 1
       fi
       LogMessageDotEcho "INFO: enable backend ok"
    fi


# in common.sh
#              it needs the following variables:
#                DSSTATUS
#                DM_DN
#                DM_PWD
#                GREP
#
    checkReplicationStatus
    rc=$?
    if [ $rc != 0 ]; then
       if [ $rc == 2 ]; then

          ConfigureMultimasterProps
          rmLockfile
          IsOnCloud
          if [ $? == 0 ] ; then
              LogMessageNewLine "INFO: remove the directory replication_in_progress: replication setup is finished with success"
              info "Remove the directory replication_in_progress: replication setup is finished with success"
              $RM -Rf  $OPENDJ_ROOT/replication_in_progress
          else
              LogMessageNewLine "INFO: Opendj replication has already been configured: END"
              info "Opendj replication has already been configured: END"
          fi
          exit 0
       else
          LogMessageNewLine "ERROR: checkReplicationStatus failed"
          error "checkReplicationStatus failed"
          rmLockfile
          exit 1
       fi
    fi

    checkDbInstance
    env=$?

    checkOpenDJHostsInterfaces
    if [ $? != 0 ]; then
        LogMessageNewLine "ERROR: checkOpenDJHostsInterfaces failed"
        error "checkOpenDJHostsInterfaces failed"
        rmLockfile
        exit 1
    fi

    checkOpenDJInstances
    if [ $? != 0 ]; then
        LogMessageNewLine "ERROR: checkOpenDJInstances failed"
        error "checkOpenDJInstances failed"
        rmLockfile
        exit 1
    fi

    enableOpendjReplication
    if [ $? != 0 ] && [ $env != 2 ]; then
        LogMessageNewLine "ERROR: enableOpendjReplication failed"
        error "enableOpendjReplication failed"
        rmLockfile
        exit 1
    #with one opendj replication configuration is failing but enabling change logs needed for liveSync
    elif [  $env == 2 ];then
       rmLockfile
       IsOnCloud
       if [ $? == 0 ] ; then
           LogMessageNewLine "INFO: remove the directory replication_in_progress: replication setup is finished with success"
           info "Remove the directory replication_in_progress: replication setup is finished with success"
           $RM -Rf  $OPENDJ_ROOT/replication_in_progress
       fi
       exit 0
    fi

    initializeOpendjReplication
    if [ $? != 0 ]; then
        LogMessageNewLine " ERROR: initializeOpendjReplication failed"
        error " initializeOpendjReplication failed"
        rmLockfile
        exit 1
    fi

    #This parameter will probably have to be set up correctly. The existing script can be simplified, I think, to sth similar as below, to work on physial as well.
    #ReconfigureOpendj
    #if [ $? != 0 ] ; then
    #    LogMessageDotEcho "ERROR: ReconfigureOpendj failed."
    #fi

    ConfigureMultimasterProps

    IsOnCloud
    if [ $? == 0 ] ; then
      LogMessageDotEcho "INFO: remove the directory replication_in_progress: replication setup is finished with success"
      info "remove the directory replication_in_progress: replication setup is finished with success"
      $RM -Rf  $OPENDJ_ROOT/replication_in_progress
    fi


    LogMessageNewLine "INFO: config_opendj_replication.sh completed successfully."
    info "config_opendj_replication.sh completed successfully."
    rmLockfile

else

  if [ $checkRes == $LOCK_OTHER ]; then
     LogMessageNewLine "INFO: replication is configured from the second instance..."
     info "Replication is configured from the second instance..."
  else
     LogMessageNewLine "ERROR: config_opendj_replication.sh failed to acquire LOCK"
     info "ERROR: config_opendj_replication.sh failed to acquire LOCK"
     exit 1
  fi

fi

exit 0
