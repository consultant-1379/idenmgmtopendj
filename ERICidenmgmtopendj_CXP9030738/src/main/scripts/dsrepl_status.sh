#!/bin/bash

################################################################################
# Copyright (c) 2023 Ericsson, Inc. All Rights Reserved.
# This script display LDAP replication status
################################################################################

# Manual procedure for recovery replication in DS 7.x

# Source variables file to get value for SERVICE_INSTANCE_NAME
if [ -f /opt/ericsson/com.ericsson.oss.security/idenmgmt/opendj/variables ]; then
    . /opt/ericsson/com.ericsson.oss.security/idenmgmt/opendj/variables
fi

IDENMGMT_ROOT=/opt/ericsson/com.ericsson.oss.security/idenmgmt
NEW_OPENDJ_VERSION=`cat $IDENMGMT_ROOT/opendj/config/version`
OPENDJ_PASSKEY=/ericsson/tor/data/idenmgmt/opendj_passkey
ROOTCA_CERT=/ericsson/tor/data/certificates/rootCA.pem

CURL=/usr/bin/curl
GREP='/bin/grep -w'
CUT=/bin/cut
PING=/bin/ping
OPENSSL=/usr/bin/openssl
HOST_NAME=/bin/hostname

LOG_DIR="/var/log/opendj"
LOG_FILE="$LOG_DIR/opendj-replication-status-`/bin/date "+%F:%H:%M:%S%:z"`.log"

source $IDENMGMT_ROOT/opendj/bin/common.sh
if [ $? -ne 0 ]; then
   echo "ERROR: Failed to source $IDENMGMT_ROOT/opendj/bin/common.sh"
   exit 1
fi

DM_PWD=""


################################################################################
# Function: getENMsets
# Description: This function get the infos about the ENM environment like side
# Parameters: none
# Return: 0 (Succeed)
#         1 (Failed)
################################################################################

getENMsets(){

OPENDJHOST0="opendjhost0"
OPENDJHOST1="opendjhost1"
LDAP_LOCAL="ldap-local"
LDAP_PEER="ldap-remote"

LogMessageDotEcho "INFO: getENMsets start"

if [ "$cENM_DEPLOYMENT" != TRUE ] ; then
   # pENM and vENM
   # global properties that are either required by SSO or defined in the SED.
   # we need the global.properties file
   GLOBAL_PROPERTY_FILE=/ericsson/tor/data/global.properties
   if [ ! -r "$GLOBAL_PROPERTY_FILE" ]; then
       LogMessage "ERROR: Cannot read $GLOBAL_PROPERTY_FILE"
       error "Cannot read $GLOBAL_PROPERTY_FILE"
       return 1
   fi
   . $GLOBAL_PROPERTY_FILE >/dev/null 2>&1

   IsOnCloud
   if [ $? == 0 ] ; then
      # vENM
      LogMessage "getENMsets vENM:"
      OPENDJ_ROOT=/ericsson/opendj/opendj
      OPENDJ_ROOT_PARENT=/ericsson/opendj
      LDAP_HOST=$SERVICE_INSTANCE_NAME
      if [ $LDAP_HOST == "opendj-1" ]; then
         LDAP_PEER="opendj-2"
      else
         LDAP_PEER="opendj-1"
      fi
      LOCAL_LDAP_HOST=$LDAP_HOST
      REMOTE_LDAP_HOST=$LDAP_PEER
      OPENDJHOST0="opendj-1"
      OPENDJHOST1="opendj-2"
   elif [ `cat /etc/hosts | egrep cloud-db |wc -l` != 0 ]; then
      #vapp
      ENMTYPE=pENM
      OPENDJ_ROOT=/opt/opendj
      OPENDJ_ROOT_PARENT=/opt/
      LDAP_HOST=$LDAP_LOCAL
      OPENDJHOST0=$LDAP_LOCAL
      OPENDJHOST1=$LDAP_PEER
   else
      # pENM

      OPENDJ_ROOT=/opt/opendj
      OPENDJ_ROOT_PARENT=/opt/

      $HOST_NAME -I | $GREP $(getent hosts $OPENDJHOST0 | cut -d' ' -f1)
      if [ $? != 0 ] ; then
         LDAP_HOST=$OPENDJHOST1
         LDAP_PEER=$OPENDJHOST0
         LOCAL_LDAP_HOST=$OPENDJHOST1
         REMOTE_LDAP_HOST=$OPENDJHOST0
      else
         LDAP_HOST=$OPENDJHOST0
         LDAP_PEER=$OPENDJHOST1
         LOCAL_LDAP_HOST=$OPENDJHOST0
         REMOTE_LDAP_HOST=$OPENDJHOST1
      fi
   fi
else
   # cENM
   OPENDJ_ROOT=/ericsson/opendj/opendj
   OPENDJ_ROOT_PARENT=/ericsson/opendj
   SIDE=$(hostname | grep 1 | wc -l)
   if [ $SIDE == 0 ];then
      LOCAL_LDAP_HOST=$DS_SVC"-0".$DS_SVC
      REMOTE_LDAP_HOST=$DS_SVC"-1".$DS_SVC
   else
      LOCAL_LDAP_HOST=$DS_SVC"-1".$DS_SVC
      REMOTE_LDAP_HOST=$DS_SVC"-0".$DS_SVC
   fi
   LDAP_HOST=$LOCAL_LDAP_HOST
   LDAP_PEER=$REMOTE_LDAP_HOST

   OPENDJHOST0=$DS_SVC"-0".$DS_SVC
   OPENDJHOST1=$DS_SVC"-1".$DS_SVC

fi

# OpenDJ tools
LDAPSEARCH=$OPENDJ_ROOT/bin/ldapsearch
DSCONFIG=$OPENDJ_ROOT/bin/dsconfig
DSREPLICATION=$OPENDJ_ROOT/bin/dsrepl
# Directory manager, basedn and ports
# from datastore.properties
PROPS_FILE=$IDENMGMT_ROOT/config/datastore.properties
LDAP_PORT=`$GREP ldapsPort $PROPS_FILE | cut -d= -f2`
DM_DN=`$GREP rootUserDN  $PROPS_FILE | cut -d= -f2-`
ADMIN_CONNECTOR_PORT=`$GREP adminConnectorPort $PROPS_FILE | cut -d= -f2`
BASE_DN=$COM_INF_LDAP_ROOT_SUFFIX

LogMessageDotEcho "INFO: getENMsets finished"

return 0

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

    $CURL -k --cacert ${ROOTCA_CERT} ldaps://$LOCAL_LDAP_HOST:${COM_INF_LDAP_PORT}/${COM_INF_LDAP_ROOT_SUFFIX} 1>>$LOG_FILE  2>&1
    localLdapRet=${PIPESTATUS[0]}

    $CURL -k --cacert ${ROOTCA_CERT} ldaps://$REMOTE_LDAP_HOST:${COM_INF_LDAP_PORT}/${COM_INF_LDAP_ROOT_SUFFIX} 1>>$LOG_FILE  2>&1
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
       $CURL -k --cacert ${ROOTCA_CERT} ldaps://$LOCAL_LDAP_HOST:${COM_INF_LDAP_PORT}/${COM_INF_LDAP_ROOT_SUFFIX} 1>>$LOG_FILE  2>&1
       localLdapRet=${PIPESTATUS[0]}

       $CURL -k --cacert ${ROOTCA_CERT} ldaps://$REMOTE_LDAP_HOST:${COM_INF_LDAP_PORT}/${COM_INF_LDAP_ROOT_SUFFIX} 1>>$LOG_FILE  2>&1
       remoteLdapRet=${PIPESTATUS[0]}

       LogMessageDotEcho "INFO: The $LOCAL_LDAP_HOST ldap instance check exit status is: $localLdapRet."
       LogMessageDotEcho "INFO: The $REMOTE_LDAP_HOST ldap instance check exit status is: $remoteLdapRet"
    done

   LogMessageDotEcho "INFO: checkOpenDJInstances completed successfully"
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

LogMessageNewLine "INFO: Opendj replication status ..."
info "Opendj replication status ..."

getENMsets
if [ $? != 0 ]; then
    echo "ERROR: getENMsets failed"
    error "getENMsets failed"
    exit 1
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
    exit 1
fi

SOURCEDB=$REMOTE_LDAP_HOST
DESTINATIONDB=$LOCAL_LDAP_HOST

LOCAL_SERVERID=$($LDAPSEARCH -h $LOCAL_LDAP_HOST -p $ADMIN_CONNECTOR_PORT -X -Z -D "$DM_DN" -w "$DM_PWD" -b "cn=config" objectClass=* | grep ds-cfg-server-id | awk  '{ print $2 }')
rr=${PIPESTATUS[0]}
if [ $rr != 0 ]; then
   LogMessageDotEcho "ERROR: Failed to retrieve serverid from local opendj ($LOCAL_LDAP_HOST) with code from DS is [$rr]"
   LogMessage "ERROR: Failed to retrieve serverid from local opendj ($LOCAL_LDAP_HOST) with code from DS is [$rr]"
else
   LogMessageDotEcho "Local opendj ($LOCAL_LDAP_HOST) has serverid $LOCAL_SERVERID"
   LogMessage "Local opendj ($LOCAL_LDAP_HOST) has serverid $LOCAL_SERVERID"
fi

REMOTE_SERVERID=$($LDAPSEARCH -h $REMOTE_LDAP_HOST -p $ADMIN_CONNECTOR_PORT -X -Z -D "$DM_DN" -w "$DM_PWD" -b "cn=config" objectClass=* | grep ds-cfg-server-id | awk  '{ print $2 }')
rr=${PIPESTATUS[0]}
if [ $rr != 0 ]; then
   LogMessageDotEcho "ERROR: Failed to retrieve serverid from peer opendj ($REMOTE_LDAP_HOST) with code from DS is [$rr]"
   LogMessage "ERROR: Failed to retrieve serverid from peer opendj ($REMOTE_LDAP_HOST) with code from DS is [$rr]"
else
   LogMessageDotEcho "Peer opendj ($REMOTE_LDAP_HOST) has serverid $REMOTE_SERVERID"
   LogMessage "Peer opendj ($REMOTE_LDAP_HOST) has serverid $REMOTE_SERVERID"
fi

SERVERID_LIST=($LOCAL_SERVERID $REMOTE_SERVERID)

BASEDNGOOD=$($DSREPLICATION status -h localhost -p 4444 -D "cn=directory manager" -w "$DM_PWD" -X -b "$BASE_DN" --showReplicas 2>/dev/null | grep -i GOOD | wc -l)
if [ $BASEDNGOOD -ne 2 ]; then
  BADBASEDN=($($DSREPLICATION status -h localhost -p 4444 -D "cn=directory manager" -w "$DM_PWD" -X -b "$BASE_DN" --showReplicas 2>/dev/null | grep -v GOOD | awk -F" " '{print $2}' | grep DS ))
fi

for i in "${!BADBASEDN[@]}"
do
   TMP=$(echo "${BADBASEDN[$i]}" | cut -d"/" -f2);
   for k in "${!SERVERID_LIST[@]}"
   do
      if [ $TMP == "${SERVERID_LIST[$k]}" ]; then
         if [ $k == 0 ]; then
            LogMessageDotEcho "Local opendj ($LOCAL_LDAP_HOST, serverid $LOCAL_SERVERID) has a BAD in replication for basedn $BASE_DN"
            LogMessage "Local opendj ($LOCAL_LDAP_HOST, serverid $LOCAL_SERVERID) has a BAD in replication for basedn $BASE_DN"
         else
            LogMessageDotEcho "Peer opendj ($REMOTE_LDAP_HOST, serverid) $REMOTE_SERVERID) has a BAD in replication for basedn $BASE_DN"
            LogMessage "Peer opendj ($REMOTE_LDAP_HOST, serverid $REMOTE_SERVERID) has a BAD in replication for basedn $BASE_DN"
         fi
      fi
   done
done


SCHEMAGOOD=$($DSREPLICATION status -h localhost -p 4444 -D "cn=directory manager" -w "$DM_PWD" -X -b "cn=schema" --showReplicas 2>/dev/null | grep -i GOOD | wc -l)
if [ $SCHEMAGOOD -ne 2 ]; then
  BADSCHEMA=($($DSREPLICATION status -h localhost -p 4444 -D "cn=directory manager" -w "$DM_PWD" -X -b "cn=schema" --showReplicas 2>/dev/null | grep -v GOOD | awk -F" " '{print $2}' | grep DS ))
fi

for i in "${!BADSCHEMA[@]}"
do
   TMP=$(echo "${BADSCHEMA[$i]}" | cut -d"/" -f2);
   for k in "${!SERVERID_LIST[@]}"
   do
      if [ $TMP == "${SERVERID_LIST[$k]}" ]; then
         if [ $k == 0 ]; then
            LogMessageDotEcho "Local opendj ($LOCAL_LDAP_HOST, serverid $LOCAL_SERVERID) has a BAD in replication for basedn cn=schema"
            LogMessage "Local opendj ($LOCAL_LDAP_HOST, serverid $LOCAL_SERVERID) has a BAD in replication for basedn cn=schema"
         else
            LogMessageDotEcho "Peer opendj ($REMOTE_LDAP_HOST, serverid $REMOTE_SERVERID) has a BAD in replication for basedn cn=schema"
            LogMessage "Peer opendj ($REMOTE_LDAP_HOST, serverid $REMOTE_SERVERID) has a BAD in replication for basedn cn=schema"
         fi
      fi
   done
done

checkDbInstance
#env=$?

checkOpenDJHostsInterfaces
if [ $? != 0 ]; then
    LogMessageNewLine "ERROR: checkOpenDJHostsInterfaces failed"
    error "checkOpenDJHostsInterfaces failed"
    exit 1
fi

checkOpenDJInstances
if [ $? != 0 ]; then
    LogMessageNewLine "ERROR: checkOpenDJInstances failed"
    error "checkOpenDJInstances failed"
    exit 1
fi

## Inserire una get del proprio host e set delle variabili

LogMessageNewLine "INFO: replication status completed"
info "Opendj replication status completed"

exit 0
