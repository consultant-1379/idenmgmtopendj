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

#LOG_DIR="/var/log/opendj"
#LOG_FILE="$LOG_DIR/opendj-replication-status-`/bin/date "+%F:%H:%M:%S%:z"`.log"

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

if [ "$cENM_DEPLOYMENT" != TRUE ] ; then
   # pENM and vENM
   # global properties that are either required by SSO or defined in the SED.
   # we need the global.properties file
   GLOBAL_PROPERTY_FILE=/ericsson/tor/data/global.properties
   if [ ! -r "$GLOBAL_PROPERTY_FILE" ]; then
       return 1
   fi
   . $GLOBAL_PROPERTY_FILE >/dev/null 2>&1

   IsOnCloud
   if [ $? == 0 ] ; then
      # vENM

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

return 0

}



###############################################################################
# Main Program
# Parameters: None
###############################################################################

getENMsets
if [ $? != 0 ]; then
    echo "ERROR: getENMsets failed"
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
    exit 1
fi

$OPENDJ_ROOT/bin/dsrepl status -h localhost -p 4444 -D "$DM_DN" -w $DM_PWD -X -b "$BASE_DN" --showReplicas

exit 0
