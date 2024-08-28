#!/bin/bash

OPENSSL=/usr/bin/openssl

########## SET ENVIRONMENT ###########
HOST_NAME=/bin/hostname
DB_HOSTNAME=`$HOST_NAME -i`

# two aliases for pENM
ENM_0="opendjhost0"
ENM_1="opendjhost1"

# two aliases for vENM
ENM_CLOUD_1="opendj-1"
ENM_CLOUD_2="opendj-2"

# Variable to enable
# the check of the peer status
SINGLE=0

# Check the environment type

if [ -z ${DS_SVC+x} ];
then
   # pENM and vENM
   SHARE_ROOT=/ericsson/tor/data
   GLOBAL_PROPERTY_FILE=/ericsson/tor/data/global.properties
   . $GLOBAL_PROPERTY_FILE >/dev/null 2>&1
   if [ $? -ne 0 ]; then
      echo "ERROR: Failed to source ${SHARE_ROOT}/global.properties"
      exit 1
   fi
   # deployment paths
   IDENMGMT_ROOT=/opt/ericsson/com.ericsson.oss.security/idenmgmt
   source $IDENMGMT_ROOT/opendj/bin/common.sh
   if [ $? -ne 0 ]; then
      echo "ERROR: Failed to source $IDENMGMT_ROOT/opendj/bin/common.sh"
      exit 1
   fi

   IsOnCloud
   if [ $? == 0 ] ; then
      # vENM
      OPENDJ_SCRIPT_ROOT=/ericsson/opendj/opendj
      OPENDJ_ROOT=/ericsson/opendj/opendj
      LOCAL_LDAP_HOST=$ENM_CLOUD_1
      REMOTE_LDAP_HOST=$ENM_CLOUD_2
      ENMTYPE=vENM
   else
      # pENM
      OPENDJ_SCRIPT_ROOT=/ericsson/opendj/opendj
      OPENDJ_ROOT=/opt/opendj
      LOCAL_LDAP_HOST=$ENM_0
      REMOTE_LDAP_HOST=$ENM_1
      ENMTYPE=pENM
   fi

   IsSingleOpendj
   if [ $? == 0 ] ; then
      SINGLE=1
   else # search peer alias
      IPLIST=$(hostname -I)
      IP_VALUE=$(getent hosts $LOCAL_LDAP_HOST | awk '{print $1}')
      RES=$(echo $IPLIST | grep $IP_VALUE | wc -l)
      if [[ $RES -eq 0 ]]; then
         DESTINATIONDB=$LOCAL_LDAP_HOST
      else
         DESTINATIONDB=$REMOTE_LDAP_HOST
      fi
   fi
else
   # cENM
   OPENDJ_SCRIPT_ROOT=/ericsson/opendj/opendj
   OPENDJ_ROOT=/ericsson/opendj/opendj
   if [ $REPLICA_NUMBER == 1 ]; then
      SINGLE=1
   else  # search peer alias
      SIDE=$(hostname | grep 1 | wc -l)
      if [ $SIDE == 0 ];then
         DESTINATIONDB=$DS_SVC"-1".$DS_SVC
      else
         DESTINATIONDB=$DS_SVC"-0".$DS_SVC
      fi
   fi
   ENMTYPE=cENM
fi
###########################################################

## TEST TO WAIT THE AVAILABILITY OF THE PEER ##
if [ $SINGLE == 0 ]; then
   echo "Q" | $OPENSSL s_client -connect $DESTINATIONDB:1636 >/dev/null 2>&1
   while [ ${PIPESTATUS[1]} != 0 ]; do
      echo -n " $DESTINATIONDB not ready" $'\r'
      sleep 2
      echo -n " Please wait                              " $'\r'
      sleep 2
      echo "Q" | $OPENSSL s_client -connect $DESTINATIONDB:1636 >/dev/null 2>&1
   done
   echo -n "                                             " $'\r'
fi
##############################################

echo "Starting renew ..."
dir=$PWD
cd $OPENDJ_SCRIPT_ROOT/bin

./newRootCA.sh
if [ $? != 0 ]; then
      echo "Failed to renew CA cert"
      cd $dir
      exit 1
fi
./newOpendjCertificates.sh
if [ $? != 0 ]; then
      echo "Failed to renew opendj cert"
      cd $dir
      exit 1
fi

echo "All renew completed successfully!"
cd $dir
exit 0
