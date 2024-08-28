#!/bin/bash

CP=/bin/cp
RM='/bin/rm -f'
OPENSSL=/usr/bin/openssl

# rootCA.pem path #####################################
SHARE_ROOT=/ericsson/tor/data
ROOTCA_DIR="${SHARE_ROOT}/certificates"
ROOTCA_FILE=$ROOTCA_DIR/rootCA.pem
ROOTCA_KEY_FILE=$ROOTCA_DIR/rootCA.key

OPENDJ_ROOT=/ericsson/opendj/opendj
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
   #pENM Only
   if [[ "${DDC_ON_CLOUD}" != TRUE ]]; then
      OPENDJ_ROOT=/opt/opendj
   fi
fi

# LogMessage #############################################################
LOG_DIR=$OPENDJ_ROOT/logs
LOG_FILE="$LOG_DIR/newRootCA-$(/bin/date "+%F:%H:%M:%S%:z").log"
IDENMGMT_ROOT=/opt/ericsson/com.ericsson.oss.security/idenmgmt
## !! common.sh has a dependence from GLOBAL_PROPERTY_FILE !!
source $IDENMGMT_ROOT/opendj/bin/common.sh >/dev/null 2>&1
if [ $? -ne 0 ]; then
   echo "ERROR: Failed to source $IDENMGMT_ROOT/opendj/bin/common.sh"
   exit 1
fi

SetLogFile $LOG_DIR $LOG_FILE
if [ $? != 0 ]; then
   echo "ERROR: SetLogFile failed"
   exit 1
fi
##########################################################################

NEW_ROOTCA_FILE=${OPENDJ_ROOT}/config/rootCA.pem
CA_SUBJ="/O=Ericsson/OU=OSS/CN=IDM"
CA_KEY_VALIDITY_PERIOD=9125
#######################################################

##################################################################################
# Function: RootCaGTxHours
# Description: This function return 0 if rootCA.pem was less then x hours
# Parameters: x number of hours
# Return:  1 if rootCA is older then x ; 0 otherwise; 2 if fails
##################################################################################

RootCaGTxHours()
{
#  LogMessage "INFO: RootCaGTxHours request has been received. Processing request....."

  if [ ! -f ${ROOTCA_FILE} ]; then
    LogMessage "ERROR: File ${ROOTCA_FILE} not found"
    return 2
  fi

  ROOTCADAY=$(date --date="$(openssl x509 -in ${ROOTCA_FILE} -noout -startdate | cut -d= -f 2)"  +"%Y-%m-%dT%H:%M:%SZ")
  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ]; then
    LogMessage "ERROR: Failed to read the start date of the self-signed certificate"
    return 2
  fi

  TODAY=$(date  +"%Y-%m-%dT%H:%M:%SZ")

  DDHOURS=$(echo "$((($(date -d "$TODAY" '+%s') - $(date -d "$ROOTCADAY" '+%s'))/60/60))")

  if [ "$DDHOURS" -gt $1 ]; then
    return 1
  else
    return 0
  fi
}


##################################################################################
# Function: CreateNewRootCACertificate
# Description: This function create a new rootCA.pem and export it to sfs
# Parameters: None
# Return:  0 everything ok, 1 fail
# Note: this function must be called ones before the instance of the two opendj
##################################################################################

CreateNewRootCACertificate()
{
  LogMessage "INFO: CreateNewRootCACertificate request has been received. Processing request....."

  $OPENSSL req -new -key ${ROOTCA_KEY_FILE} -x509 -subj $CA_SUBJ -days $CA_KEY_VALIDITY_PERIOD -out $NEW_ROOTCA_FILE 2>&1 | tee -a "${LOG_FILE}"
  if [ $? != 0 ] ; then
    LogMessage "ERROR: Failed to create the new self-signed certificate"
    return 1
  fi
  ${CP} $NEW_ROOTCA_FILE $ROOTCA_FILE
  if [ $? != 0 ] ; then
    LogMessage "ERROR: Failed to copy the new certificate on sfs"
    return 1
  fi
  ${RM} $NEW_ROOTCA_FILE
  LogMessage "INFO: CreateNewRootCACertificate completed successfully!"

  return 0
}

########
# MAIN #
########

RootCaGTxHours 24
ret=$?
if [ $ret == 1 ] ; then

  CreateNewRootCACertificate
  if [ $? != 0 ] ; then
      LogMessage "ERROR: CreateNewRootCACertificate failed"
      exit 1
  else
      exit 0
  fi

elif [ $ret == 0 ] ; then
  LogMessage "INFO: The ${ROOTCA_FILE} certificate already renew, nothing to be done"
  exit 0
else
  exit 1
fi
