#!/bin/bash

#############################################
# THIS SCRIPT IS VALID ONLY on pENM or vENM #
#############################################


# DEFAULT opendj 7.3.0 cipher suites
ALLOWED_SUITES=(
"TLS_AES_128_GCM_SHA256"
"TLS_AES_256_GCM_SHA384"
"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"
"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
#START TEMPORARY TO WORK WITH ACCESS CONTROL
"TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"
#END TEMPORARY
"TLS_EMPTY_RENEGOTIATION_INFO_SCSV")

AWK=/bin/awk
CAT=/bin/cat
GREP='/bin/grep -w'
GREP_i='/bin/grep -i'
SED=/bin/sed

OPENSSL=/usr/bin/openssl
JAVA_KEYTOOL=/usr/java/default/bin/keytool
CUT=/bin/cut
HOST_NAME=/bin/hostname
RM=/bin/rm

DM_PWD=""

LDAP_LOCAL="ldap-local"

# global properties that are either required by SSO or defined in the SED.
GLOBAL_PROPERTY_FILE=/ericsson/tor/data/global.properties
. $GLOBAL_PROPERTY_FILE >/dev/null 2>&1
if [ $? -ne 0 ]; then
   echo "ERROR: Failed to source ${SHARE_ROOT}/global.properties"
   exit 1
fi

if [[ "${DDC_ON_CLOUD}" == TRUE ]]; then
      # vENM
      OPENDJ_ROOT=/ericsson/opendj/opendj
elif [ "$(grep -c "cloud-db" /etc/hosts)" != 0 ]; then
      # vApp
      OPENDJ_ROOT=/opt/opendj
else
      # pENM
      OPENDJ_ROOT=/opt/opendj
fi

# LogMessage #############################################################
fname=$(basename $0)
fbname=${fname%.*}
LOG_DIR=$OPENDJ_ROOT/logs
LOG_FILE="$LOG_DIR/$fbname-$(/bin/date "+%F:%H:%M:%S%:z").log"
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

echo "Procedure to remove TLSv1"
LogMessage "INFO: Procedure to remove TLSv1" 1> /dev/null


# get datastore.properties settings
PROPS_FILE=$IDENMGMT_ROOT/config/datastore.properties
# OPENDJ_PASSKEY is absolutally needed please don't remove
OPENDJ_PASSKEY=/ericsson/tor/data/idenmgmt/opendj_passkey
decryptOpendjPasswd 1>/dev/null
DM_DN=$($GREP rootUserDN  $PROPS_FILE | $CUT -d"=" -f2-)
ADMIN_CONNECTOR_PORT=`$GREP adminConnectorPort $PROPS_FILE | $CUT -d= -f2`
# OPENDJ bin tools
DSCONFIG=$OPENDJ_ROOT/bin/dsconfig
DSREPLICATION=$OPENDJ_ROOT/bin/dsreplication

###########################################################################################
# Function: EnableTls
# Description: This function enable TLS protocols
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################
EnableTls()
{
  LogMessage "EnableTls request has been received. Processing request..."

  LogMessage "INFO: Checking LDAPS connection handler presence"
rtMess="$($DSCONFIG get-connection-handler-prop --port $ADMIN_CONNECTOR_PORT \
 --hostname localhost \
 --bindDN "$DM_DN" \
 --bindPassword "$DM_PWD" \
 --handler-name LDAPS \
 --trustAll --no-prompt )"

if [[ $rtMess != *"Property"* ]]
then
  LogMessage "INFO: Creating LDAPS connection handler and enabling TLS protocols"
    rtMess="$($DSCONFIG create-connection-handler \
 --hostname localhost  \
 --port $ADMIN_CONNECTOR_PORT \
 --bindDN "$DM_DN" \
 --bindPassword "$DM_PWD" \
 --handler-name LDAPS \
 --type ldap \
 --set listen-port:$COM_INF_LDAP_PORT \
 --set key-manager-provider:"PKCS12" \
 --set trust-manager-provider:"PKCS12" \
 --set ssl-cert-nickname:ssl-key-pair \
 --set use-ssl:true \
 --set ssl-protocol:TLSv1.3 \
 --set ssl-protocol:TLSv1.2 \
 ${ALLOWED_SUITES[@]/#/--set ssl-cipher-suite:} \
 --set enabled:true  --trustAll --no-prompt)"

    if [ "$?" == "0" ]
    then
            LogMessage "INFO: LDAPS connection handler created successfully"
    else
        LogMessage "ERROR: LDAPS creation failed"
        error "LDAPS connector creation failed"
        return 1
    fi
else
  # install or upgrade
  LogMessage "INFO: Enabling TLS protocols for existing LDAPS connection handler"
  #Enable TLS protocols for existing LDAPS Connection Handler
  $DSCONFIG set-connection-handler-prop \
      --port $ADMIN_CONNECTOR_PORT \
      --hostname localhost \
      --bindDN "$DM_DN" \
      --bindPassword "$DM_PWD" \
      --handler-name LDAPS \
      --reset ssl-protocol \
      --set ssl-protocol:TLSv1.3 \
      --set ssl-protocol:TLSv1.2 \
      --reset ssl-cipher-suite \
      ${ALLOWED_SUITES[@]/#/--set ssl-cipher-suite:} \
      --trustAll --no-prompt | tee -a $LOG_FILE

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ]; then
     LogMessage "ERROR: Failed to enable TLS protocols for the LDPAS Connection Handler and the error code from DS is [$rr]"
     error "Failed to enable TLS protocols for the LDPAS Connection Handler and the error code from DS is [$rr]"
     return 1
  fi

  LogMessage "INFO: LDAPS connection handler updated successfully  "
fi

  # install or upgrade
  LogMessage "INFO: Enable TLS protocols for HTTP Connection Handler "
  $DSCONFIG set-connection-handler-prop \
      --port $ADMIN_CONNECTOR_PORT \
      --hostname localhost \
      --bindDN "$DM_DN" \
      --bindPassword "$DM_PWD" \
      --handler-name HTTP \
      --reset ssl-protocol \
      --set ssl-protocol:TLSv1.3 \
      --set ssl-protocol:TLSv1.2 \
      --reset ssl-cipher-suite \
      ${ALLOWED_SUITES[@]/#/--set ssl-cipher-suite:} \
      --trustAll --no-prompt | tee -a $LOG_FILE

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ]; then
     LogMessage "ERROR: Failed to enable TLS protocols for the HTTP Connection Handler and the error code from DS is [$rr]"
     error "Failed to enable TLS protocols for the HTTP Connection Handler and the error code from DS is [$rr]"
     return 1
  fi

  # removed crypto manager management
  # crypto manager has no more "ssl-protocol" and "allowed suites" properties

  LogMessage "INFO: Enable TLS protocols for the administration connection handler"
  $DSCONFIG set-administration-connector-prop \
      --port $ADMIN_CONNECTOR_PORT \
      --hostname localhost \
      --bindDN "$DM_DN" \
      --bindPassword "$DM_PWD" \
      --reset ssl-protocol \
      --set ssl-protocol:TLSv1.3 \
      --set ssl-protocol:TLSv1.2 \
      --reset ssl-cipher-suite \
      ${ALLOWED_SUITES[@]/#/--set ssl-cipher-suite:} \
      --trustAll --no-prompt | tee -a $LOG_FILE

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ]; then
     LogMessage "ERROR: Failed to enable TLS protocols for the Admin Connection Handler and the error code from DS is [$rr]"
     error "Failed to enable TLS protocols for the Admin Connection Handler and the error code from DS is [$rr]"
     return 1
  fi

  LogMessage "EnableTls completed successfully"
}

## MAIN
EnableTls

echo "The procedure to remove TLSv1 was completed successfully"
LogMessage "INFO: The procedure to remove TLSv1 was completed successfully" 1>/dev/null
