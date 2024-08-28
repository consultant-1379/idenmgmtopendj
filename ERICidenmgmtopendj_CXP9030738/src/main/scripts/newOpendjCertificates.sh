#!/bin/bash

#############################################
# THIS SCRIPT IS VALID ONLY on pENM or vENM #
#############################################

CAT=/bin/cat
CP=/bin/cp
RM='/bin/rm -f'
CHOWN=/bin/chown
HOST_NAME=/usr/bin/hostname

#RootCA used to sign ############################
SHARE_ROOT=/ericsson/tor/data
ROOTCA_DIR="${SHARE_ROOT}/certificates"
ROOTCA_FILE=$ROOTCA_DIR/rootCA.pem
ROOTCA_KEY_FILE=$ROOTCA_DIR/rootCA.key
#################################################


OPENDJ_ROOT=/ericsson/opendj/opendj
if [ "$cENM_DEPLOYMENT" != TRUE ]
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
LOG_FILE="$LOG_DIR/newOpendjCertificates-$(/bin/date "+%F:%H:%M:%S%:z").log"
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
###########################################################################

#Certificate tools and data ##########################################
OPENSSL=/usr/bin/openssl
JAVA_KEYTOOL=/usr/java/default/bin/keytool
KEYSTORE_NAME=${OPENDJ_ROOT}/config/keystore
KEY_VALIDITY_PERIOD=7300

#update certificates
KEYSTORE_NAME_SAV=${OPENDJ_ROOT}/config/keystore.sav
KEYSTORE_NAME_OLD=${OPENDJ_ROOT}/config/keystore.old
#####################################################################


setEnvironment() {
OPENDJHOST0="opendjhost0"
OPENDJHOST1="opendjhost1"
LDAP_LOCAL="ldap-local"


if [ "$cENM_DEPLOYMENT" != TRUE ]
then # pENM and vENM #######################################
   GLOBAL_PROPERTY_FILE=/ericsson/tor/data/global.properties
   if [ ! -r "$GLOBAL_PROPERTY_FILE" ]; then
       LogMessage "ERROR: Cannot read $GLOBAL_PROPERTY_FILE"
       error "Cannot read $GLOBAL_PROPERTY_FILE"
       return 1
   fi
   . $GLOBAL_PROPERTY_FILE >/dev/null 2>&1
   # deployment paths

   IsOnCloud
   if [ $? == 0 ]
   then # vENM ###############################
      ENMTYPE=vENM
      LDAP_HOST=$SERVICE_INSTANCE_NAME
      OPENDJHOST0="opendj-1"
      OPENDJHOST1="opendj-2"
   fi  # END vENM ###############################

   if [ `cat /etc/hosts | egrep cloud-db |wc -l` != 0 ]
   then  # vapp pENM ##########################

      LDAP_HOST=$LDAP_LOCAL
      OPENDJHOST0=$LDAP_LOCAL

   else  # pENM #############################

      $HOST_NAME -I | $GREP_W $(getent hosts $OPENDJHOST0 | cut -d' ' -f1)
      if [ $? != 0 ] ; then
         LDAP_HOST=$OPENDJHOST1
      else
         LDAP_HOST=$OPENDJHOST0
      fi
    fi  # END vapp pENM ##########################

else  # cENM ################################

   SIDE=$(hostname | grep 1 | wc -l)
   if [ $SIDE == 0 ];then
      LOCAL_LDAP_HOST=$DS_SVC"-0".$DS_SVC
   else
      LOCAL_LDAP_HOST=$DS_SVC"-1".$DS_SVC
   fi
   LDAP_HOST=$LOCAL_LDAP_HOST

   OPENDJHOST0=$DS_SVC"-0".$DS_SVC
   OPENDJHOST1=$DS_SVC"-1".$DS_SVC

fi  # END cENM ################################
}


###############################################################################################
# Function: ConfigNewOpendjCertificate
# Description: This function remove the rootCA and the old opendj certificate from a duplicate
#              of keystore (keystore.sav) then create a new opendj certificate signed by the
#              new rootCA.
#              Finally, put the new certificate and the new rootCA inside the keystore.sav and
#              switch the new keystore.sav with the keystore.
# Parameters: None
# Return:  0 everything ok, 1 fail
###############################################################################################

CreateNewOpendjCertificate()
{
  LogMessage "INFO: CreateNewOpendjCertificate request has been received. Processing request....."

  # back up the old keystore
  ${CP} $KEYSTORE_NAME $KEYSTORE_NAME_SAV
  if [ $? != 0 ] ; then
    LogMessage "ERROR: Failed to save a copy of Opendj's keystore"
    return 1
  fi

  # All the following step are performed using a copy (KEYSTORE_NAME_SAV) of the original keystore

  KEYSTORE_PWD=$( $CAT $OPENDJ_ROOT/config/keystore.pin )
  #remove the old rootCA from opendj's keystore
  $JAVA_KEYTOOL -delete -alias rootCA -keystore $KEYSTORE_NAME_SAV -storepass $KEYSTORE_PWD 2>&1 | tee -a "${LOG_FILE}"
  if [ $? != 0 ] ; then
    LogMessage "ERROR: Failed to delete the old Root CA from Opendj's keystore"
    ${RM} $KEYSTORE_NAME_SAV
    return 1
  fi

  #delete the self-signed certificates from opendj keystore
  $JAVA_KEYTOOL -delete -alias ssl-key-pair -keystore $KEYSTORE_NAME_SAV -storepass "$KEYSTORE_PWD" 2>&1 | tee -a "${LOG_FILE}"
  if [ $? != 0 ] ; then
    LogMessage "ERROR: Failed to delete Opendj's self-signed certificate: ssl-key-pair from the keystorestore"
    ${RM} $KEYSTORE_NAME_SAV
    return 1
  fi

  #import the rootCA into opendj's keystore
  $JAVA_KEYTOOL -import -no-prompt -trustcacerts -alias rootCA -keystore $KEYSTORE_NAME_SAV -storepass "$KEYSTORE_PWD" -file $ROOTCA_FILE 2>/dev/null | tee -a "${LOG_FILE}"
  if [ $? != 0 ] ; then
    LogMessage "ERROR: Failed to import the Root CA into Opendj's keystore"
    ${RM} $KEYSTORE_NAME_SAV
    return 1
  fi

  #Create, sign and export Opendj certificates
  #Generate a key
  $JAVA_KEYTOOL -genkey -alias ssl-key-pair -validity $KEY_VALIDITY_PERIOD -keyalg "RSA" -keysize 2048 -dname "CN=${LDAP_HOST}" -keystore $KEYSTORE_NAME_SAV -keypass "$KEYSTORE_PWD" -storepass "$KEYSTORE_PWD" 2>&1 | tee -a "${LOG_FILE}"
  if [ $? != 0 ] ; then
     LogMessage "ERROR: Failed to generate Opendj keypair "
     ${RM} $KEYSTORE_NAME_SAV
     return 1
  fi

  # Create a CSR with the key
  $JAVA_KEYTOOL -certreq -v -alias ssl-key-pair -keystore $KEYSTORE_NAME_SAV -storepass "$KEYSTORE_PWD" -file "${IDENMGMT_ROOT}/opendj/config/${LDAP_HOST}-ldap-cer.csr" 2>/dev/null | >>$LOG_FILE
  if [ $? != 0 ] ; then
    LogMessage "ERROR: Failed to create a CSR for Opendj's certificate "
    ${RM} $KEYSTORE_NAME_SAV
    return 1
  fi

  # Sig the CSR using the Root CA
  $OPENSSL x509 -req -in ${IDENMGMT_ROOT}/opendj/config/${LDAP_HOST}-ldap-cer.csr -CA ${ROOTCA_FILE} -CAkey ${ROOTCA_KEY_FILE} -CAcreateserial -out ${IDENMGMT_ROOT}/opendj/config/${LDAP_HOST}-ldap-cer.pem -days $KEY_VALIDITY_PERIOD -extfile ${IDENMGMT_ROOT}/opendj/config/opendj-ssl-ext-ca.cnf -extensions usr_cert 2>/dev/null >>$LOG_FILE
  if [ $? != 0 ] ; then
    LogMessage "ERROR: Failed to sign a CSR for Opendj"
    ${RM} $KEYSTORE_NAME_SAV
    return 1
  fi

  #import opendj's certificate into the keystore
  $JAVA_KEYTOOL -import -no-prompt -trustcacerts -alias ssl-key-pair -keystore $KEYSTORE_NAME_SAV -storepass "$KEYSTORE_PWD" -file ${IDENMGMT_ROOT}/opendj/config/${LDAP_HOST}-ldap-cer.pem 2>/dev/null | tee -a "${LOG_FILE}"
  if [ $? != 0 ] ; then
    LogMessage "ERROR: Failed to import Opendj's certificate into the keystore"
    ${RM} $KEYSTORE_NAME_SAV
    return 1
  fi

  # remove csr
  ${RM} ${IDENMGMT_ROOT}/opendj/config/${LDAP_HOST}-ldap-cer.csr
  ${CP} $KEYSTORE_NAME $KEYSTORE_NAME_OLD
  ${CP} $KEYSTORE_NAME_SAV $KEYSTORE_NAME
  ${RM} ${KEYSTORE_NAME_SAV}

  $CHOWN -R opendj:opendj $OPENDJ_ROOT
  if [ $? != 0 ] ; then
    LogMessage "ERROR: Failed to chown directory $OPENDJ_ROOT"
    return 1
  fi
  LogMessage "INFO: CreateNewOpendjCertificate completed successfully!"
  return 0
}

########
# MAIN #
########

setEnvironment
CreateNewOpendjCertificate
if [ $? != 0 ] ; then
    LogMessage "ERROR: CreateNewOpendjCertificate failed"
    exit 1
else
    exit 0
fi
