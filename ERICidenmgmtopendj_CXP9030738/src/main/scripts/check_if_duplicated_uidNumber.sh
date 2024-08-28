#!/bin/bash

IDENMGMT_ROOT=/opt/ericsson/com.ericsson.oss.security/idenmgmt
PROPS_FILE=$IDENMGMT_ROOT/config/datastore.properties
DM_DN=`grep -w rootUserDN  $PROPS_FILE | cut -d= -f2-`
SSOLDAP_PASSKEY=/ericsson/tor/data/idenmgmt/ssoldap_passkey
OPENDJ_PASSKEY=/ericsson/tor/data/idenmgmt/opendj_passkey
OPENSSL=/usr/bin/openssl
LDAPSEARCH=/opt/opendj/bin/ldapsearch
DM_PWD=""
OUTPUT_FILE="/var/log/opendj/duplicatedUidNumber.log"
GLOBAL_PROPERTY_FILE=/ericsson/tor/data/global.properties

###########################################################################################
# Function: ReadGlobalProperty
# Description: This function reads global.properties file for required properties
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################
ReadGlobalProperty(){
# Need to wait until file is available

echo  "Checking for ${GLOBAL_PROPERTY_FILE}..."
sec=0
while true; do
  if [ ! -f ${GLOBAL_PROPERTY_FILE} ]; then
    echo "{${GLOBAL_PROPERTY_FILE} not present, waiting 10s"
    if [ $sec -gt 500 ]; then
      echo "ERROR: ${GLOBAL_PROPERTY_FILE} did not appear. Waiting time finished"
      exit 1
    fi
    sleep 10
    sec=$((sec+10));
  else
    echo "${GLOBAL_PROPERTY_FILE} exists, continuing with script execution"
    break
  fi
done

eval $(grep "LDAP_ADMIN_PASSWORD" ${GLOBAL_PROPERTY_FILE})
eval $(grep "COM_INF_LDAP_ADMIN_ACCESS" ${GLOBAL_PROPERTY_FILE})
eval $(grep "COM_INF_LDAP_ROOT_SUFFIX" ${GLOBAL_PROPERTY_FILE})
eval $(grep "COM_INF_LDAP_PORT" ${GLOBAL_PROPERTY_FILE})

# rename settings in global.properties
# NOTE: BASE_DN needs to be dc=<something>,dc=com for now
BASE_DN=$COM_INF_LDAP_ROOT_SUFFIX
}


###########################################################################################
# Function: GetPassword
# Description: This function updates the Directory Manager and SSO user passwords
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################
GetPassword()
{
  echo "UpdatePasswords request has been received. Processing request..."

  if [[ -z "${COM_INF_LDAP_ADMIN_ACCESS}" || -z "${LDAP_ADMIN_PASSWORD}" ]]; then
    echo "ERROR: COM_INF_LDAP_ADMIN_ACCESS or LDAP_ADMIN_PASSWORD is not set in ${GLOBAL_PROPERTY_FILE}"
    return 1
  fi

  if [ -r ${SSOLDAP_PASSKEY} ]; then
    SSO_USER_PWD=`echo ${COM_INF_LDAP_ADMIN_ACCESS} | ${OPENSSL} enc -a -d -md md5 -aes-128-cbc -salt -kfile ${SSOLDAP_PASSKEY}`
    if [ -z "${SSO_USER_PWD}" ]; then
      echo "ERROR: Failed to decrypt COM_INF_LDAP_ADMIN_ACCESS from ${GLOBAL_PROPERTY_FILE}"
      return 1
    fi
  else
    echo "INFO: ${SSOLDAP_PASSKEY} does not exist or is not readable"
    return 1
  fi

  if [ -r ${OPENDJ_PASSKEY} ]; then
    DM_PWD=`echo ${LDAP_ADMIN_PASSWORD} | ${OPENSSL} enc -a -d -md md5 -aes-128-cbc -salt -kfile ${OPENDJ_PASSKEY}`
    if [ -z "${DM_PWD}" ]; then
      echo "ERROR: Failed to decrypt LDAP_ADMIN_PASSWORD from ${GLOBAL_PROPERTY_FILE}"
      return 1
    fi
  else
    echo "INFO: ${OPENDJ_PASSKEY} does not exist or is not readable"
    return 1
  fi

  echo "UpdatePasswords completed successfully"
  return 0
}

###########################################################################################
# Function: CheckUID
# Description: Checks if duplicated uidNumber exist in LDAP
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################
CheckUID(){
  echo "Checking LDAP for duplicated uidNumber"
  DUPLICATED_UIDS=`$LDAPSEARCH -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" -b "ou=people,$BASE_DN" objectClass=posixAccount uidNumber | grep uidNumber | sed -e "s/uidNumber: //g" | sort | uniq -d`
  if [ -a $OUTPUT_FILE ]; then
    echo "">> $OUTPUT_FILE
  fi
  echo "Executed at: "`date` | tee -a $OUTPUT_FILE
  for UID_NO in $DUPLICATED_UIDS; do
    echo "##########" | tee -a $OUTPUT_FILE
    echo "Duplicated uidNumber: $UID_NO for users: " | tee -a $OUTPUT_FILE
    $LDAPSEARCH -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" -b "ou=people,$BASE_DN" uidNumber=$UID_NO cn | grep "cn: " | tee -a $OUTPUT_FILE
    echo "##########" | tee -a $OUTPUT_FILE
  done
  echo "Output saved to $OUTPUT_FILE"
}

########
# MAIN #
########

ReadGlobalProperty
GetPassword
CheckUID
