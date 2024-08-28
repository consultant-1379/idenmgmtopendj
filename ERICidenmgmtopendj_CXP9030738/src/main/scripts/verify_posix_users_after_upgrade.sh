#!/bin/bash

IDENMGMT_ROOT=/opt/ericsson/com.ericsson.oss.security/idenmgmt
PROPS_FILE=$IDENMGMT_ROOT/config/datastore.properties
DM_DN=`grep -w rootUserDN  $PROPS_FILE | cut -d= -f2-`
SSOLDAP_PASSKEY=/ericsson/tor/data/idenmgmt/ssoldap_passkey
OPENDJ_PASSKEY=/ericsson/tor/data/idenmgmt/opendj_passkey
OPENSSL=/usr/bin/openssl
LDAPSEARCH=/opt/opendj/bin/ldapsearch
DM_PWD=""
OUTPUT_FILE="/var/log/opendj/posixUsersMismatchAfterUpgrade.log"
GLOBAL_PROPERTY_FILE=/ericsson/tor/data/global.properties
USERS_FILE=/ericsson/tor/data/openidmlogs/users.log

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
# Function: VerifyPosixUsers
# Description: Checks if the list of users after upgrade is the same as before upgrade.
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################
VerifyPosixUsers()
{
  if [ ! -f $USERS_FILE ]; then
    echo "File $USERS_FILE does not exist."
    exit 1
  fi

  echo "Retrieving POSIX users from LDAP"
  LDAP_USERNAMES=`$LDAPSEARCH -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" -b "ou=people,$BASE_DN" objectClass=posixAccount uid | grep uid: | sed -e "s/uid: //g"`
  LDAP_UIDS=`$LDAPSEARCH -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" -b "ou=people,$BASE_DN" objectClass=posixAccount uidNumber | grep uidNumber: | sed -e "s/uidNumber: //g"`
  LDAP_USERNAMES_ARRAY=($LDAP_USERNAMES)
  LDAP_UIDS_ARRAY=($LDAP_UIDS)

  declare -A LDAP_MAP
  for LDAP_INDEX in ${!LDAP_USERNAMES_ARRAY[@]}; do
    LDAP_USERNAME=${LDAP_USERNAMES_ARRAY[$LDAP_INDEX]}
    LDAP_UID=${LDAP_UIDS_ARRAY[$LDAP_INDEX]}
    LDAP_MAP[$LDAP_USERNAME]=$LDAP_UID
  done

  echo "Retrieving POSIX users from PSQL"
  SQL_USERNAMES=`PGPASSWORD=idenmgmt123 /opt/rh/postgresql92/root/usr/bin/psql -U idenmgmt -h postgresql01 -c "select postgre_user.name, posix_user_ext.uid_number from postgre_user inner join posix_user_ext on postgre_user.id = posix_user_ext.postgre_user_id;" | tail -n +3 | head -n -2 | awk '{print $1}'`

  SQL_UIDS=`PGPASSWORD=idenmgmt123 /opt/rh/postgresql92/root/usr/bin/psql -U idenmgmt -h postgresql01 -c "select postgre_user.name, posix_user_ext.uid_number from postgre_user inner join posix_user_ext on postgre_user.id = posix_user_ext.postgre_user_id;" | tail -n +3 | head -n -2 | awk '{print $3}'`
  SQL_USERNAMES_ARRAY=($SQL_USERNAMES)
  SQL_UIDS_ARRAY=($SQL_UIDS)

  declare -A SQL_MAP
  for SQL_INDEX in ${!SQL_USERNAMES_ARRAY[@]}; do
    SQL_USERNAME=${SQL_USERNAMES_ARRAY[$SQL_INDEX]}
    SQL_UID=${SQL_UIDS_ARRAY[$SQL_INDEX]}
    SQL_MAP[$SQL_USERNAME]=$SQL_UID
  done

  echo "Retrieving POSIX users from LOG file"
  LOG_USERNAMES=`cat $USERS_FILE | awk '{print $1}'`
  LOG_UIDS=`cat $USERS_FILE | awk '{print $2}'`
  LOG_USERNAMES_ARRAY=($LOG_USERNAMES)
  LOG_UIDS_ARRAY=($LOG_UIDS)

  declare -A LOG_MAP
  for LOG_INDEX in ${!LOG_USERNAMES_ARRAY[@]}; do
    LOG_USERNAME=${LOG_USERNAMES_ARRAY[$LOG_INDEX]}
    LOG_UID=${LOG_UIDS_ARRAY[$LOG_INDEX]}
    LOG_MAP[$LOG_USERNAME]=$LOG_UID
  done

  if [ -a $OUTPUT_FILE ]; then
    echo ""> $OUTPUT_FILE
  fi
  echo "Executed at: "`date` | tee -a $OUTPUT_FILE

  for SQL_USERNAME in "${!SQL_MAP[@]}"; do
    for LOG_USERNAME in "${!LOG_MAP[@]}"; do
      if [ $SQL_USERNAME == $LOG_USERNAME ]; then
        if [ ${SQL_MAP[$SQL_USERNAME]} != ${LOG_MAP[$LOG_USERNAME]} ]; then
          echo "##########" | tee -a $OUTPUT_FILE
          echo "Existing user with inconsistent uid after upgrade: $SQL_USERNAME" | tee -a $OUTPUT_FILE
          echo "UID from PostgreSQL: ${SQL_MAP[$SQL_USERNAME]}, UID from LOG: ${LOG_MAP[$LOG_USERNAME]}" | tee -a $OUTPUT_FILE
          echo "##########" | tee -a $OUTPUT_FILE
        fi
        continue 2
      fi
    done
    echo "##########" | tee -a $OUTPUT_FILE
    echo "New user was created in PostgreSQL during upgrade: $SQL_USERNAME" | tee -a $OUTPUT_FILE
    echo "UID from PostgreSQL: ${SQL_MAP[$SQL_USERNAME]}" | tee -a $OUTPUT_FILE
    echo "##########" | tee -a $OUTPUT_FILE
  done

  for LDAP_USERNAME in "${!LDAP_MAP[@]}"; do
    for LOG_USERNAME in "${!LOG_MAP[@]}"; do
      if [ $LDAP_USERNAME == $LOG_USERNAME ]; then
        if [ ${LDAP_MAP[$LDAP_USERNAME]} != ${LOG_MAP[$LOG_USERNAME]} ]; then
	  echo "##########" | tee -a $OUTPUT_FILE
          echo "Existing user with inconsistent uid after upgrade: $LDAP_USERNAME" | tee -a $OUTPUT_FILE
          echo "UID from LDAP: ${LDAP_MAP[$LDAP_USERNAME]}, UID from LOG: ${LOG_MAP[$LOG_USERNAME]}" | tee -a $OUTPUT_FILE
          echo "##########" | tee -a $OUTPUT_FILE
        fi
        continue 2
      fi
    done
    echo "##########" | tee -a $OUTPUT_FILE
    echo "New user was created in LDAP during upgrade: $LDAP_USERNAME" | tee -a $OUTPUT_FILE
    echo "UID from LDAP: ${LDAP_MAP[$LDAP_USERNAME]}" | tee -a $OUTPUT_FILE
    echo "##########" | tee -a $OUTPUT_FILE
  done

  echo "Output saved to $OUTPUT_FILE"
}

########
# MAIN #
########

ReadGlobalProperty
GetPassword

VerifyPosixUsers
