#!/bin/bash

IDENMGMT_ROOT=/opt/ericsson/com.ericsson.oss.security/idenmgmt
PROPS_FILE=$IDENMGMT_ROOT/config/datastore.properties
DM_DN=`grep -w rootUserDN  $PROPS_FILE | cut -d= -f2-`
SSOLDAP_PASSKEY=/ericsson/tor/data/idenmgmt/ssoldap_passkey
OPENDJ_PASSKEY=/ericsson/tor/data/idenmgmt/opendj_passkey
OPENSSL=/usr/bin/openssl
LDAPSEARCH=/opt/opendj/bin/ldapsearch
DM_PWD=""
OUTPUT_FILE="/var/log/opendj/ldapUsersWithWrongUidNumber.log"
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
    echo "${GLOBAL_PROPERTY_FILE} not present, waiting 10s"
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
# Description: This function retrieves the Directory Manager and SSO user passwords
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################
GetPassword()
{
  echo "GetPassword request has been received. Processing request..."

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

  echo "GetPasswords completed successfully"
  return 0
}

###########################################################################################
# Function: CompareUID
# Description: Compares user uid from DB with uidNumber in LDAP, saves inconsistent results in output file
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################
CompareUID(){
  echo "Checking POSIX users in LDAP"
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

  echo "Checking POSIX users in DB"
  DB_USERNAMES=`ls -n /home/shared/ | awk '{print $9}'`
  DB_UIDS=`ls -n /home/shared/ | awk '{print $3}'`
  DB_USERNAMES_ARRAY=($DB_USERNAMES)
  DB_UIDS_ARRAY=($DB_UIDS)

  declare -A DB_MAP
  for DB_INDEX in ${!DB_USERNAMES_ARRAY[@]}; do
    DB_USERNAME=${DB_USERNAMES_ARRAY[$DB_INDEX]}
    DB_UID=${DB_UIDS_ARRAY[$DB_INDEX]}
    DB_MAP[$DB_USERNAME]=$DB_UID
  done

  if [ -a $OUTPUT_FILE ]; then
    echo ""> $OUTPUT_FILE
  fi
  echo "Executed at: "`date` | tee -a $OUTPUT_FILE

  for USERNAME in "${!DB_MAP[@]}"; do
    echo "Checking user: $USERNAME"
    if [ "${DB_MAP[$USERNAME]}" != 0 ] && [ "${DB_MAP[$USERNAME]}" != "${LDAP_MAP[$USERNAME]}" ]; then
        echo "##########" | tee -a $OUTPUT_FILE
        echo "Inconsistent uid for user: $USERNAME" | tee -a $OUTPUT_FILE
        echo "UID in unix: ${DB_MAP[$USERNAME]}, uidNumber in LDAP: ${LDAP_MAP[$USERNAME]}" | tee -a $OUTPUT_FILE
        echo "##########" | tee -a $OUTPUT_FILE
    fi
  done
  echo "Output saved to $OUTPUT_FILE"
}

###########################################################################################
# Function: RecalculatePosixUsers
# Description: Selects from PostgreSQL users that are POSIX users and do not have FIELD_TECHNICIAN role assigned.
# Then if these users are missing home folders recalculates posix attributes on them.
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################
RecalculatePosixUsers(){

SQL_USERNAMES=`PGPASSWORD=idenmgmt123 /opt/rh/postgresql92/root/usr/bin/psql -U idenmgmt -h postgresql01 -c "select name from postgre_user where id in (select  postgre_user_id from posix_user_ext where postgre_user_id not in (select postgre_user_id from postgre_user_role_target_group where role_id in (select id from role where name='FIELD_TECHNICIAN')));" | tail -n +3 | head -n -2`

match=false;
SQL_USERS=""
for SQL_USERNAME in $SQL_USERNAMES; do
  for DB_USERNAME in $DB_USERNAMES; do
    if [ $DB_USERNAME == $SQL_USERNAME ]; then
      match=true
      break
    fi
  done
  if [ $match == false ]; then
    SQL_USERS="$SQL_USERS$SQL_USERNAME|"
  fi
  match=false;
done
SQL_USERS="'${SQL_USERS:0:${#SQL_USERS}-1}'"
echo "Recalculate user POSIX attributes for user: $SQL_USERS"
PGPASSWORD=idenmgmt123 /opt/rh/postgresql92/root/usr/bin/psql -U idenmgmt -h postgresql01 -c 'select recalculateusersposix('$SQL_USERS');'
}

########
# MAIN #
########

ReadGlobalProperty
GetPassword
CompareUID


RecalculatePosixUsers
