#!/bin/bash 

SHARE_ROOT=/ericsson/tor/data
OPENSSL=/usr/bin/openssl
CUT=/bin/cut
GREP=/bin/grep
TMP_FOLDER=/tmp
AC_HOME_DIR=/opt/ericsson/com.ericsson.oss.security/idenmgmt

SETUP_PROPS_FILE=$AC_HOME_DIR/config/datastore.properties

GLOBAL_PROPERTY_FILE=${SHARE_ROOT}/global.properties
. $GLOBAL_PROPERTY_FILE >/dev/null 2>&1

if [[ "${DDC_ON_CLOUD}" == TRUE ]]; then
        OPENDJ_ROOT=/ericsson/opendj/opendj
else
        OPENDJ_ROOT=/opt/opendj
fi

OPENDJ_PASSKEY=${SHARE_ROOT}/idenmgmt/opendj_passkey
LDAPMODIFY=$OPENDJ_ROOT/bin/ldapmodify


DM_PWD=`echo ${LDAP_ADMIN_PASSWORD} | ${OPENSSL} enc -a -d -md md5 -aes-128-cbc -salt -kfile ${OPENDJ_PASSKEY}`
COM_INF_LDAP_PORT=`$GREP COM_INF_LDAP_PORT $GLOBAL_PROPERTY_FILE | $CUT -d "=" -f2 | awk '{print $1;}'`
DM_DN=`$GREP rootUserDN  $SETUP_PROPS_FILE | $CUT -d "=" -f 2-`

case "${1}" in


enable)

  $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt << EOT
dn: $COM_INF_LDAP_ADMIN_CN
changetype: modify
add: ds-privilege-name
ds-privilege-name: unindexed-search
EOT

rr=${PIPESTATUS[0]}
  if [ $rr = 0 ] ; then
       echo "INFO: Schema is up-to-date now: ds-privilege-name set to unindexed-search for ssouser"
  else
      if [ $rr = 20 ] ; then
          echo "INFO: Schema is already up-to-date now:  ds-privilege-name already set to unindexed-search for ssouser"
      else 
          echo "ERROR: Failed to update Opendj custom schema"
          exit 1
      fi
  fi

   exit 0

  ;;
disable)


  $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt << EOT
dn: $COM_INF_LDAP_ADMIN_CN
changetype: modify
delete: ds-privilege-name
EOT
 
 
rr=${PIPESTATUS[0]}
  if [ $rr = 0 ] ; then
       echo "INFO: Schema is up-to-date now: ds-privilege-name unindexed-search removed from ssouser"
  else
      if [ $rr = 16 ] ; then
          echo "INFO: Schema is already up-to-date now: attribute ds-privilege-name unindexed-search doesn't exist"
      else 
          echo "ERROR: Failed to update Opendj custom schema"
          exit 1
      fi
  fi

   exit 0

  ;;

*)
  echo "Usage:  $0 { enable | disable }"
    exit 1
      ;;
      esac

