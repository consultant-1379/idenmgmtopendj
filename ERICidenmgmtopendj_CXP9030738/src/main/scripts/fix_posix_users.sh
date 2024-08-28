#!/bin/bash

IDENMGMT_ROOT=/opt/ericsson/com.ericsson.oss.security/idenmgmt
PROPS_FILE=$IDENMGMT_ROOT/config/datastore.properties
DM_DN=`grep -w rootUserDN  $PROPS_FILE | cut -d= -f2-`
SSOLDAP_PASSKEY=/ericsson/tor/data/idenmgmt/ssoldap_passkey
OPENDJ_PASSKEY=/ericsson/tor/data/idenmgmt/opendj_passkey
OPENSSL=/usr/bin/openssl
DM_PWD=""

##########################################################################################
GLOBAL_PROPERTY_FILE=/ericsson/tor/data/global.properties

# Need to wait until file is available

info  "Checking for ${GLOBAL_PROPERTY_FILE}..."
sec=0
while true; do
  if [ ! -f ${GLOBAL_PROPERTY_FILE} ]; then
    info "{${GLOBAL_PROPERTY_FILE} not present, waiting 10s"
    if [ $sec -gt 500 ]; then
       info "ERROR: ${GLOBAL_PROPERTY_FILE} did not appeared. Waiting time finished"
           exit 1
    fi
    sleep 10
        sec=$((sec+10));
  else
    info "${GLOBAL_PROPERTY_FILE} exists, continuing with opendj configuration"
    break
  fi
done

. $GLOBAL_PROPERTY_FILE >/dev/null 2>&1

# rename settings in global.properties
# NOTE: BASE_DN needs to be dc=<something>,dc=com for now
BASE_DN=$COM_INF_LDAP_ROOT_SUFFIX
##########################################################################################


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


#################
# PART FOR AMOS #
#################
FixAmosUsers(){
    USERS_IN_AMOS_USERS=`/opt/opendj/bin/ldapsearch -p $COM_INF_LDAP_PORT --useSSL --trustAll --no-prompt -D "$DM_DN" -w "$DM_PWD" -b "ou=groups,$BASE_DN" cn=amos_users | grep uniqueMember | sed -e "s/uniqueMember: //"`
    echo "People in group amos_users:"
    echo $USERS_IN_AMOS_USERS

    USERS_NEEDED_AMOS=`/opt/opendj/bin/ldapsearch -p $COM_INF_LDAP_PORT --useSSL --trustAll --no-prompt -D "$DM_DN" -w "$DM_PWD" -b "ou=people,$BASE_DN" "(&(roleTG=*Amos_*)(!(roleTG=*FIELD_TECHNICIAN*)))" | grep dn | sed -e "s/dn: //"`
    echo "People that should have AMOS attributes:"
    echo $USERS_NEEDED_AMOS

    for USER in $USERS_NEEDED_AMOS
    do
      USER_ID=`echo $USER | sed -e "s/.*uid=//" | sed -e "s/,ou=.*//"`
      GROUP_ID=`/opt/opendj/bin/ldapsearch -p $COM_INF_LDAP_PORT --useSSL --trustAll --no-prompt -D "$DM_DN" -w "$DM_PWD" -b "ou=people,$BASE_DN" uid=$USER_ID gidNumber | grep gidNumber | sed -e "s/gidNumber: //"`
      if [[ $GROUP_ID = "2147483647" ]] ; then
        echo "Adding missing attributes for user $USER_ID."
       /opt/opendj/bin/ldapmodify -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt <<EOT
dn: uid=$USER_ID,ou=People,$BASE_DN
changetype: modify
replace: gidNumber
gidNumber: 5001
-
replace: homeDirectory
homeDirectory: /home/shared/$USER_ID
-
replace: loginShell
loginShell: /bin/bash
EOT
      fi
      if [[ `echo $USERS_IN_AMOS_USERS | tr [:upper:] [:lower:]` == *`echo $USER | tr [:upper:] [:lower:]`* ]] ; then
        continue
      fi
      echo "Adding $USER to amos_users group."
      USER=`echo $USER | sed -e "s/ou=People/ou=people/"`
      /opt/opendj/bin/ldapmodify -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt <<EOT
dn: cn=amos_users,ou=Groups,$BASE_DN
changetype: modify
add: uniqueMember
uniqueMember: $USER
EOT

    done
}

######################
# PART FOR SCRIPTING #
######################
FixScriptingUsers(){
    USERS_IN_SCRIPTING_USERS=`/opt/opendj/bin/ldapsearch -p $COM_INF_LDAP_PORT --useSSL --trustAll --no-prompt -D "$DM_DN" -w "$DM_PWD" -b "ou=groups,$BASE_DN" cn=scripting_users | grep uniqueMember | sed -e "s/uniqueMember: //"`
    echo "People in group scripting_users:"
    echo $USERS_IN_SCRIPTING_USERS

    USERS_NEEDED_SCRIPTING=`/opt/opendj/bin/ldapsearch -p $COM_INF_LDAP_PORT --useSSL --trustAll --no-prompt -D "$DM_DN" -w "$DM_PWD" -b "ou=people,$BASE_DN" "(&(roleTG=*Scripting_Operator*)(!(roleTG=*FIELD_TECHNICIAN*)))" | grep dn | sed -e "s/dn: //"`
    echo "People that should have Scripting attributes:"
    echo $USERS_NEEDED_SCRIPTING

    for USER in $USERS_NEEDED_SCRIPTING
    do
      USER_ID=`echo $USER | sed -e "s/.*uid=//" | sed -e "s/,ou=.*//"`
      GROUP_ID=`/opt/opendj/bin/ldapsearch -p $COM_INF_LDAP_PORT --useSSL --trustAll --no-prompt -D "$DM_DN" -w "$DM_PWD" -b "ou=people,$BASE_DN" uid=$USER_ID gidNumber | grep gidNumber | sed -e "s/gidNumber: //"`
      if [[ $GROUP_ID = "2147483647" ]] ; then
        echo "Adding missing attributes for user $USER_ID."
       /opt/opendj/bin/ldapmodify -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt <<EOT
dn: uid=$USER_ID,ou=People,$BASE_DN
changetype: modify
replace: gidNumber
gidNumber: 5003
-
replace: homeDirectory
homeDirectory: /home/shared/$USER_ID
-
replace: loginShell
loginShell: /bin/bash
EOT
      fi
      if [[ `echo $USERS_IN_SCRIPTING_USERS | tr [:upper:] [:lower:]` == *`echo $USER | tr [:upper:] [:lower:]`* ]] ; then
        continue
      fi
      echo "Adding $USER to scripting_users group."
      USER=`echo $USER | sed -e "s/ou=People/ou=people/"`
      /opt/opendj/bin/ldapmodify -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt <<EOT
dn: cn=scripting_users,ou=Groups,$BASE_DN
changetype: modify
add: uniqueMember
uniqueMember: $USER
EOT

    done
}

############################
# PART FOR ELEMENT_MANAGER #
############################
FixElementManagerUsers(){
    USERS_IN_EM_USERS=`/opt/opendj/bin/ldapsearch -p $COM_INF_LDAP_PORT --useSSL --trustAll --no-prompt -D "$DM_DN" -w "$DM_PWD" -b "ou=groups,$BASE_DN" cn=element-manager_users | grep uniqueMember | sed -e "s/uniqueMember: //"`
    echo "People in group element-manager_users:"
    echo $USERS_IN_EM_USERS

    USERS_NEEDED_EM=`/opt/opendj/bin/ldapsearch -p $COM_INF_LDAP_PORT --useSSL --trustAll --no-prompt -D "$DM_DN" -w "$DM_PWD" -b "ou=people,$BASE_DN" "(&(roleTG=*Element_Manager_Operator*)(!(roleTG=*FIELD_TECHNICIAN*)))" | grep dn | sed -e "s/dn: //"`
    echo "People that should have Element_Manager attributes:"
    echo $USERS_NEEDED_EM

    for USER in $USERS_NEEDED_EM
    do
      USER_ID=`echo $USER | sed -e "s/.*uid=//" | sed -e "s/,ou=.*//"`
      GROUP_ID=`/opt/opendj/bin/ldapsearch -p $COM_INF_LDAP_PORT --useSSL --trustAll --no-prompt -D "$DM_DN" -w "$DM_PWD" -b "ou=people,$BASE_DN" uid=$USER_ID gidNumber | grep gidNumber | sed -e "s/gidNumber: //"`
      if [[ $GROUP_ID = "2147483647" ]] ; then
        echo "Adding missing attributes for user $USER_ID."
       /opt/opendj/bin/ldapmodify -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt <<EOT
dn: uid=$USER_ID,ou=People,$BASE_DN
changetype: modify
replace: gidNumber
gidNumber: 5002
-
replace: homeDirectory
homeDirectory: /home/shared/$USER_ID
-
replace: loginShell
loginShell: /bin/bash
EOT
      fi
      if [[ `echo $USERS_IN_EM_USERS | tr [:upper:] [:lower:]` == *`echo $USER | tr [:upper:] [:lower:]`* ]] ; then
        continue
      fi
      echo "Adding $USER to element-manager_users group."
      USER=`echo $USER | sed -e "s/ou=People/ou=people/"`
      /opt/opendj/bin/ldapmodify -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt <<EOT
dn: cn=element-manager_users,ou=Groups,$BASE_DN
changetype: modify
add: uniqueMember
uniqueMember: $USER
EOT

    done
}
########
# MAIN #
########

GetPassword
FixAmosUsers
FixScriptingUsers
FixElementManagerUsers
