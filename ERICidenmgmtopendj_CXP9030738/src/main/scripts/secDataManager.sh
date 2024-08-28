#!/bin/ksh 
#
# -------------------------------------------------------------------------- #
#
#    Script: secDataManager.sh
#
#    Description: 
#       The script is used to manage the users, roles and groups in 
#       the Opendj ldap server.
#
#
#    Synopsis:
#    > secDataManager.sh -h | -help
#
#    > secDataManager.sh -list users | user | enmRoles | enmRole | groups | group | taskProfiles | scopes | scope
#
#    > secDataManager.sh -add user | enmRole | group | scope
#
#    > secDataManager.sh -delete user | enmRole | group | scope
#
#    > secDataManager.sh -update userPswd
#
#    > secDataManager.sh -assign enmRole | group | scope
#
#    > secDataManager.sh -unassign enmRole | group | scope
#
#
#    Copyright 2014 Ericsson Canada Inc, All Rights Reserved
#
# ------------------------------------------------------------------------- #
# Debugging Flag
# set -x

#######################################################################
# Setting the Environment
# Returns:
#     0       Success
#     1      failure
########################################################################

SetEnvironment(){
 
   ECHO=/bin/echo
   CAT=/bin/cat
   GREP=/bin/grep
   CUT=/bin/cut
   AWK=/bin/awk
   SED=/bin/sed
   HEAD=/usr/bin/head
   TAIL=/bin/tail
   OPENSSL=/usr/bin/openssl
   
   OPENDJ_HOME_DIR=/opt/opendj
   AC_HOME_DIR=/opt/ericsson/com.ericsson.oss.security/idenmgmt
   OPENDJ_BIN=$OPENDJ_HOME_DIR/bin
   OPENDJ_CONFIG=$OPENDJ_HOME_DIR/config
   LOGS_DIR=/var/log/opendj
   LDAPSEARCH_CMD=$OPENDJ_BIN/ldapsearch   
   LDAPMODIFY_CMD=$OPENDJ_BIN/ldapmodify  
   LDAPDELETE_CMD=$OPENDJ_BIN/ldapdelete    
   LDAPPASSWORDMODIFY_CMD=$OPENDJ_BIN/ldappasswordmodify
   SETUP_PROPS_FILE=$AC_HOME_DIR/config/datastore.properties
   GLOBAL_PROPERTY_FILE=/ericsson/tor/data/global.properties
   . $GLOBAL_PROPERTY_FILE >/dev/null 2>&1
   
   if [ ! -r $SETUP_PROPS_FILE ] ; then
      Log "ERROR: Opendj properties file [ $SETUP_PROPS_FILE ] is missing or not readable"
      LogAndDisplayNL ""
      return 1
   fi

   COMMAND_NAME="$(basename "$0")" # To get the script name
  
   MSG_LOG_LINES_MAX=1000
   MSG_LOG_LINES_KEEP=100
  
  
   # Default Roles
   SEC_ADMIN_ROLE="SECURITY_ADMIN"
   OPERATOR_ROLE="OPERATOR"
   ADMIN_ROLE="ADMINISTRATOR"

   # Default Scopes
   DEFAULT_SCOPE="DEFAULT_SCOPE"

   LDAP_PORT=`$GREP ldapPort $SETUP_PROPS_FILE | $CUT -d "=" -f 2`
   LDAPS_PORT=`$GREP ldapsPort $SETUP_PROPS_FILE | $CUT -d "=" -f 2`
   DM_DN=`$GREP rootUserDN  $SETUP_PROPS_FILE | $CUT -d "=" -f 2-`

   BASE_DN=$COM_INF_LDAP_ROOT_SUFFIX
   SSO_USER_DN=$COM_INF_LDAP_ADMIN_CN
   SSO_USER=`echo $SSO_USER_DN | $CUT -d= -f2 | $CUT -d, -f1`
   OPENDJ_PASSKEY=/ericsson/tor/data/idenmgmt/opendj_passkey

   # TODO: remove hardcoded password once TORF-18439 is delivered
   DM_PWD="ldapadmin"

   if [ -r ${OPENDJ_PASSKEY} ]; then
      DM_PWD=`echo ${LDAP_ADMIN_PASSWORD} | ${OPENSSL} enc -a -d -md md5 -aes-128-cbc -salt -kfile ${OPENDJ_PASSKEY}`
      if [ -z "${DM_PWD}" ]; then
         LogMessage "ERROR: Failed to decrypt LDAP_ADMIN_PASSWORD from ${GLOBAL_PROPERTY_FILE}"
         return 1
      fi
   fi


   SetLogFile "secDataManager"
   $ECHO ""
   $ECHO ""
   $ECHO "###################################################################################################"
   LogAndDisplay "secDataManager.sh script is invoked"
   LogAndDisplayNL ""
   $ECHO "---------------------------------------------------------------------------------------------------"
   $ECHO "Writing Logs to : $LOGFILE"
   $ECHO "---------------------------------------------------------------------------------------------------"
   $ECHO "###################################################################################################"
   $ECHO ""
   Log "INFO: SetEnvironment completed successfully"
   LogAndDisplayNL ""
   return 0

}
#####################################################################################
# Creates a daily log file
# It search if a log file already exist for the current day. If the log
# file exist and has greater than 1000 lines in size, only the last
# 100 lines of the file will be kept and all new messages will appended to it.
# if the file does not exist, create a new log file for the day.
#
# Returns:
#	0	Success
#	1	Errors
#
# Arguments:
#       1- Logfile base name
#####################################################################################
SetLogFile()
{
   if [ "$1" = "" ] ; then
      $ECHO "ERROR: Log file basename is expected."
      return 1
   fi
   logFileBasename=$1
   searchTimeStamp=`date "+%Y_%m_%d"`

   searchFile=`ls -t $LOGS_DIR/${logFileBasename}_${searchTimeStamp}*.log 2>/dev/null | $HEAD -1`
   if [ "$searchFile" != "" ] ; then
      LOGFILE="$searchFile"
      if [ "$( wc -l "$LOGFILE" | awk '{ print $1 }' )" -gt $MSG_LOG_LINES_MAX ]; then
          tail_output=$( tail -$MSG_LOG_LINES_KEEP $LOGFILE )
          echo $tail_output > $LOGFILE
      fi
      $ECHO "INFO: SetLogFile - Log File was re-open at [`date '+%B %d %Y %T' `]\n" 2> /dev/null >> $LOGFILE
      $ECHO ""
      if [ $? != 0 ] ; then
         $ECHO "ERROR: SetLogFile - Failed to write to Log file [ $LOGFILE ]."
         $ECHO ""
         return 1
      fi

      return 0
   fi

   LOGFILE="$LOGS_DIR/secDataManager_`date '+%Y_%m_%d'`.log"
   return $?

}

###############################################
# Function: ListUsers
# Arguments: none
# This function lists all the enmUser Entries in 
# the ldap server and displayed the total
# number of users as well.
# The ssouser is not displayed.
###############################################
ListUsers(){


  Log "INFO: ListUsers - starting... "
  LogAndDisplayNL ""
  $LDAPSEARCH_CMD --port $LDAP_PORT -D "$DM_DN" -w "$DM_PWD" --baseDN "ou=People,$BASE_DN" \
                           --countEntries "(&(uid=*)(!(uid=$SSO_USER))(userType=enmUser))" uid userType 
   
  if [ $? -ne 0 ] ; then
     LogAndDisplay "ERROR: ListUsers: Failed to list users from directory server"
     LogAndDisplayNL ""
       return  1
  else
       Log "INFO: ListUsers - completed with no errors."
       LogAndDisplayNL ""
       return 0
  fi

}

###############################################
# Function: ListUser
# Arguments: none
###############################################
ListUser(){
    Log "INFO: ListUser - starting...."
    LogAndDisplayNL ""

    # Remove and leading and trailing \" chars
    ldapUserName="${enteredUserName%\"}"
    ldapUserName="${ldapUserName#\"}"
   
 
   if [[ ${ldapUserName} == $SSO_USER ]] ; then
     LogAndDisplay "The entered user id is a hidden user and cannot be listed."
     LogAndDisplayNL ""
     LogAndDisplay "Please try again with a difference user id"
     LogAndDisplayNL ""
     return 0
   fi
 
    # Retrieve the sought user detailes including the role membership
    $LDAPSEARCH_CMD --port $LDAP_PORT -D "$DM_DN" -w "$DM_PWD" --baseDN "$BASE_DN" --countEntries "(&(uid=$ldapUserName)(userType=enmUser))"  \
        isMemberOf @person userType uid 

    if [ $? -ne 0 ] ; then
      LogAndDisplay "ERROR:List User -  Failed to get user: $enteredUserName from directory server"
      LogAndDisplayNL ""
      return  1
    else
       Log "INFO: ListUser - Completed with no errors."
       LogAndDisplayNL ""
       return 0
    fi
     

}
###############################################
# Function: ListM2MUsers
# Arguments: none
# This function lists all the M2M users
###############################################
ListM2MUsers(){


  Log "INFO: ListM2MUsers - starting... "
  LogAndDisplayNL ""
  $LDAPSEARCH_CMD --port $LDAP_PORT -D "$DM_DN" -w "$DM_PWD" --baseDN "ou=M2MUsers,$BASE_DN" --countEntries "(uid=*)" uid userType uidNumber gidNumber homeDirectory
   
  if [ $? -ne 0 ] ; then
     LogAndDisplay "ERROR: ListM2MUsers: Failed to list M2M users from directory server"
     LogAndDisplayNL ""
       return  1
  else
       Log "INFO: ListM2MUsers - completed with no errors."
       LogAndDisplayNL ""
       return 0
  fi

}



###############################################
# Function: ListRoles
# Arguments: none
# This function lists all the ENMS Roles Entries in
# the local ldap server and displayed the total
# number of roles as well.
###############################################
ListRoles(){
   Log "INFO: ListRoles - starting ...... "
   LogAndDisplayNL ""
   
   # Listing only the DNs and CNs.
   $LDAPSEARCH_CMD --port $LDAP_PORT -D "$DM_DN" -w "$DM_PWD" --baseDN "ou=Roles,$BASE_DN" --countEntries cn=\* cn description

   if [ $? -ne 0 ] ; then
      LogAndDisplay "ERROR: ListRoles - Failed to get list of ENM roles from directory server"
      LogAndDisplayNL ""
      return  1
   else
      Log "INFO: ListRoles - Completed with no errors."
      LogAndDisplayNL ""
      return 0
   fi
 
 }


###############################################
# Function: ListRole
# Arguments: none
# This functions lists the details of the selected
# enms Role.
###############################################
ListRole(){
   Log "INFO: ListRole - starting ...."
   LogAndDisplayNL ""
   #$ECHO "entered roleName: " $roleName
   
   # Remove and leading and trailing " chars
   cleanRoleName="${roleName%\"}"
   cleanRoleName="${cleanRoleName#\"}"
   
   $LDAPSEARCH_CMD --port $LDAP_PORT -D "$DM_DN" -w "$DM_PWD" --baseDN "ou=Roles,$BASE_DN" --countEntries cn=$cleanRoleName

   if [ $? -ne 0 ] ; then
      LogAndDisplay "ERROR: ListRole - Failed to get the enmRole data from directory server"
      LogAndDisplayNL ""
      return  1
   else
      Log "INFO: ListRole - Completed with no errors."
      LogAndDisplayNL ""
      return 0
   fi
 
}

###############################################
# Function: ListGroups
# Arguments: none
# This function lists all the user Groups Entries in
# the ldap server and displays the total
# number of groups as well.
###############################################

ListGroups(){
   Log "INFO: ListGroups - starting ...."
   LogAndDisplayNL ""
   
   # Listing only the DNs and CNs.
   $LDAPSEARCH_CMD --port $LDAP_PORT -D "$DM_DN" -w "$DM_PWD" --baseDN "ou=Groups,$BASE_DN" --countEntries cn=\* cn

   if [ $? -ne 0 ] ; then
      LogAndDisplay "ERROR: ListGroups - Failed to get list of groups from directory server"
      LogAndDisplayNL ""
      return  1
   else
      Log "INFO: ListGroups - Completed with no errors."
      LogAndDisplayNL ""
      return 0
   fi
 
}


###############################################
# Method: ListGroup
# Arguments: none
###############################################

ListGroup(){
   Log "INFO: ListGroup - starting ...."
   LogAndDisplayNL ""
   #$ECHO "entered groupName: " $groupName
   
   # Remove and leading and trailing " chars
   cleanGroupName="${groupName%\"}"
   cleanGroupName="${cleanGroupName#\"}"

   $LDAPSEARCH_CMD --port $LDAP_PORT -D "$DM_DN" -w "$DM_PWD" --baseDN "ou=Groups,$BASE_DN" --countEntries cn=$cleanGroupName

   if [ $? -ne 0 ] ; then
      LogAndDisplay "ERROR: ListGroups - Failed to get the data for the selected group from directory server"
      LogAndDisplayNL ""
      return  1
   else
      Log "INFO: ListGroup - Completed with no errors."
      LogAndDisplayNL ""
      return 0
   fi
 
}


###############################################
# Function: ListTaskProfiles 
# Arguments: none
###############################################
ListTaskProfiles(){
   Log "INFO: ListTaskProfiles - starting ...."
   LogAndDisplayNL ""
   
   $LDAPSEARCH_CMD -p $LDAP_PORT -D "$DM_DN" -w "$DM_PWD" -b "$BASE_DN" "(objectClass=TaskProfilesList)" taskProfile 

   if [ $? -ne 0 ] ; then
      LogAndDisplay "ERROR: ListTaskProfiles - Failed to get the task profiles data from directory server"
      LogAndDisplayNL ""
      return  1
   else
      Log "INFO: ListTaskProfiles - Completed with no errors."
      LogAndDisplayNL ""
      return 0
   fi
 
}

###############################################
# Function: ListScopes
# Arguments: none
# This function lists all the Scopes Entries in
# the local ldap server and displayed the total
# number of scope as well.
###############################################
ListScopes(){
   Log "INFO: ListScopes - starting ...... "
   LogAndDisplayNL ""
  
   # Listing only the DNs and CNs.
   $LDAPSEARCH_CMD --port $LDAP_PORT -D "$DM_DN" -w "$DM_PWD" --baseDN "ou=Scopes,$BASE_DN" --countEntries cn=\* cn description

   if [ $? -ne 0 ] ; then
      LogAndDisplay "ERROR: ListScopes - Failed to get list of scopes from directory server"
      LogAndDisplayNL ""
      return  1
   else
      Log "INFO: ListScopes - Completed with no errors."
      LogAndDisplayNL ""
      return 0
   fi

 }

###############################################
# Function: ListScope
# Arguments: none
# This functions lists the details of the selected
# scope.
###############################################
ListScope(){
   Log "INFO: ListScope - starting ...."
   LogAndDisplayNL ""
   #$ECHO "entered scopeName: " $scopeName

   # Remove and leading and trailing " chars
   cleanScopeName="${scopeName%\"}"
   cleanScopeName="${cleanScopeName#\"}"

   $LDAPSEARCH_CMD --port $LDAP_PORT -D "$DM_DN" -w "$DM_PWD" --baseDN "ou=Scopes,$BASE_DN" --countEntries cn=$cleanScopeName

   if [ $? -ne 0 ] ; then
      LogAndDisplay "ERROR: ListScope - Failed to get the scope data from directory server"
      LogAndDisplayNL ""
      return  1
   else
      Log "INFO: ListScope - Completed with no errors."
      LogAndDisplayNL ""
      return 0
   fi

}

###############################################
# Function: AddUser 
# Arguments: none
# This functions adds a new enmUser to the ldap server.
###############################################
AddUser() {
   Log "INFO: AddUser - starting  ...." 
   LogAndDisplayNL ""

   ldapUserName="${enteredUserName%\"}"
   ldapUserName="${ldapUserName#\"}"
  
   echo "dn: uid=$ldapUserName,ou=People,$BASE_DN" > newUser.ldif 
   echo "uid: "$ldapUserName >> newUser.ldif 

   echo "objectClass: person" >> newUser.ldif
   echo "objectClass: inetOrgPerson" >> newUser.ldif 
   echo "objectClass: organizationalPerson">> newUser.ldif 
   echo "objectClass: top" >> newUser.ldif 
   echo "objectClass: userTypeOC" >> newUser.ldif 
   echo "userType: enmUser" >> newUser.ldif 

   echo "cn: $firstName" >> newUser.ldif 
   echo "sn: $lastName" >> newUser.ldif
   echo "userPassword: $userPswd" >> newUser.ldif


   $LDAPMODIFY_CMD -p $LDAP_PORT  -D "$DM_DN" -w $DM_PWD -a -f "newUser.ldif"

   if [ $? -ne 0 ] ; then
      LogAndDisplay "ERROR: AddUser - Failed to add a new user to the ldap directory server"
      LogAndDisplayNL ""
      return  1
   else
      `rm -f ./newUser.ldif`
      Log "INFO: AddUser - Completed with no errors."
      LogAndDisplayNL ""
      return 0
   fi
}


###############################################
# Function: AddRole 
# Arguments: none
# This function adds a new enm role to the directory
# server. No users are assigned to this role.
###############################################
AddRole() {
   Log "INFO: AddRole - starting ...." 
   LogAndDisplayNL ""

   cleanRoleName="${roleName%\"}"
   cleanRoleName="${cleanRoleName#\"}"

   cleanDesc="${roleDescription%\"}"
   cleanDesc="${cleanDesc#\"}"

   # The ou=Roles container has been already created during priming phase 
   $ECHO "dn: cn=$cleanRoleName,ou=Roles,$BASE_DN" > newRole.ldif 
   $ECHO "cn: $cleanRoleName" >> newRole.ldif
   $ECHO "objectClass: groupOfUniqueNames" >> newRole.ldif 
   $ECHO "objectClass: top" >> newRole.ldif 
   $ECHO "objectClass: enmRole" >> newRole.ldif 
   $ECHO "description: $cleanDesc" >> newRole.ldif
   
   $LDAPMODIFY_CMD -p $LDAP_PORT  -D "$DM_DN" -w $DM_PWD -a -f "newRole.ldif"

   if [ $? -ne 0 ] ; then
      LogAndDisplay "ERROR: AddRole - Failed to add a new role to the ldap directory server"
      LogAndDisplayNL ""
      return  1
   else
      `rm -f ./newRole.ldif`
      Log "INFO: AddRole - Completed with no errors."
      LogAndDisplayNL ""
      return 0
   fi
}


###########################################################
# Function: AddGroup 
# Arguments: none
# This function adds a new User Group to the directory
# server. No users are assigned to this group at this phase.
###########################################################
AddGroup() {
   Log "INFO: AddGroup - starting ...." 
   LogAndDisplayNL ""

   # Remove and leading and trailing " chars
   cleanGroupName="${groupName%\"}"
   cleanGroupName="${cleanGroupName#\"}"

   # The ou=Groups container has been already created during priming phase 
   $ECHO "dn: cn=$cleanGroupName,ou=Groups,$BASE_DN" > newGroup.ldif 
   $ECHO "cn: $cleanGroupName" >> newGroup.ldif
   $ECHO "objectClass: groupOfUniqueNames" >> newGroup.ldif 
   $ECHO "objectClass: top" >> newGroup.ldif 
   $ECHO "objectClass: cpp " >> newGroup.ldif 
   $ECHO "taskProfile: $taskProfile" >> newGroup.ldif 
   $ECHO "objectClass: ecim" >> newGroup.ldif 
   $ECHO "ecimRole: $ecimRole" >> newGroup.ldif 
   $ECHO "objectClass: targetGroup " >> newGroup.ldif 
   $ECHO "target: $target" >> newGroup.ldif 
   $ECHO "description: $groupDesc" >> newGroup.ldif
   
   $LDAPMODIFY_CMD -p $LDAP_PORT  -D "$DM_DN" -w $DM_PWD -a -f "newGroup.ldif"

   if [ $? -ne 0 ] ; then
      LogAndDisplay "ERROR: AddGroup - Failed to add a new group to the ldap directory server"
      LogAndDisplayNL ""
      return  1
   else
      `rm -f ./newGroup.ldif`
      Log "INFO: AddGroup - Completed with no errors."
      LogAndDisplayNL ""
      return 0
   fi
}


###############################################
# Function: AddScope
# Arguments: none
# This function adds a new scope to the directory
# server. No users are assigned to this scope.
###############################################
AddScope() {
   Log "INFO: AddScope - starting ...."
   LogAndDisplayNL ""

   cleanScopeName="${scopeName%\"}"
   cleanScopeName="${cleanScopeName#\"}"

   cleanDesc="${scopeDescription%\"}"
   cleanDesc="${cleanDesc#\"}"

   # The ou=Scopes container has been already created during priming phase
   $ECHO "dn: cn=$cleanScopeName,ou=Scopes,$BASE_DN" > newScope.ldif
   $ECHO "cn: $cleanScopeName" >> newScope.ldif
   $ECHO "objectClass: groupOfUniqueNames" >> newScope.ldif
   $ECHO "objectClass: top" >> newScope.ldif
   $ECHO "description: $cleanDesc" >> newScope.ldif
  
   $LDAPMODIFY_CMD -p $LDAP_PORT  -D "$DM_DN" -w $DM_PWD -a -f "newScope.ldif"

   if [ $? -ne 0 ] ; then
      LogAndDisplay "ERROR: AddScope - Failed to add a new scope to the ldap directory server"
      LogAndDisplayNL ""
      return  1
   else
      `rm -f ./newScope.ldif`
      Log "INFO: AddScope - Completed with no errors."
      LogAndDisplayNL ""
      return 0
   fi
}

###############################################
# Function: DeleteUser
# Arguments: none 
###############################################
DeleteUser() {
   Log "INFO: DeleteUser - starting ...."
   LogAndDisplayNL ""

    # Remove and leading and trailing " chars
    cleanUserId="${enteredUserName%\"}"
    cleanUserId="${cleanUserId#\"}"

   if [[ ${cleanUserId} == $SSO_USER ]] ; then
     LogAndDisplay "The entered user id is a protected user and cannot be deleted."
     LogAndDisplayNL ""
     LogAndDisplay "Please try again with a difference user id"
     LogAndDisplayNL ""
     LogAndDisplay "ERROR: DeleteUser - Failed to delete user: $cleanUserId from directory server" 
     LogAndDisplayNL ""
     return 1
   fi

    $LDAPDELETE_CMD --port $LDAP_PORT -D "$DM_DN" -w "$DM_PWD" uid=$cleanUserId,"ou=People,$BASE_DN"

    if [ $? -ne 0 ] ; then
      LogAndDisplay "ERROR: DeleteUser - Failed to delete user \"$cleanUserId\" from directory server"
      LogAndDisplayNL ""
      return  1
    else
       Log "INFO: DeleteUser - Completed with no errors"
       LogAndDisplayNL ""
       return 0
    fi
    
}

###############################################
# Function: DeleteRole
# Arguments: none 
###############################################
DeleteRole() {
   Log "INFO: DeleteRole - Starting ...."
   LogAndDisplayNL ""

    # Remove any leading and trailing " chars
    cleanRoleName="${roleName%\"}"
    cleanRoleName="${cleanRoleName#\"}"

   if [[ ${cleanRoleName} == $SEC_ADMIN_ROLE || \
         ${cleanRoleName} == $OPERATOR_ROLE || \
         ${cleanRoleName} == $ADMIN_ROLE ]] ; then
     LogAndDisplay "The entered role name is a default role name and cannot be deleted."
     LogAndDisplayNL ""
     LogAndDisplay "Please try again with a difference role name"
     LogAndDisplayNL ""
     LogAndDisplay "ERROR: DeleteRole - Failed to delete role: \"$cleanRoleName\" from directory server" 
     LogAndDisplayNL ""
     return 1
   fi

    $LDAPDELETE_CMD --port $LDAP_PORT -D "$DM_DN" -w "$DM_PWD" cn=$cleanRoleName,"ou=Roles,$BASE_DN"

    if [ $? -ne 0 ] ; then
      LogAndDisplay "ERROR: DeleteRole - Failed to delete role: \"$cleanRoleName\" from directory server"
      LogAndDisplayNL ""
      return  1
    else
       Log "INFO: DeleteRole - Completed with no errors"
       LogAndDisplayNL ""
       return 0
    fi
    
}


###############################################
# Function: DeleteGroup
# Arguments: none 
###############################################

DeleteGroup() {
    Log "INFO: DeleteGroup - Starting ...."
    LogAndDisplayNL ""

    cleanGroupName="${groupName%\"}"
    cleanGroupName="${cleanGroupName#\"}"

    $LDAPDELETE_CMD --port $LDAP_PORT -D "$DM_DN" -w "$DM_PWD" cn=$cleanGroupName,"ou=Groups,$BASE_DN"

    if [ $? -ne 0 ] ; then
      LogAndDisplay "ERROR: DeleteGroup - Failed to delete group \"$cleanGroupName\" from directory server"
      LogAndDisplayNL ""
      return  1
    else
       Log "INFO: DeleteGroup - Completed with no errors"
       return 0
    fi
    
}

###############################################
# Function: DeleteScope
# Arguments: none
###############################################
DeleteScope() {
   Log "INFO: DeleteScope - Starting ...."
   LogAndDisplayNL ""

    # Remove any leading and trailing " chars
    cleanScopeName="${scopeName%\"}"
    cleanScopeName="${cleanScopeName#\"}"

   
   if [[ ${cleanScopeName} == $DEFAULT_SCOPE ]] ; then 
     LogAndDisplay "The entered scope name is a default scope name and cannot be deleted."
     LogAndDisplayNL ""
     LogAndDisplay "Please try again with a difference scope name"
     LogAndDisplayNL ""
     LogAndDisplay "ERROR: DeleteScope - Failed to delete scope: \"$cleanScopeName\" from directory server"
     LogAndDisplayNL ""
     return 1
   fi

    $LDAPDELETE_CMD --port $LDAP_PORT -D "$DM_DN" -w "$DM_PWD" cn=$cleanScopeName,"ou=Scopes,$BASE_DN"

    if [ $? -ne 0 ] ; then
      LogAndDisplay "ERROR: DeleteScope - Failed to delete scope: \"$cleanScopeName\" from directory server"
      LogAndDisplayNL ""
      return  1
    else
       Log "INFO: DeleteScope - Completed with no errors"
       LogAndDisplayNL ""
       return 0
    fi
   
}

###############################################
# Function: UpdateUserPassword
# Arguments: none
###############################################
UpdateUserPassword() {
    Log "INFO: UpdateUserPassword - Starting ...." 
    LogAndDisplayNL ""

    cleanUserId="${enteredUserName%\"}"
    cleanUserId="${cleanUserId#\"}"
    
    cleanCurrUserPswd="${currUserPswd%\"}"
    cleanCurrUserPswd="${cleanCurrUserPswd#\"}"
    
    cleanUserPswd="${newUserPswd%\"}"
    cleanUserPswd="${cleanUserPswd#\"}"

    $LDAPPASSWORDMODIFY_CMD --no-prompt -p $LDAP_PORT  -D "$DM_DN" -w $DM_PWD -a "dn:uid=$cleanUserId,ou=People,$BASE_DN" -c $cleanCurrUserPswd -n $cleanUserPswd


    if [ $? -ne 0 ] ; then
      LogAndDisplay "ERROR: UpdateUserPassword - Failed to update the used password from directory server"
      LogAndDisplayNL ""
      return  1
    else
       Log "INFO: UpdateUserPassword- Completed with no errors"
       LogAndDisplayNL ""
       return 0
    fi
    
}


###############################################
# Function: AssignEnmRole 
# Arguments: none
# This function assigns a new role to the selected user.
# A user can have more than one role assigned to him/her at any time.
###############################################

AssignEnmRole(){
   Log "INFO: AssignEnmRole - Starting ...."
   LogAndDisplayNL ""

   cleanUserName="${enteredUserName%\"}"
   cleanUserName="${cleanUserName#\"}"

   cleanRoleName="${roleName%\"}"
   cleanRoleName="${cleanRoleName#\"}"

   
   $ECHO "dn: cn=${cleanRoleName},ou=Roles,$BASE_DN" > newUserRole.ldif
   $ECHO "changetype: modify" >> newUserRole.ldif
   $ECHO "add:uniquemember" >> newUserRole.ldif
   $ECHO "uniquemember: uid=$cleanUserName,ou=People,$BASE_DN" >> newUserRole.ldif 


   $LDAPMODIFY_CMD -p $LDAP_PORT  -D "$DM_DN" -w $DM_PWD -f "newUserRole.ldif"

   if [ $? -ne 0 ] ; then
       LogAndDisplay "ERROR: AssignEnmRole - Failed to Assign a role to the user"
       LogAndDisplayNL ""
      return  1
    else
       `rm -f ./newUserRole.ldif`
       Log "INFO: AssignEnmRole - Completed with no errors"
       LogAndDisplayNL ""
       return 0
    fi
    
}


###############################################
# Function: UnassignEnmRole
# Arguments: none
# This function unassigns an enmRole from the selected user.
###############################################
UnassignEnmRole(){
   Log "INFO: UnassignEnmRole - Starting ...."
   LogAndDisplayNL ""

   cleanUserName="${enteredUserName%\"}"
   cleanUserName="${cleanUserName#\"}"

   cleanRoleName="${roleName%\"}"
   cleanRoleName="${cleanRoleName#\"}"

   $ECHO "dn: cn=${cleanRoleName},ou=Roles,$BASE_DN" > unassignEnmRole.ldif
   $ECHO "changetype: modify" >> unassignEnmRole.ldif 
   $ECHO "delete:uniquemember" >> unassignEnmRole.ldif 
   $ECHO "uniquemember: uid=$cleanUserName,ou=People,$BASE_DN" >> unassignEnmRole.ldif 


   $LDAPMODIFY_CMD -p $LDAP_PORT  -D "$DM_DN" -w $DM_PWD -f "unassignEnmRole.ldif"

   if [ $? -ne 0 ] ; then
      LogAndDisplay "ERROR: UnassignEnmRole - Failed to Unassign an enmRole to the user"
      LogAndDisplayNL ""
      return  1
    else
       `rm -f ./unassignEnmRole.ldif`
       Log "INFO: UnassignEnmRole - Completed with no errors"
       LogAndDisplayNL ""
       return 0
    fi
    
}


###############################################
# Function: AssignGroup 
# Arguments: none
# This function assigns a new group to the selected user.
# A user can have more than one group assigned to him/her at any time.
###############################################

AssignGroup(){
   Log "INFO: AssignGroup - Starting ...."
   LogAndDisplayNL ""

   cleanUserName="${enteredUserName%\"}"
   cleanUserName="${cleanUserName#\"}"

   cleanGroupName="${groupName%\"}"
   cleanGroupName="${cleanGroupName#\"}"

   $ECHO "dn: cn=${cleanGroupName},ou=Groups,$BASE_DN" > newUserGroup.ldif
   $ECHO "changetype: modify" >> newUserGroup.ldif
   $ECHO "add:uniquemember" >> newUserGroup.ldif
   $ECHO "uniquemember: uid=$cleanUserName,ou=People,$BASE_DN" >> newUserGroup.ldif 

   $LDAPMODIFY_CMD -p $LDAP_PORT  -D "$DM_DN" -w $DM_PWD -f "newUserGroup.ldif"

   if [ $? -ne 0 ] ; then
      LogAndDisplay "ERROR: AssignGroup - Failed to assign a group to a user"
      LogAndDisplayNL ""
      return  1
    else
       `rm -f ./newUserGroup.ldif`
       Log "INFO: AssignGroup - Completed with no errors"
       LogAndDisplayNL ""
       return 0
    fi
    
}


###############################################
# Function: UnassignGroup
# Arguments: none
# This function unassigns a group from the selected user.
###############################################
UnassignGroup(){
   Log "INFO: UnassignGroup - Starting ...."
   LogAndDisplayNL ""

   cleanUserName="${enteredUserName%\"}"
   cleanUserName="${cleanUserName#\"}"

   cleanGroupName="${groupName%\"}"
   cleanGroupName="${cleanGroupName#\"}"

   $ECHO "dn: cn=${cleanGroupName},ou=Groups,$BASE_DN" > unassignGroup.ldif
   $ECHO "changetype: modify" >> unassignGroup.ldif 
   $ECHO "delete:uniquemember" >> unassignGroup.ldif 
   $ECHO "uniquemember: uid=$cleanUserName,ou=People,$BASE_DN" >> unassignGroup.ldif 


   $LDAPMODIFY_CMD -p $LDAP_PORT  -D "$DM_DN" -w $DM_PWD -f "unassignGroup.ldif"

   if [ $? -ne 0 ] ; then
      LogAndDisplay "ERROR: UnassignGroup - Failed to unassign a group to a user"
      LogAndDisplayNL ""
      return  1
    else
       `rm -f ./unassignGroup.ldif`
       Log "INFO: UnassignGroup - Completed with no errors"
       LogAndDisplayNL ""
       return 0
    fi
    
}


###############################################
# Function: AssignScope
# Arguments: none
# This function assigns a new scope to the selected user.
# A user can have more than one scope assigned to him/her at any time.
###############################################

AssignScope(){
   Log "INFO: AssignScope - Starting ...."
   LogAndDisplayNL ""

   cleanUserName="${enteredUserName%\"}"
   cleanUserName="${cleanUserName#\"}"

   cleanScopeName="${scopeName%\"}"
   cleanScopeName="${cleanScopeName#\"}"

  
   $ECHO "dn: cn=${cleanScopeName},ou=Scopes,$BASE_DN" > newUserScope.ldif
   $ECHO "changetype: modify" >> newUserScope.ldif
   $ECHO "add:uniquemember" >> newUserScope.ldif
   $ECHO "uniquemember: uid=$cleanUserName,ou=People,$BASE_DN" >> newUserScope.ldif


   $LDAPMODIFY_CMD -p $LDAP_PORT  -D "$DM_DN" -w $DM_PWD -f "newUserScope.ldif"

   if [ $? -ne 0 ] ; then
       LogAndDisplay "ERROR: AssignScope - Failed to Assign a scope to the user"
       LogAndDisplayNL ""
      return  1
    else
       `rm -f ./newUserScope.ldif`
       Log "INFO: AssignScope - Completed with no errors"
       LogAndDisplayNL ""
       return 0
    fi
   
}


###############################################
# Function: UnassignScope
# Arguments: none
# This function unassigns an scope from the selected user.
###############################################
UnassignScope(){
   Log "INFO: UnassignScope - Starting ...."
   LogAndDisplayNL ""

   cleanUserName="${enteredUserName%\"}"
   cleanUserName="${cleanUserName#\"}"

   cleanScopeName="${scopeName%\"}"
   cleanScopeName="${cleanScopeName#\"}"

   $ECHO "dn: cn=${cleanScopeName},ou=Scopes,$BASE_DN" > unassignScope.ldif
   $ECHO "changetype: modify" >> unassignScope.ldif
   $ECHO "delete:uniquemember" >> unassignScope.ldif
   $ECHO "uniquemember: uid=$cleanUserName,ou=People,$BASE_DN" >> unassignScope.ldif


   $LDAPMODIFY_CMD -p $LDAP_PORT  -D "$DM_DN" -w $DM_PWD -f "unassignScope.ldif"

   if [ $? -ne 0 ] ; then
      LogAndDisplay "ERROR: UnassignScope - Failed to Unassign a scope to the user"
      LogAndDisplayNL ""
      return  1
    else
       `rm -f ./unassignScope.ldif`
       Log "INFO: UnassignScope - Completed with no errors"
       LogAndDisplayNL ""
       return 0
    fi

}


###############################################
# Function Log
# Arguments: message to log
###############################################
Log(){
 $ECHO -n `date '+%B %d %Y %T' `": $1" >> $LOGFILE
}


###############################################
# Function LogAndDisplay
# Arguments: message to log
###############################################
LogAndDisplay(){
 #$ECHO -n  `date '+%B %d %Y %T' `": $1" 
 $ECHO -n "$1" 
 $ECHO -n `date '+%B %d %Y %T' `": $1" >> $LOGFILE
 #$ECHO "$1"
 #$ECHO "$1" >> $LOGFILE 
}


###############################################
# Function LogAndDisplayNL
# Arguments: None
###############################################

LogAndDisplayNL(){
 $ECHO "" 
 $ECHO "" >> $LOGFILE

}
###############################################
# Function FormatOutput
# Arguments: message to log
###############################################
FormatOutput(){
  IFS="\|"
  for i in $res
  do 
    $ECHO $i
  done
}
###############################################
# Function Usage
# Arguments: None
###############################################
Usage(){
    $ECHO "" 
    $ECHO "Usage:" 
    $ECHO ""
    $ECHO "$COMMAND_NAME -h | -help"
    $ECHO "" 
    $ECHO "$COMMAND_NAME -list users | user | enmRoles | enmRole | groups | group | taskProfiles | scopes | scope"
    $ECHO ""
    $ECHO "$COMMAND_NAME -add user | enmRole | group | scope" 
    $ECHO ""
    $ECHO "$COMMAND_NAME -delete user | enmRole | group | scope" 
    $ECHO ""
    $ECHO "$COMMAND_NAME -update userPswd" 
    $ECHO ""
    $ECHO "$COMMAND_NAME -assign enmRole | group | scope" 
    $ECHO ""
    $ECHO "$COMMAND_NAME -unassign enmRole | group | scope" 
    $ECHO ""
}


#####################################################################################
# This method reads the user input
# Returns:
#       answer: the answer of the user
#####################################################################################
GetUserResponse()
{

  # Read the response from the terminal
   while read entry
     do
       case "$entry" in
 
         # Set $ANSWER to y if the response is yes
         [Yy] | [Yy][Ee][Ss] )
           ANSWER=y
           return
           ;;
 
         # Set $ANSWER to n if the response is no
         [Nn] | [Nn][Oo] )
           ANSWER=n
           return
           ;;

         # Otherwise, wait for a valid response
        * )
          LogAndDisplay "Invalid response, please respond with \"yes\" or \"no\": "
          ;;
       esac
   done
}

###########################################################
# Function: AskForConfirmation
# Confirm if the information entered is correct
###########################################################
AskForConfirmation () { 

   LogAndDisplay "Is all of the above information correct (y/n/q) (<Enter> for n)? ";
   read  -u0 RESP;
   $ECHO "";
   return $RESP;
}



###########################################################
# Function: AskForUserData
# Prompts the user to enter User Data.
###########################################################
AskForUserData()
{
   typeset input1="";
   typeset input2="";
   typeset input3="";
   typeset input4="";
   typeset input5="";
   
   while [[ ${input1} == "" ]]
     do
       $ECHO -n "Enter the User Id (uid): "
       read -u0 input1;
     done
   
   while [[ ${input2} == "" ]]
     do
       $ECHO -n "Enter the first name: "; 
       read -u0 input2;
     done
   
   while [[ ${input3} == "" ]]
     do
       $ECHO -n "Enter the last name: "; 
       read -u0 input3;
     done
  
   stty -echo >/dev/null
   while [[ ${input4} == "" ||  ${input5} == "" ||  ${input4} !=  ${input5} ]]
     do
       $ECHO -n "Enter the user password:"; 
       read -u0 input4;
       $ECHO ""
       $ECHO -n "Please confirm the user password:"; 
       read -u0 input5;
       if [ "$input4" != "$input5" ] ; then
          $ECHO ""
          $ECHO -n "ERROR: passwords don't match"; 
       fi
       $ECHO ""
     done
   stty echo  >/dev/null

   enteredUserName=$input1;
   firstName=$input2;
   lastName=$input3;
   userPswd=$input4;
}
###########################################################
# Function: AskForRoleData
# Prompts the user to enter Role Data.
###########################################################
AskForRoleData()
{
   typeset input1="";
   typeset input2="";

   while [[ ${input1} == "" ]]
      do
      $ECHO -n "Enter a value for the role Common Name (cn): ";
      read -u0 input1;
   done

   $ECHO -n "Enter a value for the role description:  (<Enter> for null): ";
   read -u0 input2;

   roleName=$input1;
   roleDescription=$input2;

}
###########################################################
# Function: AskForRoleName
# Prompts the user to enter Role Name.
###########################################################
AskForRoleName()
{

   typeset input1="";
   while [[ ${input1} == "" ]]
      do
      $ECHO -n "Enter a value for the role Common Name (cn): ";
      read -u0 input1;
   done
   roleName=$input1;
}
###########################################################
# Function: AskForScopeData
# Prompts the user to enter Scope Data.
###########################################################
AskForScopeData()
{
   typeset input1="";
   typeset input2="";

   while [[ ${input1} == "" ]]
      do
      $ECHO -n "Enter a value for the scope Common Name (cn): ";
      read -u0 input1;
   done

   $ECHO -n "Enter a value for the scope description:  (<Enter> for null): ";
   read -u0 input2;

   scopeName=$input1;
   scopeDescription=$input2;
}
###########################################################
# Function: AskForScopeName
# Prompts the user to enter Scope Name.
###########################################################
AskForScopeName()
{
   typeset input1="";
   while [[ ${input1} == "" ]]
      do
      $ECHO -n "Enter a value for the scope Common Name (cn): ";
      read -u0 input1;
   done
   scopeName=$input1;
}
###########################################################
# Function: AskForUserName
# Prompt the user to enter the username.
###########################################################
AskForUserName()
{
   typeset input1="";
   while [[ ${input1} == "" ]]
      do
      $ECHO -n "Enter a value for the User Id (uid): ";
      read -u0 input1;
   done
   enteredUserName="\"$input1\"";
}

###########################################################
# Function: AskForUserPassword
# Prompt the user to enter the new user password.
###########################################################
AskForUserPassword()
{
   typeset input1="";
   typeset input2="";
   while [[ ${input1} == "" ]]
      do
      $ECHO -n "Enter the value for the Current User Password: ";
      read -u0 input1;
   done
   currUserPswd=$input1;
   while [[ ${input2} == "" ]]
      do
      $ECHO -n "Enter a value for the New User Password: ";
      read -u0 input2;
   done
   newUserPswd=$input2;

}


###########################################################
# Function: AskForGroupName
# Prompts the user to enter Group Name.
###########################################################
AskForGroupName()
{
   typeset input1="";
   while [[ ${input1} == "" ]]
      do
      $ECHO -n "Enter a value for the group Common Name (cn): ";
      read -u0 input1;
   done
   groupName=$input1;
}

###########################################################
# Function: AskForGroupData
# Prompts the user to enter group Data.
###########################################################
AskForGroupData()
{
   typeset input1="";
   typeset input2="";
   typeset input3="";
   typeset input4="";
   typeset input5="";
   while [[ ${input1} == "" ]]
      do
      $ECHO -n "Enter a value for the new group Common Name (cn): ";
      read -u0 input1;
   done

   ListTaskProfiles
   while [[ ${input2} == "" ]]
     do
     $ECHO -n "Enter a task profile value for the from the list above: ";
     read -u0 input2;
   done

   while [[ ${input3} == "" ]]
     do
     $ECHO -n "Enter a value for the target: ";
     read -u0 input3;
   done


   while [[ ${input4} == "" ]]
     do
     $ECHO -n "Enter a value for the ecim role: ";
     read -u0 input4;
   done


   $ECHO -n "Enter a value for the group description:  (<Enter> for null): ";
   read -u0 input5;

   groupName=$input1;
   taskProfile=$input2;
   target=$input3;
   ecimRole=$input4;
   groupDesc=$input5;

}


#########################################################
# Main Program
#########################################################

SetEnvironment

if [ $? -ne 0 ] ; then
  LogAndDisplay "ERROR: Main - Failed to set the environment"
  exit 1
fi

if [ $# -eq 0 ]; then
    Usage
    exit 1
fi
while [ $# -gt 0 ];
do
    case "$1" in
    	-h|-help)
            Usage
            exit 0
            ;;
       -list)
             command="-list"
             list_type="$2"
              case $2 in
                 users)
                   shift 2
                   ;;
                 m2musers)
                   shift 2
                   ;;
                 enmRoles)
                   shift 2
                   ;;
		 scopes)
		   shift 2
		   ;;
		 user)
                   AskForUserName
                   shift 2
                   ;;
		 enmRole)
                   AskForRoleName
                   shift 2
                   ;;
		 groups)
                   shift 2
                   ;;
		 group)
                   AskForGroupName
                   shift 2
                   ;;
		 taskProfiles)
                   shift 2
                   ;;
		 scope)
		   AskForScopeName
		   shift 2
		   ;;
	         *)
                  LogAndDisplay "ERROR: Main - Syntax error: Unrecognized or missing argument" 
                  Usage
                  exit 1
                  ;;
               esac
             ;;
    
       -add)
            command="-add"
            add_type="$2"
              case "$2" in
                 user)
		   AskForUserData
		   AskForConfirmation
		   while [[ "$RESP" != "y" ]] ; do
		      if [[ ${RESP} == "q" ]] 
                        then
                        LogAndDisplay "WARNING: Main - Exiting program before new user data is saved."       
                        LogAndDisplayNL ""
                        LogAndDisplay "WARNING: Main - No changes made to the ldap directory server."
                        LogAndDisplayNL ""
	                exit 
                      elif [[ $RESP == "" ||  $RESP == "n" ]]
                         then
                        AskForUserData
	                AskForConfirmation
                     else
                       # Otherwise it was an invalid option chosen 
                       LogAndDisplay "Invalid option was entered.  Please try again"
                       LogAndDisplay "Is all of the above information correct (y/n/q) (<Enter> for n)? "
                       read  -u0 RESP;
                       LogAndDisplayNL ""
                      fi

                 done
                      shift 1
                   ;;
		   
                  enmRole)
		   AskForRoleData
		   AskForConfirmation
		   while [[ "$RESP" != "y" ]] ; do
		      if [[ ${RESP} == "q" ]] 
                        then
                        LogAndDisplay "WARNING: Main - Exiting program before new role data is saved."
                        LogAndDisplayNL ""
                        LogAndDisplay "WARNING: Main - No changes made to the ldap directory server."                       
                        LogAndDisplayNL ""
	                exit 
                      elif [[ $RESP == "" ||  $RESP == "n" ]]
                         then
                        AskForRoleData
	                AskForConfirmation
                     else
                       # Otherwise it was an invalid option chosen 
                       LogAndDisplay "Invalid option was entered.  Please try again"
                       LogAndDisplay "Is all of the above information correct (y/n/q) (<Enter> for n)? "
                       read  -u0 RESP;
                       LogAndDisplayNL "" 
                      fi

                   done
                       shift 1 
                   ;;
              
                  group)
                  $ECHO "Hit the add group"
                  AskForGroupData
		  AskForConfirmation
		  while [[ "$RESP" != "y" ]] ; do
		      if [[ ${RESP} == "q" ]] 
                        then
                        LogAndDisplay "WARNING: Main - Exiting program before new group data is saved."
                        LogAndDisplayNL ""
                        LogAndDisplay "WARNING: Main - No changes made to the ldap directory server."                      
                        LogAndDisplayNL ""
	                exit 
                      elif [[ $RESP == "" ||  $RESP == "n" ]]
                         then
                        AskForGroupData
	                AskForConfirmation
                     else
                       # Otherwise it was an invalid option chosen
                       LogAndDisplay "Invalid option was entered.  Please try again"
                       LogAndDisplay "Is all of the above information correct (y/n/q) (<Enter> for n)? " 
                       read  -u0 RESP;
                       LogAndDisplayNL "" 
                      fi

                  done
                      shift 1
                   ;;	

                  scope)
                   AskForScopeData
                   AskForConfirmation
                   while [[ "$RESP" != "y" ]] ; do
                      if [[ ${RESP} == "q" ]]
                        then
                        LogAndDisplay "WARNING: Main - Exiting program before new scope data is saved."
                        LogAndDisplayNL ""
                        LogAndDisplay "WARNING: Main - No changes made to the ldap directory server."
                        LogAndDisplayNL ""
                        exit
                      elif [[ $RESP == "" ||  $RESP == "n" ]]
                         then
                        AskForScopeData
                        AskForConfirmation
                     else
                       # Otherwise it was an invalid option chosen
                       LogAndDisplay "Invalid option was entered.  Please try again"
                       LogAndDisplay "Is all of the above information correct (y/n/q) (<Enter> for n)? "
                       read  -u0 RESP;
                       LogAndDisplayNL ""
                      fi

                   done
                       shift 1
                   ;;

                 *)
                  LogAndDisplay "ERROR: Main - Syntax error: Unrecognized or missing argument" 
                  Usage 
                  exit 1
                  ;;
             esac
             shift 1
             ;;

       -update)
            command="-update"
            update_type="$2"
              case "$2" in
                 userPswd)
                   AskForUserName
		   AskForUserPassword
		   AskForConfirmation
		   while [[ "$RESP" != "y" ]] ; do
		      if [[ ${RESP} == "q" ]] 
                        then
                        LogAndDisplay "WARNING: Main - Exiting program before new user data is saved."
                        LogAndDisplayNL ""
                        LogAndDisplay "WARNING: Main - No changes made to the ldap directory server."
                        LogAndDisplayNL ""
	                exit 
                      elif [[ $RESP == "" ||  $RESP == "n" ]]
                         then
                        AskForUserName
		        AskForUserPassword
		        AskForConfirmation
                     else
                       # Otherwise it was an invalid option chosen 
                       LogAndDisplay "Invalid option was entered.  Please try again"
                       LogAndDisplay "Is all of the above information correct (y/n/q) (<Enter> for n)? "
                       read  -u0 RESP;
                       LogAndDisplayNL ""
                      fi

                   done
                      shift 1
                   ;;
                 *)
                  LogAndDisplay "ERROR: Main - Syntax error: Unrecognized or missing argument" 
                  Usage
                  exit 1
                  ;;
             esac
             shift 1
             ;;

       -delete)
            command="-delete"
            delete_type="$2"
              case $2 in
                 user)
                   AskForUserName
                   shift 1
                   ;;
		 enmRole)
                   AskForRoleName
                   shift 1
                   ;;
		 group)
                   AskForGroupName
                   shift 1
                   ;;
                 scope)
                   AskForScopeName
                   shift 1
                   ;;
                 *)
                  LogAndDisplay "ERROR: Main - Syntax error: Unrecognized or missing argument" 
                  Usage
                  exit 1
                    
             esac
             shift 1
             ;;

       -assign)
            command="-assign"
            assign_type="$2"
              case $2 in
                  enmRole)
                   AskForUserName
		   AskForRoleName
		   AskForConfirmation
		   while [[ "$RESP" != "y" ]] ; do
		      if [[ ${RESP} == "q" ]] 
                        then
                        LogAndDisplay "WARNING: Main - Exiting program before new role data is saved."
                        LogAndDisplayNL ""
                        LogAndDisplay "WARNING: Main - No changes made to the ldap directory server."
                        LogAndDisplayNL ""
	                exit 
                      elif [[ $RESP == "" ||  $RESP == "n" ]]
                         then
                   AskForUserName
		   AskForRoleName
		   AskForConfirmation
                      else
                        # Otherwise it was an invalid option chosen 
                        LogAndDisplay "Invalid option was entered.  Please try again"
                        LogAndDisplay "Is all of the above information correct (y/n/q) (<Enter> for n)? "
                        read  -u0 RESP;
                        LogAndDisplayNL "" 
                      fi
                   done
                   shift 1 
                   ;;

		 group)
                   AskForUserName
                   AskForGroupName
                   shift 1
                   ;;

                  scope)
                   AskForUserName
                   AskForScopeName
                   AskForConfirmation
                   while [[ "$RESP" != "y" ]] ; do
                      if [[ ${RESP} == "q" ]]
                        then
                        LogAndDisplay "WARNING: Main - Exiting program before new scope data is saved."
                        LogAndDisplayNL ""
                        LogAndDisplay "WARNING: Main - No changes made to the ldap directory server."
                        LogAndDisplayNL ""
                        exit
                      elif [[ $RESP == "" ||  $RESP == "n" ]]
                         then
                   AskForUserName
                   AskForScopeName
                   AskForConfirmation
                      else
                        # Otherwise it was an invalid option chosen
                        LogAndDisplay "Invalid option was entered.  Please try again"
                        LogAndDisplay "Is all of the above information correct (y/n/q) (<Enter> for n)? "
                        read  -u0 RESP;
                        LogAndDisplayNL ""
                      fi
                   done
                   shift 1
                   ;;

                 *)
                  LogAndDisplay "ERROR: Main - Syntax error: Unrecognized or missing argument" 
                  Usage
                  exit 1
                    
             esac
             shift 1
             ;;


       -unassign)
            command="-unassign"
            unassign_type="$2"
              case $2 in
                  enmRole)
                   AskForUserName
		   AskForRoleName
		   AskForConfirmation
		   while [[ "$RESP" != "y" ]] ; do
		      if [[ ${RESP} == "q" ]] 
                        then
                        LogAndDisplay "WARNING: Main - Exiting program before new user and role data is saved."
                        LogAndDisplayNL ""
                        LogAndDisplay "WARNING: Main - No changes made to the ldap directory server."
                        LogAndDisplayNL ""
	                exit 
                      elif [[ $RESP == "" ||  $RESP == "n" ]]
                         then
                             AskForUserName
		             AskForRoleName
		             AskForConfirmation
                      else
                        # Otherwise it was an invalid option chosen 
                        LogAndDisplay "Invalid option was entered.  Please try again"
                        LogAndDisplay "Is all of the above information correct (y/n/q) (<Enter> for n)? "
                        read  -u0 RESP;
                        LogAndDisplayNL ""
                      fi
                   done
                   shift 1 
                   ;;

		 group)
                   AskForUserName
                   AskForGroupName
		   AskForConfirmation
		   while [[ "$RESP" != "y" ]] ; do
		      if [[ ${RESP} == "q" ]] 
                        then
                        LogAndDisplay "WARNING: Main - Exiting program before new user and group data is saved."
                        LogAndDisplayNL ""
                        LogAndDisplay "WARNING: Main - No changes made to the ldap directory server."
                        LogAndDisplayNL ""
	                exit 
                      elif [[ $RESP == "" ||  $RESP == "n" ]]
                         then
                             AskForUserName
		             AskForGroupName
		             AskForConfirmation
                      else
                        # Otherwise it was an invalid option chosen 
                        LogAndDisplay "Invalid option was entered.  Please try again"
                        LogAndDisplay "Is all of the above information correct (y/n/q) (<Enter> for n)? "
                        read  -u0 RESP;
                        LogAndDisplayNL ""
                      fi
                   done
                   shift 1
                   ;;

                  scope)
                   AskForUserName
                   AskForScopeName
                   AskForConfirmation
                   while [[ "$RESP" != "y" ]] ; do
                      if [[ ${RESP} == "q" ]]
                        then
                        LogAndDisplay "WARNING: Main - Exiting program before new user and scope data is saved."
                        LogAndDisplayNL ""
                        LogAndDisplay "WARNING: Main - No changes made to the ldap directory server."
                        LogAndDisplayNL ""
                        exit
                      elif [[ $RESP == "" ||  $RESP == "n" ]]
                         then
                             AskForUserName
                             AskForScopeName
                             AskForConfirmation
                      else
                        # Otherwise it was an invalid option chosen
                        LogAndDisplay "Invalid option was entered.  Please try again"
                        LogAndDisplay "Is all of the above information correct (y/n/q) (<Enter> for n)? "
                        read  -u0 RESP;
                        LogAndDisplayNL ""
                      fi
                   done
                   shift 1
                   ;;

                 *)
                  LogAndDisplay "ERROR: Main - Syntax error: Unrecognized or missing argument" 
                  Usage
                  exit 1
                    
             esac
             shift 1
             ;;
       *)
         LogAndDisplay "ERROR: Main - Syntax error: Unrecognized or missing argument" 
         Usage
         exit 1
    esac
  done

if [ "$command" = "-list" ]; then
    if [ $list_type = "users" ]; then
       ListUsers
       rc=$?
       
       if [ $rc -eq 0 ] ; then
         Log "INFO: Main - ListUsers completed successfully"
         LogAndDisplayNL ""
       else
         LogAndDisplay "ERROR: Main - ListUsers failed"
         LogAndDisplayNL ""
       fi  
    elif [ $list_type = "m2musers" ]; then
       ListM2MUsers
       rc=$?

       if [ $rc -eq 0 ] ; then
         Log "INFO: Main - ListM2MUsers completed successfully"
         LogAndDisplayNL ""
       else
         LogAndDisplay "ERROR: Main - ListM2MUsers failed"
         LogAndDisplayNL ""
       fi  
    elif [ $list_type = "enmRoles" ]; then
       ListRoles
       rc=$?

       if [ $rc -eq 0 ] ; then
         Log "INFO: Main - ListRoles completed successfully"
         LogAndDisplayNL ""
       else
         LogAndDisplay "ERROR: Main - ListRoles failed"
         LogAndDisplayNL ""
       fi  
    elif [ $list_type = "user" ]; then
       ListUser 
       rc=$?
     
       if [ $rc -eq 0 ] ; then
         Log "INFO: Main - ListUser completed successfully"
         LogAndDisplayNL ""
       else
         LogAndDisplay "ERROR: Main - ListUser failed"
         LogAndDisplayNL ""
       fi   
    elif [ $list_type = "enmRole" ]; then
       ListRole
       rc=$?
    
       if [ $rc -eq 0 ] ; then
         Log "INFO: Main - ListRole completed successfully"
         LogAndDisplayNL ""
       else
         LogAndDisplay "ERROR: Mian - ListRole failed"
         LogAndDisplayNL ""
       fi   
    elif [ $list_type = "groups" ]; then
       ListGroups
       rc=$?
   
       if [ $rc -eq 0 ] ; then
         Log "INFO: Main - ListGroups completed successfully"
         LogAndDisplayNL ""
       else
         LogAndDisplay "ERROR: Main - ListGroups failed"
         LogAndDisplayNL ""
       fi   
    elif [ $list_type = "group" ]; then
       ListGroup
       rc=$?
  
       if [ $rc -eq 0 ] ; then
         Log "INFO: Main - ListGroup completed successfully"
         LogAndDisplayNL ""
       else
         LogAndDisplay "ERROR: Main - ListGroup failed"
         LogAndDisplayNL ""
       fi   
    elif [ $list_type = "taskProfiles" ]; then
       ListTaskProfiles
       rc=$?
 
       if [ $rc -eq 0 ] ; then
         Log "INFO: Main - ListTaskProfiles completed successfully"
         LogAndDisplayNL ""
       else
         LogAndDisplay "ERROR: Main - ListTaskProfiles failed"
         LogAndDisplayNL ""
       fi   
    elif [ $list_type = "scopes" ]; then
       ListScopes
       rc=$?

       if [ $rc -eq 0 ] ; then
         Log "INFO: Main - ListScopes completed successfully"
         LogAndDisplayNL ""
       else
         LogAndDisplay "ERROR: Main - ListScopes failed"
         LogAndDisplayNL ""
       fi
    elif [ $list_type = "scope" ]; then
       ListScope
       rc=$?

       if [ $rc -eq 0 ] ; then
         Log "INFO: Main - ListScope completed successfully"
         LogAndDisplayNL ""
       else
         LogAndDisplay "ERROR: Main - ListScope failed"
         LogAndDisplayNL ""
       fi
    fi
elif [ "$command" = "-add" ]; then
    if [ "$add_type" = "user" ]; then
       AddUser 
       rc=$?

       if [ $rc -eq 0 ] ; then
         Log "INFO: Main - AddUser completed successfully"
         LogAndDisplayNL ""
       else
         LogAndDisplay "ERROR: Main - AddUser failed"
         LogAndDisplayNL ""
       fi   
    elif [ "$add_type" = "enmRole" ]; then
       AddRole
       rc=$?

       if [ $rc -eq 0 ] ; then
         Log "INFO: Main - AddRole completed successfully"
         LogAndDisplayNL ""
       else
         LogAndDisplay "ERROR: Main - AddRole failed"
         LogAndDisplayNL ""
       fi     
    elif [ "$add_type" = "group" ]; then
       AddGroup
       rc=$?

       if [ $rc -eq 0 ] ; then
         Log "INFO: Main - AddGroup completed successfully"
         LogAndDisplayNL ""
       else
         LogAndDisplay "ERROR: Main - AddGroup failed"
         LogAndDisplayNL ""
       fi
    elif [ "$add_type" = "scope" ]; then
       AddScope
       rc=$?

       if [ $rc -eq 0 ] ; then
         Log "INFO: Main - AddScope completed successfully"
         LogAndDisplayNL ""
       else
         LogAndDisplay "ERROR: Main - AddScope failed"
         LogAndDisplayNL ""
       fi    
    fi
elif [ "$command" = "-update" ]; then
    if [ "$update_type" = "userPswd" ]; then
       UpdateUserPassword 
       rc=$?

       if [ $rc -eq 0 ] ; then
         Log "INFO: Main - UpdateUserPswd completed successfully"
         LogAndDisplayNL ""
       else
         LogAndDisplay "ERROR: Main - UpdateUserPswd failed"
         LogAndDisplayNL ""
       fi   
    fi
   
elif [ "$command" = "-assign" ]; then
    if [ "$assign_type" = "enmRole" ]; then
     #  UpdateUserPassword 
       AssignEnmRole
       rc=$?

       if [ $rc -eq 0 ] ; then
         Log "INFO: Main - AssignEnmRole completed successfully"
         LogAndDisplayNL ""
       else
         LogAndDisplay "ERROR: Main - AssignEnmRole failed"
         LogAndDisplayNL ""
       fi   
    elif [ "$assign_type" = "group" ]; then
       AssignGroup
       rc=$?

       if [ $rc -eq 0 ] ; then
         Log "INFO: Main - AssignGroup completed successfully"
         LogAndDisplayNL ""
       else
         LogAndDisplay "ERROR: Main - AssignGroup failed"
         LogAndDisplayNL ""
       fi     
    elif [ "$assign_type" = "scope" ]; then
       AssignScope
       rc=$?

       if [ $rc -eq 0 ] ; then
         Log "INFO: Main - AssignScope completed successfully"
         LogAndDisplayNL ""
       else
         LogAndDisplay "ERROR: Main - AssignScope failed"
         LogAndDisplayNL ""
       fi
    fi
    
elif [ "$command" = "-unassign" ]; then
    if [ "$unassign_type" = "enmRole" ]; then
       UnassignEnmRole
       rc=$?

       if [ $rc -eq 0 ] ; then
         Log "INFO: Main - UnassignEnmRole completed successfully"
         LogAndDisplayNL ""
       else
         LogAndDisplay "ERROR: Main - UnassignEnmRole failed"
         LogAndDisplayNL ""
       fi   
    elif [ "$unassign_type" = "group" ]; then
       UnassignGroup
       rc=$?

       if [ $rc -eq 0 ] ; then
         Log "INFO: Main - UnassignGroup completed successfully"
         LogAndDisplayNL ""
       else
         LogAndDisplay "ERROR: Main - UnassignGroup failed"
         LogAndDisplayNL ""
       fi     
    elif [ "$unassign_type" = "scope" ]; then
       UnassignScope
       rc=$?

       if [ $rc -eq 0 ] ; then
         Log "INFO: Main - UnassignScope completed successfully"
         LogAndDisplayNL ""
       else
         LogAndDisplay "ERROR: Main - UnassignScope failed"
         LogAndDisplayNL ""
       fi
    fi
 
elif [ "$command" = "-delete" ]; then
    if [ $delete_type = "user" ]; then
       #ListUser
       LogAndDisplay "WARNING: Are you sure you want to delete this user ? (yes/no):"
       GetUserResponse
       if [ "$ANSWER" == "n" ] ; then
          LogAndDisplayNL ""
          LogAndDisplay "INFO: User selected to exit .....Exiting from the tool."
          LogAndDisplayNL ""
          exit
       elif [ "$ANSWER" == "y" ] ; then
          LogAndDisplayNL ""
          LogAndDisplay "INFO: User selected to proceed....."
          LogAndDisplayNL ""
          DeleteUser
          rc=$?

          if [ $rc -eq 0 ] ; then
            Log "INFO: Main - DeleteUser completed successfully"
            LogAndDisplayNL ""
          else
            LogAndDisplay "ERROR: Main - DeleteUser failed"
            LogAndDisplayNL ""
          fi    
       fi
    elif [ $delete_type = "enmRole" ]; then
       ListRole
       LogAndDisplay "WARNING: Are you sure you want to delete this role ? (yes/no):"
       GetUserResponse
       if [ "$ANSWER" == "n" ] ; then
         LogAndDisplayNL ""
         LogAndDisplay "INFO: User selected to exit .....Exiting from the tool."
         LogAndDisplayNL ""
         exit
       elif [ "$ANSWER" == "y" ] ; then
         LogAndDisplayNL ""
         LogAndDisplay "INFO: User selected to proceed....."
         LogAndDisplayNL ""
         DeleteRole
         rc=$?

         if [ $rc -eq 0 ] ; then
           Log "INFO: Main -  DeleteRole completed successfully"
           LogAndDisplayNL ""
         else
           LogAndDisplay "ERROR: Main - DeleteRole failed"
           LogAndDisplayNL ""
         fi   
       fi

    elif [ $delete_type = "group" ]; then
       ListGroup
       LogAndDisplay "WARNING: Are you sure you want to delete this group ? (yes/no):"
       GetUserResponse
       if [ "$ANSWER" == "n" ] ; then
         LogAndDisplayNL ""
         LogAndDisplay "INFO: User selected to exit .....Exiting from the tool."
         LogAndDisplayNL ""
         exit
       elif [ "$ANSWER" == "y" ] ; then
         LogAndDisplayNL ""
         LogAndDisplay "INFO: User selected to proceed....."
         LogAndDisplayNL ""
         DeleteGroup
         rc=$?

         if [ $rc -eq 0 ] ; then
           Log "INFO: Main - DeleteGroup completed successfully"
           LogAndDisplayNL ""
         else
           LogAndDisplay "ERROR: Main - DeleteGroup failed"
           LogAndDisplayNL ""
         fi   
       fi

    elif [ $delete_type = "scope" ]; then
       ListScope
       LogAndDisplay "WARNING: Are you sure you want to delete this scope? (yes/no):"
       GetUserResponse
       if [ "$ANSWER" == "n" ] ; then
         LogAndDisplayNL ""
         LogAndDisplay "INFO: User selected to exit .....Exiting from the tool."
         LogAndDisplayNL ""
         exit
       elif [ "$ANSWER" == "y" ] ; then
         LogAndDisplayNL ""
         LogAndDisplay "INFO: User selected to proceed....."
         LogAndDisplayNL ""
         DeleteScope
         rc=$?

         if [ $rc -eq 0 ] ; then
           Log "INFO: Main -  DeleteScope completed successfully"
           LogAndDisplayNL ""
         else
           LogAndDisplay "ERROR: Main - DeleteScope failed"
           LogAndDisplayNL ""
         fi  
       fi

    fi
fi

exit 0
