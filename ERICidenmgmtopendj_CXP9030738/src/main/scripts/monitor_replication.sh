#!/bin/bash

################################################################################
# Copyright (c) 2019 Ericsson, Inc. All Rights Reserved.
# This script checks opendj replication writing and then deleting an object
#
# Author: Alessandro DaCanal, Luciano Gemme, Marco Cappelli
#
# mod: 01/01/2024
#
###############################################################################

# optional parameter, if present the script will not manage the lock file
# (to be used only in manual mode)
ONDOCKER=false
if [ ! -z "$1" ] ; then
   if [ "$1" == "docker" ] ; then
      echo "DOCKER MODE"
      ONDOCKER=true
      shift
   fi
fi

# optional parameter, if present the script can be killed by other runs
# (to be used only if launched by CRON)
CRON_MODE="CRON_MODE"
ONCRON=false
if [ ! -z "$1" ] ; then
   if [ "$1" == "CRON_MODE" ] ; then
      #echo "CRON MODE"
      ONCRON=true
   fi
fi

# remove dash to enable debug DEBUG
#set -x

# for OPENDJ6.5 minus a option is not more allowed
#LDAPOPTS="-a"
LDAPOPTS=""

# Source variables file to get value for SERVICE_INSTANCE_NAME
if [ -f /opt/ericsson/com.ericsson.oss.security/idenmgmt/opendj/variables ]; then
    . /opt/ericsson/com.ericsson.oss.security/idenmgmt/opendj/variables
fi

IDENMGMT_ROOT=/opt/ericsson/com.ericsson.oss.security/idenmgmt
OPENDJ_PASSKEY=/ericsson/tor/data/idenmgmt/opendj_passkey

#definition of commands
OPENSSL=/usr/bin/openssl
CUT=/bin/cut
RM='/bin/rm -rf'
PING=/bin/ping
CAT=/bin/cat
GREP=/bin/grep
VGREP='/bin/grep -v'
WCL='/usr/bin/wc -l'
PS=/bin/ps
TAIL=/usr/bin/tail
ECHO=/bin/echo
AWK=/usr/bin/awk
KILL='/bin/kill -9'
MV=/bin/mv

source $IDENMGMT_ROOT/opendj/bin/common.sh
if [ $? -ne 0 ]; then
   echo "ERROR: Failed to source $IDENMGMT_ROOT/opendj/bin/common.sh"
   exit 1
fi

DM_PWD=""

################################################################################
# Function: getENMsets
# Description: This function get the infos about the ENM environment like side
# Parameters: none
# Return: 0 (Succeed)
#         1 (Failed)
################################################################################

getENMsets(){

OPENDJHOST0="opendjhost0"
OPENDJHOST1="opendjhost1"
LDAP_LOCAL="ldap-local"
LDAP_PEER="ldap-remote"

if [ "$cENM_DEPLOYMENT" != TRUE ] ; then
   # pENM and vENM
   # global properties that are either required by SSO or defined in the SED.
   # we need the global.properties file
   GLOBAL_PROPERTY_FILE=/ericsson/tor/data/global.properties
   if [ ! -r "$GLOBAL_PROPERTY_FILE" ]; then
       return 1
   fi
   . $GLOBAL_PROPERTY_FILE >/dev/null 2>&1

   IsOnCloud
   if [ $? == 0 ] ; then
      # vENM

      OPENDJ_ROOT=/ericsson/opendj/opendj
      OPENDJ_ROOT_PARENT=/ericsson/opendj
      LDAP_HOST=$SERVICE_INSTANCE_NAME
      if [ $LDAP_HOST == "opendj-1" ]; then
         LDAP_PEER="opendj-2"
      else
         LDAP_PEER="opendj-1"
      fi
      LOCAL_LDAP_HOST=$LDAP_HOST
      REMOTE_LDAP_HOST=$LDAP_PEER
      OPENDJHOST0="opendj-1"
      OPENDJHOST1="opendj-2"
   elif [ `cat /etc/hosts | egrep cloud-db |wc -l` != 0 ]; then
      #vapp
      ENMTYPE=pENM
      OPENDJ_ROOT=/opt/opendj
      OPENDJ_ROOT_PARENT=/opt/
      LDAP_HOST=$LDAP_LOCAL
      OPENDJHOST0=$LDAP_LOCAL
      OPENDJHOST1=$LDAP_PEER
   else
      # pENM

      OPENDJ_ROOT=/opt/opendj
      OPENDJ_ROOT_PARENT=/opt/

      $HOST_NAME -I | $GREP $(getent hosts $OPENDJHOST0 | cut -d' ' -f1)
      if [ $? != 0 ] ; then
         LDAP_HOST=$OPENDJHOST1
         LDAP_PEER=$OPENDJHOST0
         LOCAL_LDAP_HOST=$OPENDJHOST1
         REMOTE_LDAP_HOST=$OPENDJHOST0
      else
         LDAP_HOST=$OPENDJHOST0
         LDAP_PEER=$OPENDJHOST1
         LOCAL_LDAP_HOST=$OPENDJHOST0
         REMOTE_LDAP_HOST=$OPENDJHOST1
      fi
   fi
else
   # cENM
   OPENDJ_ROOT=/ericsson/opendj/opendj
   OPENDJ_ROOT_PARENT=/ericsson/opendj
   SIDE=$(hostname | grep 1 | wc -l)
   if [ $SIDE == 0 ];then
      LOCAL_LDAP_HOST=$DS_SVC"-0".$DS_SVC
      REMOTE_LDAP_HOST=$DS_SVC"-1".$DS_SVC
   else
      LOCAL_LDAP_HOST=$DS_SVC"-1".$DS_SVC
      REMOTE_LDAP_HOST=$DS_SVC"-0".$DS_SVC
   fi
   LDAP_HOST=$LOCAL_LDAP_HOST
   LDAP_PEER=$REMOTE_LDAP_HOST

   OPENDJHOST0=$DS_SVC"-0".$DS_SVC
   OPENDJHOST1=$DS_SVC"-1".$DS_SVC

fi

# OpenDJ tools
LDAPSEARCH=$OPENDJ_ROOT/bin/ldapsearch
DSCONFIG=$OPENDJ_ROOT/bin/dsconfig
DSREPLICATION=$OPENDJ_ROOT/bin/dsrepl
# Directory manager, basedn and ports
# from datastore.properties
PROPS_FILE=$IDENMGMT_ROOT/config/datastore.properties
LDAP_PORT=`$GREP ldapsPort $PROPS_FILE | cut -d= -f2`
DM_DN=`$GREP rootUserDN  $PROPS_FILE | cut -d= -f2-`
ADMIN_CONNECTOR_PORT=`$GREP adminConnectorPort $PROPS_FILE | cut -d= -f2`
BASE_DN=$COM_INF_LDAP_ROOT_SUFFIX

return 0

}


# use of environment variables 
## LOCAL_LDAP_HOST="ldap-local"
## REMOTE_LDAP_HOST="ldap-remote"
# (use these ones for DOCKER)
if [ $ONDOCKER == true ]
then
   LOCAL_LDAP_HOST="$LDAP_LOCAL"
   REMOTE_LDAP_HOST="$LDAP_REMOTE"
fi

# deployment paths
SHARE_ROOT=/ericsson/tor/data

LOG_DIR="/var/log/opendj"
LOG_FILE_FILTER="$LOG_DIR/opendj-check-replication-opendj-"
LOG_FILE="$LOG_FILE_FILTER`/bin/date "+%F:%H:%M:%S%:z"`.log"

# for elapsed time story
MON_REPL_CNTFILE="monitorreplication.cnt"
MON_REPL_ENTRY=48

searchObject="(objectclass=subentry)"
pingObject="(uid=Administrator)"

# constants
MAX_COUNTER=3
UPGRADE_TIMEOUT=10
NOENTRY_CODE=32
ALREADYEXISTS_CODE=68

###########################################################################################
# Function: PingHost
# Description: This function ping the host
# Parameters: None
# Return:  0 everything ok, 1 fail
#
# (could be move to common.sh)
#
###########################################################################################
PingHost()
{
  ldap_host=$1
  LogMessageDotEcho "INFO: ping $ldap_host"
  $PING $ldap_host -c 2 >> $LOG_FILE
  if [ $? != 0 ] ; then
   	return 1
  fi
  return 0
}

###########################################################################################
# Function: CreateTestReplication
# Description: This function creates a object for testing replication between opendj1 and opendj2
# Parameters: LDAP_HOST
# Return:  0 everything ok, 1 fail
###########################################################################################
CreateTestReplication()
{
  ldap_host=$1
  LogMessageDotEcho "INFO: CreateTestReplication request has been received...... Processing request"

  #echo $DM_DN $DM_PWD $REPLICATION_USER_NAME $BASE_DN

  echo "$createData" | $LDAPMODIFY $LDAPOPTS -h "$ldap_host" -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" >> $LOG_FILE

  rr=${PIPESTATUS[1]}
  if [ $rr -ne 0 ] && [ $rr -ne $ALREADYEXISTS_CODE ] ; then
    LogMessageDotEcho "ERROR: Failed to add new $REPLICATION_OBJECTNAME and the error code from DS is [$rr]"
    #error "Failed to add test object and the error code from DS is [$rr]"
    return 1
  fi

  LogMessageDotEcho "DEBUG: CreateTestReplication ....... completed"

  return 0

}

###########################################################################################
# Function: CheckLdapPing
# Description: This function check ldap server is working and configured
# Parameters: mode LDAP_HOST
# Return:  0 everything ok, 1 fail
###########################################################################################
CheckLdapPing()
{
  ldap_host=$1

  LogMessageDotEcho "INFO: CheckLdapPing $ldap_host request has been received...... Processing request"

  $LDAPSEARCH -h $ldap_host -p 1636 --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" -b "$BASE_DN" "$pingObject" >> $LOG_FILE

  rr=$?
  if [ $rr -ne 0 ] ; then
    LogMessageDotEcho "ERROR: Failed to ldap ping $local_remote and the error code from DS is [$rr]"
    #error "Failed to ldap ping $local_remote and the error code from DS is [$rr]"
    return 1
  fi

  LogMessageDotEcho "DEBUG: CheckLdapPing $ldap_host ...... completed"

  return 0

}


###########################################################################################
# Function: CheckTestReplication
# Description: This function check the presence of object for testing replication between opendj1 and opendj2
# Parameters: mode LDAP_HOST
# Return:  0 everything ok, 1 fail
###########################################################################################
CheckTestReplication()
{
  local_remote=$1
  ldap_host=$2

  LogMessageDotEcho "INFO: CheckTestReplication $local_remote request has been received...... Processing request"

  $LDAPSEARCH -h $ldap_host -p 1636 --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" -b "$objectBase" "$searchObject" >> $LOG_FILE

  rr=$?
  if [ $rr -ne 0 ] ; then
    LogMessageDotEcho "ERROR: Failed to find new $REPLICATION_OBJECTNAME in $local_remote and the error code from DS is [$rr]"
    #error "Failed to find $REPLICATION_OBJECTNAME in $local_remote and the error code from DS is [$rr]"
    return 1
  fi

  LogMessageDotEcho "DEBUG: CheckTestReplication $local_remote ...... completed"

  return 0

}



###########################################################################################
# Function: DeleteTestReplication
# Description: This function delete the object for testing replication between opendj1 and opendj2
# Parameters: mode LDAP_HOST
# Return:  0 everything ok, 1 fail
###########################################################################################
DeleteTestReplication()
{
  local_remote=$1
  ldap_host=$2

  LogMessageDotEcho "INFO: DeleteTestReplication $local_remote request has been received...... Processing request"

  $LDAPDELETE -Z -X -h $ldap_host -p 1636 -D "$DM_DN" -w "$DM_PWD" --no-prompt "$objectBase" >> $LOG_FILE 2>&1

  rr=$?
  if [ $rr -ne 0 ] ; then
    if [ $rr -eq $NOENTRY_CODE ] ; then
       LogMessageDotEcho "DEBUG: delete new $REPLICATION_OBJECTNAME in $local_remote : no such entry"
    else 
       LogMessageDotEcho "ERROR: Failed to delete new $REPLICATION_OBJECTNAME in $local_remote and the error code from DS is [$rr]"
       #error "Failed to delete $REPLICATION_OBJECTNAME in $local_remote and the error code from DS is [$rr]"
       return 1
    fi
  fi

  LogMessageDotEcho "DEBUG: DeleteTestReplication $local_remote ...... completed"

  return 0

}


###########################################################################################
# Function: CleanLogFilesAndKillOldProcesses
# Description: This function removes all old files in /var/log/opendj and kills all hang process 
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################
CleanLogFilesAndKillOldProcesses()
{
    #remove old log files in /var/log/opendj
    #find ${LOG_FILE_FILTER}* -type f -mtime +3 | xargs rm
    ${RM} ${LOG_FILE_FILTER}*   
    LogMessageDotEcho "INFO: monitor_replication.sh : Removed all old log files"

    local pid_strings;
    pid_strings=$($PS -ef | $GREP  "monitor_replication.sh" | grep $CRON_MODE | $VGREP grep | $VGREP $$ | $AWK '{printf  "%s ", $2  }'  )
           
    LogMessageDotEcho "INFO: Pid found are= $pid_strings"
                   
    declare -a pid_split_array
    local IFS=' ' pid_split_array=($pid_strings)
                           
    LogMessageDotEcho "INFO: Pid size is ${#pid_split_array[@]}"
                               
    if [[ "${#pid_split_array[@]}" -eq 0 ]] ; then
        LogMessageDotEcho  "INFO: No pids found to kill returning"
        return 0;
    fi
                                                           
    for element in "${pid_split_array[@]}"
        do
            if [[ ( $element -ne $$ ) ]]; then
                     $KILL  "$element" 2>/dev/null
                     LogMessageDotEcho  "INFO: Kill hang process $element"
            fi                                               
        done

    return 0;

}                                                                                                                             

###############################################################################
# Main Program
# Parameters: None
###############################################################################

source $IDENMGMT_ROOT/opendj/bin/common.sh
if [ $? -ne 0 ]; then
   echo "ERROR: Failed to source $IDENMGMT_ROOT/opendj/bin/common.sh"
   exit 1
fi
SetLogFile $LOG_DIR $LOG_FILE
if [ $? != 0 ]; then
   echo "ERROR: SetLogFile failed"
   #error "SetLogFile failed"
   exit 1
fi

if [ $ONCRON == false ]
then
   LogMessage "INFO: ...........monitor_replication: manual mode"
fi

getENMsets
if [ $? != 0 ]; then
    echo "ERROR: monitor_replication: getENMsets failed"
    error "monitor_replication: getENMsets failed"
    exit 1
fi

decryptOpendjPasswd
if [ $? != 0 ]; then
    LogMessageNewLine "ERROR: decryptOpendjPasswd failed"
    error "decryptOpendjPasswd failed"
    exit 1
fi

CleanLogFilesAndKillOldProcesses
if [ $? != 0 ] ; then
   LogMessageDotEcho "ERROR: CleanLogFiles failed"
   #error "CleanLogFilesAndKillOldProcesses failed"
   exit 1
fi

LogMessageNewLine "INFO: ...........monitor_replication......START"
info "INFO: ...........monitor_replication......START"
initTime=$SECONDS

# check for single opendj installation
IsSingleOpendj
if [ $? == 0 ] ; then
   #LogMessageDotEcho "monitor_replication: one db node env"
   LogMessageNewLine "INFO: ...........monitor_replication......OK - one db node env : exit 0"
   infoNoEcho "INFO: ...........monitor_replication......OK - one db node env : exit 0"
   echo "ENM_OPENDJ: INFORMATION ( OPENDJ ): INFO: ...........monitor_replication......OK - one db node env : exit 0"
   exit 0
fi

# define opendj root directory on cloud and phy
LDAPMODIFY=$OPENDJ_ROOT/bin/ldapmodify
LDAPSEARCH=$OPENDJ_ROOT/bin/ldapsearch
LDAPDELETE=$OPENDJ_ROOT/bin/ldapdelete

LogMessageDotEcho "LOCAL_LDAP_HOST $LOCAL_LDAP_HOST - REMOTE_LDAP_HOST $REMOTE_LDAP_HOST"

PingHost $LOCAL_LDAP_HOST
if [ $? != 0 ] ; then
   LogMessage "INFO: Ping Local Host failed"
   exit 0
fi
PingHost $REMOTE_LDAP_HOST
if [ $? != 0 ] ; then
   LogMessage "INFO: Ping Remote Host failed"
   exit 0
fi

# check ldap servers
CheckLdapPing $LOCAL_LDAP_HOST
if [ $? != 0 ] ; then
   LogMessage "INFO: Local LDAP server not configured"
   exit 0
fi
CheckLdapPing $REMOTE_LDAP_HOST
if [ $? != 0 ] ; then
   LogMessage "INFO: Remote LDAP server not configured"
   exit 0
fi


#
# TEST OBJECT DATA
#
# use these to use a password policy object
DB_HOSTNAME=`hostname`
REPLICATION_OBJECTNAME=DummyPolicy-$DB_HOSTNAME-$RANDOM
objectBase="cn=$REPLICATION_OBJECTNAME,$BASE_DN"
dummyBase="{base \"ou=dummy\"}"
createData="$(cat << EOT
dn: $objectBase
changetype: add
objectClass: top
objectClass: subentry
objectClass: pwdPolicy
cn: $REPLICATION_OBJECTNAME
pwdAttribute: userPassword
pwdMaxAge: 99
subtreeSpecification: $dummyBase
EOT
)"


CreateTestReplication $LOCAL_LDAP_HOST
if [ $? != 0 ] ; then
   LogMessage "ERROR: CreateTestReplication failed"
   #error "CreateTestReplication failed"
   exit 1
fi

retryCounter=1

while [ $retryCounter -le $MAX_COUNTER ] ; do
    LogMessageDotEcho "INFO: Check opendjreplication in OpenDJ local n $retryCounter"
    CheckTestReplication "local" $LOCAL_LDAP_HOST
    if [ ${?} -ne 0 ] ; then
          retryCounter=$((retryCounter+1))
          # failed: wait and retry
         LogMessageDotEcho "INFO: Wait and retry"
         sleep $UPGRADE_TIMEOUT
    else
      # executed
      retryCounter=100
    fi
done

if [ $retryCounter -ne 100 ] ; then
    LogMessageDotEcho "ERROR: max retry reached: opendjreplication is not present in OpenDJ local"
    DeleteTestReplication "local" $LOCAL_LDAP_HOST
    DeleteTestReplication "remote" $REMOTE_LDAP_HOST
    LogMessageNewLine "ERROR: ...........monitor_replication......FAIL: exit 1"
    infoNoEcho "ERROR: ...........monitor_replication......FAIL: exit 1"
    echo "ENM_OPENDJ: INFORMATION ( OPENDJ ): ERROR: ...........monitor_replication......FAIL: exit 1"
    return 1
fi 

retryCounter=1

while [ $retryCounter -le $MAX_COUNTER ] ; do
    LogMessageDotEcho "INFO: Check opendjreplication in OpenDJ remote n $retryCounter"
    CheckTestReplication "remote" $REMOTE_LDAP_HOST
    if [ ${?} -ne 0 ] ; then
          retryCounter=$((retryCounter+1))
          # failed: wait and retry
          LogMessageDotEcho "INFO: Wait and retry"
          sleep $UPGRADE_TIMEOUT
    else
	
	LogMessageDotEcho " "
	LogMessageDotEcho " >>>>>>> REPLICATION OK <<<<<<<< "
	LogMessageDotEcho " "
  
      # executed
      retryCounter=100
    fi
done

if [ $retryCounter -ne 100 ] ; then
    LogMessageDotEcho "ERROR: max retry reached: opendjreplication is not present in OpenDJ remote"
    DeleteTestReplication "remote" $REMOTE_LDAP_HOST
    DeleteTestReplication "local" $LOCAL_LDAP_HOST
    LogMessageNewLine "ERROR: ...........monitor_replication......FAIL: exit 1"
    infoNoEcho "ERROR: ...........monitor_replication......FAIL: exit 1"
    echo "ENM_OPENDJ: INFORMATION ( OPENDJ ): ERROR: ...........monitor_replication......FAIL: exit 1"
    exit 1
fi

DeleteTestReplication "local" $LOCAL_LDAP_HOST
DeleteTestReplication "remote" $REMOTE_LDAP_HOST

endTime=$SECONDS
elapsedTime=$((endTime - initTime))

LogMessageNewLine "INFO: ...........monitor_replication......OK: exit 0"
infoNoEcho "INFO: ...........monitor_replication......OK: exit 0"
echo "ENM_OPENDJ: INFORMATION ( OPENDJ ): INFO: ...........monitor_replication......OK: exit 0"

#
# update elapsed time log
#

# read last row of log file (the one just written)
lastLogLine=$($TAIL -n 1 $LOG_FILE)
# append data to elapsed time log
lastLogTime=$($ECHO $lastLogLine | $AWK '{print $1}')
lastLogElapsed=$elapsedTime
#check if it is already copied
timeFind=0
if [ -f ${OPENDJ_ROOT}/$MON_REPL_CNTFILE ]; then
      timeFind=$($GREP $lastLogTime $LOG_DIR/$MON_REPL_CNTFILE | $WC -l)
fi
if [ "$timeFind" -eq "0" ]; then 
      # append the log
      $ECHO $lastLogTime " - "$lastLogElapsed" sec." >>  $LOG_DIR/$MON_REPL_CNTFILE
         
      #cat the log to last values
      $CAT $LOG_DIR/$MON_REPL_CNTFILE | $TAIL -n $MON_REPL_ENTRY > $LOG_DIR/dummy
      $MV $LOG_DIR/dummy $LOG_DIR/$MON_REPL_CNTFILE
fi

exit 0
