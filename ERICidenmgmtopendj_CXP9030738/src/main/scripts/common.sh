#!/bin/bash

################################################################################
# Copyright (c) 2014 Ericsson, Inc. All Rights Reserved.
# This script contains the common functions used by all Opendj scripts
# Author: Simohamed Elmajdoubi
# ESN 38708
# 
###############################################################################


######################################################################
# This functions creates the log file
#
######################################################################
SetLogFile()
{

   LOG_DIR=$1
   LOG_FILE=$2
   # Create the log directory if it does not already exist 
   if [ ! -d $LOG_DIR ] ; then
      mkdir -p $LOG_DIR
      if [ $? != 0 ] ; then
         echo "Failed to create $LOG_DIR"
         exit 1
      fi
   fi
   chown opendj:opendj $LOG_DIR
   if [ $? != 0 ] ; then
      echo "Failed to set ownership on $LOG_DIR"
      exit 1
   fi

   # Construct the LOG_ FILE name and create it and validate it can be written
   touch $LOG_FILE 
   if [ $? != 0 ] ; then
      echo "Failed to create $LOG_FILE"
      exit 1
   fi

   # change permission on log file to rw to all
   chmod 666 $LOG_FILE 
   if [ $? != 0 ] ; then
      echo "Failed to set permssions on $LOG_FILE"
      exit 1
   fi

   # change owner to opendj
   chown opendj:opendj $LOG_FILE
   if [ $? != 0 ] ; then
      echo "Failed to change ownership of $LOG_FILE"
      exit 1
   fi
   
   return 0
}

LogMessage()
{ 
   ts=`/bin/date "+%F:%H:%M:%S%:z"`
   msg="$ts: $1"
   echo $msg 
   echo $msg >> $LOG_FILE
}

#
# the following functions are used to limit standad output print
#

LogMessageNewLine()
{ 
   ts=`/bin/date "+%F:%H:%M:%S%:z"`
   msg="$ts: $1"
   echo ""
   echo $msg >> $LOG_FILE
}

LogMessageDotEcho()
{ 
   if [ ! -z ${LOGFILE+x} ]; then
   ts=`/bin/date "+%F:%H:%M:%S%:z"`
   msg="$ts: $1"
   echo -n "."
   echo $msg >> $LOG_FILE
   fi
}

LogMessageNoEcho()
{ 
   ts=`/bin/date "+%F:%H:%M:%S%:z"`
   msg="$ts: $1"
   echo $msg >> $LOG_FILE
}


###########################################################################################
# Function: info
# Description: This function prints info message on syslog
#
# Parameters: Message to print
###########################################################################################
info()
{
  logger -s -t ENM_OPENDJ -p user.notice "INFORMATION ( OPENDJ ): $@"
}


###########################################################################################
# Function: error
# Description: This function prints error message on syslog
#
# Parameters: Error to print
###########################################################################################
error()
{
  logger -s -t ENM_OPENDJ -p user.err "ERROR ( OPENDJ ): $@"
}

###########################################################################################
# Function: infoNoEcho 
# Description: This function prints info message on syslog and without echo
#
# Parameters: Message to print
###########################################################################################
infoNoEcho()
{
  logger -t ENM_OPENDJ -p user.notice "INFORMATION ( OPENDJ ): $@"
}


###########################################################################################
# Function: ShutdownOpendj
# Description: This function  stops opendj
#
# Parameters: None
# Returns:  0 success
#           1 failure
###########################################################################################
ShutdownOpendj()
{
  LogMessage "ShutdownOpendj request has been received. Processing request....."
  
  if [ $(/sbin/pidof systemd) ] ; then
    /bin/systemctl stop opendj
    RC=$?
  elif [ $(/sbin/pidof init) ] ; then
    /sbin/service opendj stop
    RC=$?
  else
    echo "Error: Failed to find any services system."
    RC=1
  fi
 
  if [ $RC != 0 ] ; then
     LogMessage "ERROR: Failed to stop Opendj" 
     return 1
  fi
  LogMessage "ShutdownOpendj completed successfully!"

  return 0
}



######################################################################
# This functions checks for CLOUD envoronment
#    requires DDC_ON_CLOUD (in GLOBAL_PROPERTIES)
# Parameters: None
# Return:  0 true, 1 false
#
######################################################################
IsOnCloud()
{
  if [[ "${DDC_ON_CLOUD}" == TRUE ]]; then
    return 0
  fi
  return 1
}



######################################################################
# This functions checks for single opendj envoronment
# Parameters: None
# Return:  0 true , 1 false
#
######################################################################
IsSingleOpendj()
{

    IsOnCloud
    if [ $? == 0 ] ; then
       # on cloud check consul data
       CONSUL_GET_PD="consul kv get -recurse enm/deployment/persistent_data"
       if  [ `$CONSUL_GET_PD | grep opendj | wc -l` == 1 ]; then
	    return 0
       fi
    else 
       # on phy check hosts data
       if [ `cat /etc/hosts | grep "cloud-db" |wc -l ` != 0 ]; then
            return 0
       fi
   fi
   return 1
}






###########################################################################################
# Function: StartOpendj
# Description: This function starts opendj
# Parameters: None
# Returns:  0 success
#           1 failure
###########################################################################################
StartOpendj()
{
  LogMessage "StartOpendj request has been received. Processing request....."
  
  if [ $(/sbin/pidof systemd) ] ; then
    /bin/systemctl start opendj
    rc=$?
  elif [ $(/sbin/pidof init) ] ; then
    /sbin/service opendj start
    rc=$?
  else
    echo "Error: Failed to find any services system."
    rc=1
  fi

  if [ $rc != 0 ] ; then
     LogMessage "ERROR: Failed to start Opendj" 
     return 1
  fi
  LogMessage "StartOpendj completed successfully....."

  return 0
}


################################################################################
# Function: decryptOpendjPasswd
# Description: This function decrypts OpenDJ admin password from
#              global.properties file
#              it needs the following variables:
#                OPENDJ_PASSKEY
#                LDAP_ADMIN_PASSWORD (in GLOBAL.PROPERTIES)
#                OPENSSL
#                GLOBAL_PROPERTY_FILE
#                DM_PWD (exported)
# Parameters: none
# Return: 0 (Succeed)
#         1 (Failed)
################################################################################
decryptOpendjPasswd()
{
   LogMessageDotEcho "INFO: decryptOpendjPasswd request is received ...... Processing request"

   #if [ -e ${OPENDJ_PASSKEY} ]; then
   #  DM_PWD=`sg jboss -c "echo ${LDAP_ADMIN_PASSWORD} | ${OPENSSL} enc -a -d -aes-128-cbc -salt -kfile ${OPENDJ_PASSKEY}"`
   if [ -r ${OPENDJ_PASSKEY} ]; then
      DM_PWD=`echo ${LDAP_ADMIN_PASSWORD} | ${OPENSSL} enc -a -d -md md5 -aes-128-cbc -salt -kfile ${OPENDJ_PASSKEY} 2> /dev/null`
      if [ -z "${DM_PWD}" ]; then
         LogMessageDotEcho "ERROR: Failed to decrypt LDAP_ADMIN_PASSWORD from ${GLOBAL_PROPERTY_FILE}"
         return 1
      fi
   else
      LogMessageDotEcho "INFO: ${OPENDJ_PASSKEY} does not exist"
      return 1
   fi
   LogMessageDotEcho "INFO: decryptOpendjPasswd completed successfully"
   return 0
}



###############################################################################
# function: checkReplicationStatus
# Description: check whether opendj replication has already been configured or not
#              If yes, just exit the script, not further configuration is required
#              it needs the following variables:
#                DSSTATUS
#                DM_DN
#                DM_PWD
#                ADMIN_CONNECTOR_PORT
#                GREP
# Parameters: no
# Return:   0 (Succeed but replication is not enabled yet)
#           1 (Failed)
#           2 (Succeed and replication has already been enabled)
################################################################################
function checkReplicationStatus(){
    LogMessageDotEcho "INFO: checkReplicationStatus request is received ...... processing request"

    # opendj DS 6.5 requires also hostname and post
    replication_check_result=$($DSSTATUS --hostname localhost --port $ADMIN_CONNECTOR_PORT --bindDN "$DM_DN" --bindPassword "$DM_PWD" --trustAll |$GREP Replication)

    rr=${PIPESTATUS[0]}
    if [ $rr != 0 ]
    then
        LogMessageDotEcho "ERROR: Failed to check Opendj replication status and the error code from DS is [$rr]"
        return 1
    fi
    if [[ "$replication_check_result" =~ .*Enabled.* ]]
    then
        LogMessageDotEcho "info: Opendj replication configured"
        return 2
    else
        LogMessageDotEcho "INFO: Opendj replication not configured"
        return 0
    fi
}



###########################################################################################
# Function: TransformLogPolicyUnits
# Description: This function converts, transforms and re-converts log policies units to MB
# Parameters: Initial value in string form, constant with which multiply it
# Returns: transformed value in string form, e.g. "<value> mb"
#           -1 failure
###########################################################################################
TransformLogPolicyUnits()
{
    LogMessage "Value to convert $1 and transform multiplying with $2"
    INIT_VALUE=$1
    CONSTANT=$2
    if [[ $INIT_VALUE == *" gb" ]]; then
        INIT_INT=$(echo "${INIT_VALUE% gb*} * 1024" | bc -l)
    elif [[ $INIT_VALUE == *" mb" ]]; then
        INIT_INT=${INIT_VALUE% mb*}
    else
        LogMessage "Value to convert in invalid format (must finish with mb or gb)"
        exit -1
    fi

    RETURNED_INT=$(echo "$INIT_INT * $CONSTANT" | bc -l | awk '{printf("%d\n",$1 + 0.5)}')
    
    RETURNED_VALUE="$RETURNED_INT mb"
    LogMessage "Returned value $RETURNED_VALUE"

    echo $RETURNED_VALUE
}

