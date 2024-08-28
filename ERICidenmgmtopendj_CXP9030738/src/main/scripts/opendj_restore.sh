#!/bin/bash


################################################################################
# Copyright (c) 2014 Ericsson, Inc. All Rights Reserved.
# This script perform restore of OpenDJ data/schema/tasks and replicationChanges
# Author: Malgorzata Luchter (XMAGLUC)
#
###############################################################################


# parameters:
#
# 1: <backup dir> (required)
# 2: <log dir> (required)
# 3: <bkp_area> (optional) area to be restored (eg: userRoot), if par4 not given it will list the available IDs
# 4: "<backup ID>" (optional) backupID to restore

# parameters
if [ -z "$1" ] ; then
   echo "Missing parameter"
   echo "syntax: opendj_restore.sh <backup dir> <log dir> [<area> [\"<backupID>\"]]"
   exit 1
fi
if [ -z "$2" ] ; then
   echo "Missing parameter"
   echo "syntax: opendj_restore.sh <backup dir> <log dir> [<area> [\"<backupID>\"]]"
   exit 1
fi
BACKUP_DIR=$1
LOG_DIR=$2
FORCE_MODE=false
FORCE_AREA=""
FORCE_ID=""
if [ ! -z "$3" ] ; then
   FORCE_MODE=true
   FORCE_AREA=$3
   if [ ! -z "$4" ] ; then
      FORCE_ID=$4
      echo "RESTORE OF Area:$FORCE_AREA backupID:$FORCE_ID"
   else
      echo "RESTORE: LIST ONLY BACKUP IN $FORCE_AREA"
   fi
fi

SERVICE="/sbin/service"
GREP='/bin/grep'
TAIL='/usr/bin/tail'
CUT=/bin/cut
WC='/usr/bin/wc'

LOG_FILE="$LOG_DIR/opendj-restore-`/bin/date "+%F:%H:%M:%S%:z"`.log"
OPENSSL=/usr/bin/openssl

# deployment paths
SHARE_ROOT=/ericsson/tor/data
# global properties that are either required by SSO or defined in the SED.
GLOBAL_PROPERTY_FILE=${SHARE_ROOT}/global.properties
. $GLOBAL_PROPERTY_FILE >/dev/null 2>&1



if [[ "${DDC_ON_CLOUD}" == TRUE ]]; then
    OPENDJ_BASE=/ericsson/opendj/opendj
else
    OPENDJ_BASE=/opt/opendj
fi
BACKUP=$OPENDJ_BASE/bin/dsbackup
MANAGE_TASKS=$OPENDJ_BASE/bin/manage-tasks
IDENMGMT_ROOT=/opt/ericsson/com.ericsson.oss.security/idenmgmt
PROPS_FILE=$IDENMGMT_ROOT/config/datastore.properties
LDAP_PORT=`$GREP ldapsPort $PROPS_FILE | $CUT -d= -f2`
DM_DN=`$GREP rootUserDN  $PROPS_FILE | $CUT -d= -f2-`
DM_PWD=""

# global properties that are either required by SSO or defined in the SED.
eval $(${GREP} "LDAP_ADMIN_PASSWORD" ${GLOBAL_PROPERTY_FILE})


OPENDJ_PASSKEY=/ericsson/tor/data/idenmgmt/opendj_passkey




###########################################################################################
# Main Program
# Description: Restores opendj data (uses the latest backup)
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################

echo "Script to restore opendj data"
echo -n "Log file: $LOG_FILE"

source $IDENMGMT_ROOT/opendj/bin/common.sh
if [ $? -ne 0 ]; then
   echo "ERROR: Failed to source $IDENMGMT_ROOT/opendj/bin/common.sh"
   exit 1
fi

#Create log file
SetLogFile $LOG_DIR $LOG_FILE
if [ $? != 0 ] ; then
   echo "ERROR: SetLogFile failed."
   exit 1
fi

result=0

if [ ! -d $BACKUP_DIR ]; then
	LogMessage "ERROR: backup dir does not exist"
   	exit 1
fi

LogMessage ""
#check if opendj is running
if [ $(/sbin/pidof systemd) ] ; then
    LogMessage "check status with systemV"
    /bin/systemctl status opendj
elif [ $(/sbin/pidof init) ] ; then
    LogMessage "check status with initd"
    /sbin/service opendj status
else
    LogMessage "check status docker more"
    /sbin/service opendj status
fi

#if running
if [ $? == 0 ]; then
    LogMessage "Opendj is RUNNING"
    decryptOpendjPasswd
    restoreTaskCount=1

    if [ $FORCE_MODE == true ]; then
       # check for the area
       if [ ! -z "$FORCE_AREA" ]; then

          # check to list backupID
          if [[ "$FORCE_ID" == "" ]]; then
             backupList=$($BACKUP list --backupLocation $BACKUP_DIR --backendName $FORCE_AREA --no-prompt |$GREP "Backup ID")
             LogMessage "Backups available in area: $FORCE_AREA "
             bl=${backupList//"Backup ID:"/""}
             LogMessage "$bl"
             exit 0
          else
             BACKUP_ID=$FORCE_ID
             LogMessage "Restore area: $FORCE_AREA, BackupID: $FORCE_ID"
          fi
       fi
    else
       BACKUP_ID=`$BACKUP list --backupLocation $BACKUP_DIR --no-prompt |$GREP "Backup ID"|$TAIL -n1|$GREP -oE '[^ ]+$'`
    fi

    if [ -z "$BACKUP_ID" ]; then
       LogMessage "WARN: no backup to restore for $f"
       exit 1       
    fi
    LogMessage "Restore ID:$BACKUP_ID"
    if [ `du -k -all  $f | grep $BACKUP_ID  | cut -f1 | grep '^0$' | wc -l` -eq 1 ]; then
       LogMessage "ERROR: backup file destroyed $f"
       result=1
    fi
    $BACKUP restore --port 4444 --trustAll --bindPassword $DM_PWD --bindDN "$DM_DN" --backupLocation $BACKUP_DIR --backupID $BACKUP_ID --no-prompt --start 0 | tee -a $LOG_FILE
    rc=${PIPESTATUS[0]}
    if [ $rc != 0 ] ; then
       LogMessage "ERROR: Cannot restore $BACKUP_DIR"
       result=1
    fi

    RESULT=`$MANAGE_TASKS --port 4444 --trustAll --bindDN "$DM_DN"  --bindPassword $DM_PWD --summary --no-prompt | $TAIL -n$restoreTaskCount`
    LogMessage "$RESULT"
else
    LogMessage "Opendj is STOPPED"
    decryptOpendjPasswd
    restoreTaskCount=1

    if [ $FORCE_MODE == true ]; then
       # check for the area
       if [ ! -z "$FORCE_AREA" ]; then

          # check to list backupID
          if [[ "$FORCE_ID" == "" ]]; then
             backupList=$($BACKUP list --backupLocation $BACKUP_DIR --backendName $FORCE_AREA --no-prompt |$GREP "Backup ID")
             LogMessage "Backups available in area: $FORCE_AREA "
             bl=${backupList//"Backup ID:"/""}
             LogMessage "$bl"
             exit 0
          else
             BACKUP_ID=$FORCE_ID
             LogMessage "Restore area: $FORCE_AREA, BackupID: $FORCE_ID"
          fi
       fi	  
     else
        BACKUP_ID=`$BACKUP list --backupLocation $BACKUP_DIR --no-prompt |$GREP "Backup ID"|$TAIL -n1|$GREP -oE '[^ ]+$'`
     fi
     if [ -z "$BACKUP_ID" ]; then
        LogMessage "WARN: no backup to restore for $f"
        exit 1
     fi
     LogMessage "Restore ID:$BACKUP_ID"
     if [ `du -k -all  $BACKUP_DIR | grep $BACKUP_ID  | cut -f1 | grep '^0$' | wc -l` -eq 1 ]; then
        LogMessage "ERROR: backup file destroyed $f"
        result=1
     fi
     $BACKUP restore --backupLocation $BACKUP_DIR --backupID $BACKUP_ID --no-prompt --offline | tee -a $LOG_FILE
     rc=${PIPESTATUS[0]}
     if [ $rc != 0 ] ; then
        LogMessage "ERROR: Cannot restore $BACKUP_DIR"
        result=1
     fi

fi

exit $result

