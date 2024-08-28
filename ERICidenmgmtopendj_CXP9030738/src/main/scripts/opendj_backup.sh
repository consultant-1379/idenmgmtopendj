#!/bin/bash

################################################################################
# Copyright (c) 2014 Ericsson, Inc. All Rights Reserved.
# This script creates backup of OpenDJ data/schema/tasks and replciationChanges
# Author: Malgorzata Luchter (XMAGLUC)
#
###############################################################################

# parameters:
#
# 1: <backup dir> (required)
# 2: <log dir> (required)
# 3: --clear-old (optional)
# 4: <number> (optional) old backups to mantain (it requires par 3 is given)


# parameters
if [ -z "$1" ] ; then
   echo "Missing parameter"
   echo "syntax: opendj_backup.sh <backup dir> <log dir> [--clear-old [number od backup to keep]]"
   exit 1
fi
if [ -z "$2" ] ; then
   echo "Missing parameter"
   echo "syntax: opendj_backup.sh <backup dir> <log dir> [--clear-old [number od backup to keep]]"
   exit 1
fi
BACKUP_DIR=$1
LOG_DIR=$2
CLEARLOG_MODE=false
if [ ! -z "$3" ] ; then
   if [ "$3" == "--clear-old" ] ; then
       CLEARLOG_MODE=true
   fi
fi
BACKUPS_NMB=19
if [ ! -z "$4" ] ; then
   BACKUPS_NMB=$4
fi

# linux commands
SERVICE="/sbin/service"
GREP='/bin/grep -w'
CUT=/bin/cut
SORT=/bin/sort
UNIQ='/usr/bin/uniq'
WC='/usr/bin/wc'
OPENSSL=/usr/bin/openssl
TAIL='/usr/bin/tail'
HEAD='/usr/bin/head'
XARGS=/usr/bin/xargs
RM=/bin/rm
SED=/bin/sed
FIND=/bin/find
WHOAMI=/usr/bin/whoami

# deployment paths
SHARE_ROOT=/ericsson/tor/data
LOG_FILE="$LOG_DIR/opendj-backup-`/bin/date "+%F:%H:%M:%S%:z"`.log"


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
# Function: checkDir
# Description: This function check that expected directory is available 
# Parameters: directory
# Return: 0 (Succeed)
#         1 (Failed)
###########################################################################################

checkDir()
{
   DIRECTORY=$1
   MAX_RETRY=30
   FIND_VALUE=99
   SLEEP_TIME=3
   RETRY=0

   LogMessage "check exist "$DIRECTORY

   while [ $RETRY -le $MAX_RETRY ]
   do
   #echo $RETRY
     if [ -d "$DIRECTORY" ]; then
       # Control will enter here if $DIRECTORY exists.
       # set max retry to exit
       RETRY=$FIND_VALUE
     else
       LogMessage "Retry $RETRY"  
       RETRY=$((RETRY+1))
       sleep $SLEEP_TIME
     fi
   done
   
   if [ $RETRY -ne $FIND_VALUE ]; then
      LogMessage "ERROR:Failed to check $DIRECTORY"
      return 1
   fi
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
#
# NOTE: it has a different file check and uses jboss group for openssl
#       (it is required in the pre-upgrade phase)
#
# Parameters: none
# Return: 0 (Succeed)
#         1 (Failed)
################################################################################
decryptOpendjPasswdLocal()
{
   LogMessageDotEcho "INFO: decryptOpendjPasswd request is received ...... Processing request"


   if [ -e ${OPENDJ_PASSKEY} ]; then
     DM_PWD=`sg jboss -c "echo ${LDAP_ADMIN_PASSWORD} | ${OPENSSL} enc -a -d -md md5 -aes-128-cbc -salt -kfile ${OPENDJ_PASSKEY}"`
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




######################
#
#   M A I N
#
######################

echo "Script to create opendj backup"
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

#   check if shared area is present
checkDir $SHARE_ROOT
if [ $? != 0 ]; then
    exit 1
fi



################################################################################
# Function: checkForEmptyFiles
# Description: checks if backup created unpropriate files and if so removes them
# Parameters: none
# Return: 0 (Succeed)
#         1 (Failed)
################################################################################
checkForEmptyFiles(){
    code=0
    for f in $BACKUP_DIR/*; do
        if [ -d $f ];then
            array=( `du -b $f/* | grep backup- | grep "^0" |rev |  cut -d "/" -f1 | rev | tr '\n' ' '` )
            for var in "${array[@]}"
                do
                rm -f `echo $f/$var | tr -s "/"`
                if [ $? != 0 ]; then
                    LogMessage "ERROR: Cannot remove 0 size backup file $var"
                    continue
                fi
                id=`echo $var | grep -o '[0-9]\{14\}Z'`
                if [ -z $id ];then
                    LogMessage "ERROR: Cannot extraxt id from $var:incorrect id format"
                    continue
                fi
                sed -i -e  "`grep -n id.*$id $f/backup.info | cut -d ':' -f1`,`grep -n file.*$id $f/backup.info| cut -d ':' -f1`d" $f/backup.info
                if [ $? != 0 ]; then
                    LogMessage "ERROR: Cannot remove entry from backup.info for  $var"
                    continue
                fi
            done
            if [ `echo ${#array[@]}` -ne 0 ];then
                LogMessage "ERROR: Backup created 0 size file"
                code=1
            fi
        fi
    done
    return $code
}

###############################################################################
# Function: createBackup
# Parameters: optional parameter --clear-old
# Return: 0 (Succeed)
#         1 (Failed)
###############################################################################
createBackup()
{

    TASK_ID=`$BACKUP create --port $LDAP_PORT --bindDN "$DM_DN" --bindPassword $DM_PWD --backupLocation $BACKUP_DIR --trustAll --start 0  | tee -a $LOG_FILE | awk '{print $3}'`
    rc=${PIPESTATUS[0]}
    if [ $rc != 0 ]; then
        LogMessage "ERROR: backup failure"
        return 1
    fi

    LogMessage "Waiting for results"
    #waiting up to 10 minutes to finish
    nr=0
    until [ `$MANAGE_TASKS --port $LDAP_PORT --trustAll --bindDN "$DM_DN"  --bindPassword $DM_PWD -n -s | $GREP $TASK_ID | egrep -i "wait|running" |wc -l` -eq 0 ]
        do
        echo "waiting for backup"
        sleep 10
        nr=`expr $nr + 1`
        if [ $nr -gt 60 ]; then
            RESULT=`$MANAGE_TASKS --port $LDAP_PORT --trustAll --bindDN "$DM_DN"  --bindPassword $DM_PWD -n -s | $GREP $TASK_ID`
            LogMessage "ERROR:backup failure-task still waiting/running"
            LogMessage "$RESULT"
            return 1
        fi
    done

    #if success return 0
    RESULT=`$MANAGE_TASKS --port $LDAP_PORT --trustAll --bindDN "$DM_DN"  --bindPassword $DM_PWD -n -s | $GREP $TASK_ID`

    echo "RESULT:"
    echo $RESULT
    echo "======"

    if [ `echo $RESULT | $GREP "success.*" |wc -l` -eq 1 ];then
        LogMessage "INFO: backup completed successfully"

        #delete old backups&logs if nmb of backups greater than BACKUPS_NMB
        if [ $CLEARLOG_MODE == true ]; then
            LogMessage "Clear Old Backups"
	    $BACKUP purge --port $LDAP_PORT --bindDN "$DM_DN" --bindPassword $DM_PWD --backupLocation $BACKUP_DIR --keepCount $BACKUPS_NMB --trustAll --start 0
	    rc=${PIPESTATUS[0]}
    	    if [ $rc != 0 ]; then
               LogMessage "ERROR: Clear Old Backups failure"
               return 1
            fi

	    LogMessage "Clear Old Logs"
            num_logs=`ls $LOG_DIR/opendj-backup-* -t | $WC -l`
            if [ $num_logs -gt $BACKUPS_NMB ]; then
              old_logs=`(ls $LOG_DIR/opendj-backup-* -t|$HEAD -n $BACKUPS_NMB;ls $LOG_DIR/opendj-backup-*)|$SORT| $UNIQ -u`
              LogMessage "Delete logs:$old_logs"
              echo $old_logs|$XARGS $RM
            fi
        fi
        sync
        return 0
    else
        #backup non finished succeffully
        return 1
    fi

    #else some kind of error
    LogMessage "ERROR:backup failure: s$RESULT"
    return 1
}


###############################################################################
# Main Program
# Description: Backup opendj data
# Parameters: backup directory, log directory, optional parameter -clear-old
# Return:  0 everything ok, 1 fail
###############################################################################


# BACKUPDIR is passed as parameter, its /var/tmp/backupdir, 
# the last part is created by opendj backup utility
# so we should test the parent of this one
#checkDir $BACKUP_DIR
#if [ $? != 0 ]; then
#    exit 1
#fi

# just for log, check the user
whoamiAnswer=`$WHOAMI`
LogMessage "opendj_backup run by:"$whoamiAnswer


#decryptOpendjPasswdLocal
decryptOpendjPasswdLocal
if [ $? != 0 ]; then
    LogMessage "ERROR: decrypt password failed."
    exit 1
 
fi

if [ $(/sbin/pidof systemd) ] ; then
    /bin/systemctl status opendj
elif [ $(/sbin/pidof init) ] ; then
    /sbin/service opendj status
fi

if [ $? != 0 ]; then
    LogMessage "INFO: cannot create backup-opendj not ready"
    exit 1
fi

if [ ! -d $BACKUP_DIR ]; then
    mkdir -p $BACKUP_DIR
    if [ $? != 0 ]; then
        LogMessage "ERROR:Failed to create backup directory: $BACKUP_DIR"
        exit 1
    fi
fi

chown opendj:opendj $BACKUP_DIR
if [ $? != 0 ]; then
    LogMessage "ERROR:Failed to set ownership on $BACKUP_DIR"
    exit 1
fi

lockfile1=$BACKUP_DIR/backup.lock
backup_lockfile=$OPENDJ_BASE/bklock.lock
if ( set -o noclobber; echo "locked" > "$lockfile1") 2> /dev/null; then
    echo "locked" > "$backup_lockfile"
    
    LogMessage "CREATE BACKUP"

    createBackup
    result=$?

# here if result not zero, you could delete backup directory and try again

    rm -f $backup_lockfile
    rm -f $lockfile1
    exit $result
else
    LogMessage "INFO: Backup created from the second instance"
    exit 0
fi

