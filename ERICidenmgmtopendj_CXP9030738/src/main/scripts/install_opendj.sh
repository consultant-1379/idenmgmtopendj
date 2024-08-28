#!/bin/bash

################################################################################
# Copyright (c) 2013 Ericsson, Inc. All Rights Reserved.
# This script installs the OpenDJ directory server
# Author: Simohamed Elmajdoubi
# ESN 38708
#
#
#
###############################################################################

# Source variables file to get value for SERVICE_INSTANCE_NAME
if [ -f /opt/ericsson/com.ericsson.oss.security/idenmgmt/opendj/variables ]; then
    . /opt/ericsson/com.ericsson.oss.security/idenmgmt/opendj/variables
fi

if [ -f /opt/ericsson/com.ericsson.oss.security/idenmgmt/opendj/bin/bintools.sh ]; then
    . /opt/ericsson/com.ericsson.oss.security/idenmgmt/opendj/bin/bintools.sh
fi


#TEMPORARY? JAVA 11 will become default version?
OPENDJ_JAVA_HOME=""
JAVA_VERSION=""
JAVA_MAJOR_VERSION=""
JAVA_UPDATE_VERSION=""

LOG_DIR="/var/log/opendj"
LOG_FILE="$LOG_DIR/opendj-install-`/bin/date "+%F:%H:%M:%S%:z"`.log"
UPL_LOG="$LOG_DIR/opendj-uplift-`/bin/date "+%F:%H:%M:%S%:z"`.log"
DUMP_PATH="/tmp"
HPROF_LOG="$DUMP_PATH/opendj-`/bin/date "+%F:%H:%M:%S%:z"`.hprof"

#############################################################
# Partitions on pENM - TO BE CHANGED
CHANGELOGDBPATH=/var/ericsson/opendj/changelogDb
DBPATH=/var/ericsson/opendj/db
#############################################################

# deployment paths
SHARE_ROOT=/ericsson/tor/data
# global properties that are either required by SSO or defined in the SED.
#GLOBAL_PROPERTY_FILE=${SHARE_ROOT}/global.properties
#. $GLOBAL_PROPERTY_FILE
IDENMGMT_ROOT=/opt/ericsson/com.ericsson.oss.security/idenmgmt
CERTS_DIR="${IDENMGMT_ROOT}/opendj/certs"

ROOTCA_DIR="${SHARE_ROOT}/certificates"
IDENMGMT_COMMON_DIR=${SHARE_ROOT}/idenmgmt
BACKUP_DIR=${SHARE_ROOT}
USERMOD=/usr/sbin/usermod

#create passkeys group
GROUPNAME=jboss
PKUSER=opendj

#backup script
OPENDJ_BACKUP=$IDENMGMT_ROOT/opendj/bin/opendj_backup.sh

#crontab file for opendj user
OPENDJ_CRONTAB_FILE=/var/spool/cron/opendj

#Scheduled backup params
NO_ROLLBACK_OPENDJ_DIR=/ericsson/tor/no_rollback/opendj
SHEDULED_BACKUP_DIR=$NO_ROLLBACK_OPENDJ_DIR/scheduled_backup
SCHEDULED_BACKUP_LOG_DIR=/var/log/opendj/backup/
CRON_BACKUP_TASK="*/30 * * * * ${OPENDJ_BACKUP} $SHEDULED_BACKUP_DIR $SCHEDULED_BACKUP_LOG_DIR --clear-old"

#Certificate tools
JAVA_KEYTOOL=/usr/java/default/bin/keytool
ROOTCA_FILE=$ROOTCA_DIR/rootCA.pem
ROOTCA_KEY_FILE=$ROOTCA_DIR/rootCA.key
KEY_VALIDITY_PERIOD=7300
CONFIGURE_CERTS=${IDENMGMT_ROOT}/opendj/bin/extract_certs_if_required.sh

# get datastore.properties settings
PROPS_FILE=$IDENMGMT_ROOT/config/datastore.properties
DM_DN=`$GREP_W rootUserDN  $PROPS_FILE | $CUT -d= -f2-`
ADMIN_CONNECTOR_PORT=`$GREP_W adminConnectorPort $PROPS_FILE | $CUT -d= -f2`
SUPER_USER_PASSWD_POLICY=`$GREP_W superuserPasswdPolicy  $PROPS_FILE | $CUT -d= -f2`
RANDOM_PASSWD_GENERATOR=`$GREP_W randomPasswdGenerator  $PROPS_FILE | $CUT -d= -f2`
DEFAULT_PASSWD_POLICY="Default Password Policy"
REPLICATION_ADMIN_UID=`$GREP_W replicationAdminUid $PROPS_FILE | $CUT -d= -f2`
REPLICATION_PORT=`$GREP_W replicationPort $PROPS_FILE | $CUT -d= -f2`

# other paths
OPENDJ_INTERNAL_LOCK_FILE=${OPENDJ_ROOT}/locks/server.lock
UNWILLINGCNTFILE="ldapnoresponse.cnt"
MON_REPL_CNTFILE="monitorreplication.cnt"

# PurgeDelay Setting
REPLICATION_PURGE_DELAY_CLOUD="24h"
REPLICATION_PURGE_DELAY_pENM="24h"

################################################################

# deployment paths
SHARE_ROOT=/ericsson/tor/data
# global properties that are either required by SSO or defined in the SED.
IDENMGMT_ROOT=/opt/ericsson/com.ericsson.oss.security/idenmgmt
DEPLOY_PATH=/opt/ericsson/com.ericsson.oss.security/idenmgmt/config/deploymentId.cnf
CERTS_DIR="${IDENMGMT_ROOT}/opendj/certs"



###############################################################
TMP_FOLDER=/tmp
OPENDJ_TMP=$TMP_FOLDER/opendj_tmp

# password policies constants
USERS_WITH_DISABLED_PASSWORD_AGEING=( "COMUser" )


DEPLOYMENT_ID=`$GREP_W DEPLOYMENT_ID $DEPLOY_PATH | $CUT -d= -f2`
DEPLOYMENT_ID_PASSWORD=`$GREP_W DEPLOYMENT_ID_PASSWORD $DEPLOY_PATH | $CUT -d= -f2`


SSO_USER_PWD=""
DM_PWD=""

OPENDJ_PASSKEY=${SHARE_ROOT}/idenmgmt/opendj_passkey
SSOLDAP_PASSKEY=${SHARE_ROOT}/idenmgmt/ssoldap_passkey

#upgrade stop timeouts
UPGRADE_MAX_COUNTER=20
UPGRADE_TIMEOUT=120

# Log Policy Related
# since DS version 7.3.0 "Replication Repair Logger" no more present
LOG_PUBLISHERS=("File-Based Access Logger"
               "File-Based Audit Logger"
               "File-Based Debug Logger"
               "File-Based Error Logger"
	       "File-Based HTTP Access Logger")

TIME_LIMIT_ROTATION_POLICY="24 Hours Time Limit Rotation Policy"
SIZE_LIMIT_ROTATION_POLICY="Size Limit Rotation Policy"
FILE_COUNT_RETENTION_POLICY="File Count Retention Policy"
SIZE_LIMIT_RETENTION_POLICY="Size Limit Retention Policy"

SIZE_LIMIT_RETENTION_POLICY_ACCESS="Size Limit Retention Policy Access"
SIZE_LIMIT_RETENTION_POLICY_AUDIT="Size Limit Retention Policy Audit"
SIZE_LIMIT_RETENTION_POLICY_ERROR="Size Limit Retention Policy Error"
SIZE_LIMIT_RETENTION_POLICY_REPLICATION="Size Limit Retention Policy Replication"

AUDITLOGPUBLISHER="File-Based Audit Logger"

LOG_POLICY_CONF=$IDENMGMT_ROOT/opendj/config/opendj_log_policy.cnf
LOG_RETENTION_TOTAL_SIZE_LIMIT=$($GREP_W Log_Retention_Total_File_Size_Limit $LOG_POLICY_CONF | $CUT -d= -f2- )
LOG_RETENTION_FILE_NUMBER_LIMIT=$($GREP_W Log_Retention_File_Number_Limit $LOG_POLICY_CONF | $CUT -d= -f2 )
LOG_ROTATION_TIME_LIMIT=$($GREP_W Log_Rotation_Time_Limit $LOG_POLICY_CONF | $CUT -d= -f2- ) 
LOG_ROTATION_FILE_SIZE_LIMIT=$($GREP_W Log_Rotation_File_Size_Limit $LOG_POLICY_CONF | $CUT -d= -f2- )

# cpher suites for TLS1
ALLOWED_SUITES_TLS1=(
"TLS_AES_128_GCM_SHA256"
"TLS_AES_256_GCM_SHA384"
"TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"
"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
"TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
"TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"
"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"
"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"
"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256"
"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA"
"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256"
"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"
"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
"TLS_EMPTY_RENEGOTIATION_INFO_SCSV"
"TLS_RSA_WITH_AES_128_CBC_SHA"
"TLS_RSA_WITH_AES_128_CBC_SHA256"
"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA")

# DEFAULT opendj 7.3.0 cipher suites
ALLOWED_SUITES=("TLS_AES_128_GCM_SHA256"
                "TLS_AES_256_GCM_SHA384"
                "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
                "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
		#START TEMPORARY TO WORK WITH ACCESS CONTROL
		"TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
		"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"
		#END TEMPORARY
                "TLS_EMPTY_RENEGOTIATION_INFO_SCSV")

#################################################################
# SetENMSettings 
# Arguments: parameter 1 install
#                      2 upgrade
#
# Returns:
#   0      Success
#   1      Failure
#################################################################
SetENMSettings(){
OPENDJHOST0="opendjhost0"
OPENDJHOST1="opendjhost1"
LDAP_LOCAL="ldap-local"
LDAP_PEER="ldap-remote"
LDIF_DIR=""

echo "==========> SetENMSettings start with parameter :$1"
LogMessage "==========> SetENMSettings start with parameter :$1"

if [ "$cENM_DEPLOYMENT" != TRUE ] ; then
   # pENM and vENM
   # global properties that are either required by SSO or defined in the SED.
   # we need the global.properties file
   GLOBAL_PROPERTY_FILE=/ericsson/tor/data/global.properties
   if [ ! -r "$GLOBAL_PROPERTY_FILE" ]; then
       LogMessage "ERROR: Cannot read $GLOBAL_PROPERTY_FILE"
       error "Cannot read $GLOBAL_PROPERTY_FILE"
   return 1
fi
   . $GLOBAL_PROPERTY_FILE >/dev/null 2>&1
   # deployment paths

   IsOnCloud
   if [ $? == 0 ] ; then
      # vENM
      echo "==========> SetENMSettings for vENM with parameter :$1"
      LogMessage "==========> SetENMSettings for vENM with parameter :$1"
      OPENDJ_ROOT=/ericsson/opendj/opendj
      OPENDJ_ROOT_PARENT=/ericsson/opendj
      LDIF_DIR=/ericsson/opendj/opendj_ldif

      # We must find where the user-99.ldif is before
      if [ $1 -eq 1 -o ! -f ${OPENDJ_ROOT}/config/schema/00-core.ldif ]; then
        echo "==========> vENM 99-user.ldif management: if"
        LogMessage "==========> vENM 99-user.ldif management: if"
        mkdir -p ${OPENDJ_ROOT}/template/db/schema/
        ${CP} /opt/opendj/template/config/schema/99-user.ldif ${OPENDJ_ROOT}/template/db/schema/
      else
       mkdir -p ${OPENDJ_ROOT}/template/config/schema/
       ${CP} /opt/opendj/template/config/schema/99-user.ldif ${OPENDJ_ROOT}/template/config/schema/
      fi

      ENMTYPE=vENM
      LDAP_HOST=$SERVICE_INSTANCE_NAME
      if [ $LDAP_HOST == "opendj-1" ]; then
         LDAP_PEER="opendj-2"
      else
         LDAP_PEER="opendj-1"
      fi
      OPENDJHOST0="opendj-1"
      OPENDJHOST1="opendj-2"
      SERVERID=$LDAP_HOST
   elif [ `cat /etc/hosts | egrep cloud-db |wc -l` != 0 ]; then
      #vapp
      ENMTYPE=pENM
      OPENDJ_ROOT=/opt/opendj
      OPENDJ_ROOT_PARENT=/opt/
      LDIF_DIR=$OPENDJ_ROOT/logs/opendj_ldif

      #move 99-user.ldif from default location copied from pom, which is normally correct only during upgrade
      if [ $1 -eq 1 -o ! -f ${OPENDJ_ROOT}/config/schema/00-core.ldif ]; then
        mkdir -p ${OPENDJ_ROOT}/template/db/schema/
        ${CP} ${OPENDJ_ROOT}/template/config/schema/99-user.ldif ${OPENDJ_ROOT}/template/db/schema/
      fi

      LDAP_HOST=$LDAP_LOCAL
      OPENDJHOST0=$LDAP_LOCAL
      OPENDJHOST1=$LDAP_PEER
      SERVERID=$LDAP_HOST
   else
      # pENM
      
      OPENDJ_ROOT=/opt/opendj
      OPENDJ_ROOT_PARENT=/opt/
      LDIF_DIR=$OPENDJ_ROOT/logs/opendj_ldif

      #move 99-user.ldif from default location copied from pom, which is normally correct only during upgrade
      if [ $1 -eq 1 -o ! -f ${OPENDJ_ROOT}/config/schema/00-core.ldif ]; then
        mkdir -p ${OPENDJ_ROOT}/template/db/schema/
        ${CP} ${OPENDJ_ROOT}/template/config/schema/99-user.ldif ${OPENDJ_ROOT}/template/db/schema/
      fi

      ENMTYPE=pENM
      $HOST_NAME -I | $GREP_W $(getent hosts $OPENDJHOST0 | cut -d' ' -f1)
      if [ $? != 0 ] ; then
         LDAP_HOST=$OPENDJHOST1
         LDAP_PEER=$OPENDJHOST0
      else
         LDAP_HOST=$OPENDJHOST0
         LDAP_PEER=$OPENDJHOST1
      fi
      SERVERID=$LDAP_HOST
   fi
else   #  if [ $1 -eq 1 -o ! -f ${OPENDJ_ROOT}/config/schema/00-core.ldif ]; then
   # cENM

   if [ $1 == 1 ]; then
       OPENDJ_ROOT=/var/tmp/opendj/opendj
       OPENDJ_ROOT_PARENT=/var/tmp/opendj
       LDIF_DIR=/ericsson/opendj/opendj/logs/opendj_ldif
   else
       OPENDJ_ROOT=/ericsson/opendj/opendj
       OPENDJ_ROOT_PARENT=/ericsson/opendj
       LDIF_DIR=$OPENDJ_ROOT/logs/opendj_ldif
   fi

       echo " ENMSetting : $OPENDJ_ROOT"

   if [ $1 -eq 1 -o ! -f ${OPENDJ_ROOT}/config/schema/00-core.ldif ]; then
      mkdir -p ${OPENDJ_ROOT}/template/db/schema/
      ${CP} /opt/opendj/template/config/schema/99-user.ldif ${OPENDJ_ROOT}/template/db/schema/
   else
      mkdir -p ${OPENDJ_ROOT}/template/config/schema/
      ${CP} /opt/opendj/template/config/schema/99-user.ldif ${OPENDJ_ROOT}/template/config/schema/
   fi

   SIDE=$(hostname | grep 1 | wc -l)
   if [ $SIDE == 0 ];then
      LOCAL_LDAP_HOST=$DS_SVC"-0".$DS_SVC
      REMOTE_LDAP_HOST=$DS_SVC"-1".$DS_SVC
      SERVERID=$DS_SVC"-0"
   else
      LOCAL_LDAP_HOST=$DS_SVC"-1".$DS_SVC
      REMOTE_LDAP_HOST=$DS_SVC"-0".$DS_SVC
      SERVERID=$DS_SVC"-1"
   fi
   LDAP_HOST=$LOCAL_LDAP_HOST
   LDAP_PEER=$REMOTE_LDAP_HOST

   OPENDJHOST0=$DS_SVC"-0".$DS_SVC
   OPENDJHOST1=$DS_SVC"-1".$DS_SVC

fi

if [ $1 -eq 1 -o ! -f ${OPENDJ_ROOT}/config/schema/00-core.ldif ]; then
    #Due to opendj uplift to 6.5.0 schema location does change only during fresh install and not upgrade
    OPENDJ_SCHEMA_DIR=${OPENDJ_ROOT}/db/schema
    OPENDJ_NEW_SCHEMA_DIR=${OPENDJ_ROOT}/template/db/schema
else
    #upgrade
    OPENDJ_SCHEMA_DIR=${OPENDJ_ROOT}/config/schema
    OPENDJ_NEW_SCHEMA_DIR=${OPENDJ_ROOT}/template/config/schema
fi

# OpenDJ tools
KEYSTORE_NAME=${OPENDJ_ROOT}/config/keystore
LDAPMODIFY=$OPENDJ_ROOT/bin/ldapmodify
LDAPSEARCH=$OPENDJ_ROOT/bin/ldapsearch
LDAPDELETE=$OPENDJ_ROOT/bin/ldapdelete
DSCONFIG=$OPENDJ_ROOT/bin/dsconfig
DSREPLICATION=$OPENDJ_ROOT/bin/dsrepl
LDIFDIFF=$OPENDJ_ROOT/bin/ldifdiff
LDIFSEARCH=$OPENDJ_ROOT/bin/ldifsearch
LDIFMODIFY=$OPENDJ_ROOT/bin/ldifmodify
EXPORT_LDIF=$OPENDJ_ROOT/bin/export-ldif
IMPORT_LDIF=$OPENDJ_ROOT/bin/import-ldif
UPGRADE=$OPENDJ_ROOT/upgrade
STOP_DS=$OPENDJ_ROOT/bin/stop-ds
START_DS=$OPENDJ_ROOT/bin/start-ds
DSKEYMGR=$OPENDJ_ROOT/bin/dskeymgr
REBUILD_INDEX=$OPENDJ_ROOT/bin/rebuild-index
OPENDJ_INTERNAL_LOCK_FILE=${OPENDJ_ROOT}/locks/server.lock

# rename settings in global.properties
# NOTE: BASE_DN needs to be dc=<something>,dc=com for now
BASE_DN=$COM_INF_LDAP_ROOT_SUFFIX
CONTAINER_BASE=`echo $BASE_DN | cut -f1 -d, | cut -f2 -d=`
SSO_USER_DN=$COM_INF_LDAP_ADMIN_CN

# update orgName in datastore.properties
cat $PROPS_FILE | grep -v orgName > /tmp/datastore.properties.tem
echo com.ericsson.nms.security.orgName=${BASE_DN} >> /tmp/datastore.properties.tem
echo "com.ericsson.nms.security.ldapHost=localhost" >> /tmp/datastore.properties.tem
mv /tmp/datastore.properties.tem $PROPS_FILE

return 0

}

##############################################################
#  ScheduleExportLdif
#  Arguments: None
#
# Returns:
#   0      Success/Fail
#################################################################

ScheduleExportLdif(){
    LogMessage "INFO: ScheduleExportLdif invoked, processing request .........."
  
    TASK_ID="ScheduleExportLdif" 
    TIME_SCHEDULE="32\ 6\ \*\ \*\ \*"


    if [ ! -d $LDIF_DIR ]; then
            LogMessage "INFO: Creating $LDIF_DIR ...."
            ${MKDIR} $LDIF_DIR

            $CHOWN -R opendj:opendj $LDIF_DIR
            if [ $? -ne 0 ]; then
               LogMessage "ERROR: failed to chown $LDIF_DIR"
               error "Failed to chown $LDIF_DIR"
               return 0
            fi
    fi 


    CMD="$OPENDJ_ROOT"'/bin/export-ldif --ldifFile '"$LDIF_DIR"'/userdb_'"$LDAP_HOST"'.ldif  --excludeAttribute ds-sync-state  --excludeAttribute ds-sync-hist --backendID userRoot --hostName localhost -p '"$ADMIN_CONNECTOR_PORT"'  -D "'"${DM_DN}"'" -w '"$DM_PWD"' --trustAll --noPropertiesFile  --recurringTask '"${TIME_SCHEDULE}"' --taskId '"$TASK_ID"
    su opendj -c "$CMD"
    if [ ${?} -ne 0 ]; then
        LogMessage "ERROR: Task already exists"
        info "Task already exists"
        return 0
    fi
    
    LogMessage "INFO: ScheduleExportLdif succesfully completed"
    info "ScheduleExportLdif succesfully completed"
    return 0
    
}

#################################################################
# AddOpendjUserToJbossGroup: adds opendj user to jboss group
# Arguments: None
#
# Returns:
#   0      Success
#   1      Failure
#################################################################

AddOpendjUserToJbossGroup(){
    LogMessage "INFO: AddOpendjUserToJbossGroup invoked, processing request .........."

    $GREP_W $GROUPNAME /etc/group
    if [ $? -ne 0 ]; then
        LogMessage "ERROR: group $GROUPNAME does not exist"
        error "Group $GROUPNAME does not exist"
        return 1
    fi

    $USERMOD -a -G $GROUPNAME $PKUSER
    if [ $? -ne 0 ]; then
        LogMessage "ERROR: user could not be added"
        error "User could not be added"
        return 1
    fi

    LogMessage "INFO: AddOpendjUserToJbossGroup completed successfully"
    info "AddOpendjUserToJbossGroup completed successfully"
    return 0
}

#################################################################
# ExtractAndConfigureCerts: invoke ${CONFIGURE_CERTS} only once
#   that means only during initial install and only on one node
# Arguments: None
#
# Returns:
#   0      Success
#   1      Failure
#################################################################

ExtractAndConfigureCerts(){
    LogMessage "INFO: ExtractAndConfigureCerts invoked, processing request .........."

    if [ "${cENM_DEPLOYMENT}" != TRUE ]; then

    ${LOCKFILE} ${SHARE_ROOT}/opendj_certs.lock -1 -r 100
    if [ ${?} -ne 0 ]; then
        LogMessage "ERROR: something went wrong during locking"
        error "Something went wrong during locking"
        return 1
    fi
    fi

    if [ "${DDC_ON_CLOUD}" == TRUE ] || [ "${cENM_DEPLOYMENT}" == TRUE ] ; then
        neo4j_passkey_file="${CERTS_DIR}/idenmgmt/neo4j_passkey"
        if [ ! -f "${SHARE_ROOT}/idenmgmt/neo4j_passkey" ]; then

            ${CP} $neo4j_passkey_file "${SHARE_ROOT}/idenmgmt/"
            [ ${?} -ne 0 ] && LogMessage "ERROR: Problem copying neo4j_passkey, continuing anyway"
        fi
    fi

    if [ "${DDC_ON_CLOUD}" == TRUE ] || [ "${cENM_DEPLOYMENT}" == TRUE ] ; then
        if [ ! -s $SSOLDAP_PASSKEY ]; then
            LogMessage "INFO: configuring certs for vENM/cENM"
            ${CONFIGURE_CERTS}
        fi
    else  # on pENM
        LogMessage "INFO: configuring certs for pENM"
        ${CONFIGURE_CERTS}
    fi

    if [ "${cENM_DEPLOYMENT}" != TRUE ]; then
       # remove lock file
       ${RM_RF} ${SHARE_ROOT}/opendj_certs.lock
       # remove old lock file (used during previous installations)
       ${RM_RF} ${SHARE_ROOT}/certs.lock
    fi

    LogMessage "INFO: ExtractAndConfigureCerts completed successfully"
    info "ExtractAndConfigureCerts completed successfully"
    return 0
}

#################################################################
# HardenPasskeys: changes mode of passkey files to 440
# Arguments: None
# Returns:
#   0      Success
#   1      Failure
#################################################################

HardenPasskeys(){
    LogMessage "INFO: HardenPasskeys invoked, processing request .........."

    FILES_TO_HARDENING=(idmmysql_passkey openidm_passkey postgresql01_passkey opendj_passkey secadmin_passkey ssoldap_passkey neo4j_passkey)

    for FILE in ${FILES_TO_HARDENING[*]}
    do
        $CHOWN root:$GROUPNAME $IDENMGMT_COMMON_DIR/$FILE
        if [ $? != 0 ] ; then
            LogMessage "ERROR: Failed to change $FILE owner and group "
            error "Failed to change $FILE owner and group "
            return 1
        fi

        $CHMOD 440 $IDENMGMT_COMMON_DIR/$FILE
        if [ $? != 0 ] ; then
            LogMessage "ERROR: Failed to change $FILE mode "
            error "Failed to change $FILE mode "
            return 1
        fi
    done

    LogMessage "INFO: HardenPasskeys completed successfully"
    info "HardenPasskeys completed successfully"
    return 0
}

#################################################################
# HardenCerts: changes mode of certificates to 600
# Arguments: None
#
# Returns:
#   0      Success
#   1      Failure
#################################################################

HardenCerts()
{
    LogMessage "INFO: HardenCerts invoked, processing request .........."

    output=$($CHMOD -R 600 ${ROOTCA_DIR}/sso ${ROOTCA_DIR}/rootCA.* 2>&1)
    if [ $? != 0 ]; then
        LogMessage "ERROR: Failed to change permission for certificate files, ${output}"
        error "Failed to change permission for certificate files, ${output}"
        return 1
    fi
   output=$($CHOWN -R opendj:opendj ${ROOTCA_DIR}/sso ${ROOTCA_DIR}/rootCA.* 2>&1)
    if [ $? != 0 ]; then
        LogMessage "ERROR: Failed to change owner for certificates files, ${output}"
        error "Failed to change owner for certificates files, ${output}"
        return 1
    fi
    output=$($CHMOD -R 644 ${ROOTCA_DIR}/rootCA.pem 2>&1)
    if [ $? != 0 ]; then
        LogMessage "ERROR: Failed to change permission for rootCA.pem , ${output}"
        error "Failed to change permission for file rootCA.pem, ${output}"
        return 1
    fi
    LogMessage "INFO: HardenCerts completed successfully"
    info "HardenCerts completed successfully"
    return 0
}

#################################################################
# ExportLDIF: Export LDIF for the 3pp uplift vapp only
# Arguments: None
# Returns:
#   0      Success
#   1      Failure
#################################################################
ExportLDIF()
{
   LogMessage "INFO: ExportLDIF invoked, processing request .........."
   if [ "$LDAP_HOST" == $LDAP_LOCAL ]; then
      if [ "$OLD_OPENDJ_VERSION" != "$NEW_OPENDJ_VERSION" ]; then
          mkdir -p $OPENDJ_TMP
          if [ $? != 0 ] ; then
            LogMessage "ERROR: Failed to create directory $OPENDJ_TMP"
            error "Failed to create directory $OPENDJ_TMP"
            return 1
          fi

          $CHOWN -R opendj:opendj $OPENDJ_TMP
          if [ $? -ne 0 ]; then
             LogMessage "ERROR: failed to chown $OPENDJ_TMP"
             error "Failed to chown $OPENDJ_TMP"
             return 1
          fi

          StopDS
          if [ $? != 0 ] ; then
             LogMessage "ERROR: StopDS failed"
             error "StopDS failed"
             return 1
          fi

          LogMessage "INFO: Exporting userRoot backend to LDIF file" 2>&1 | tee -a "${UPL_LOG}"
          if [ "$OLD_OPENDJ_VERSION" != "3.0.0" ]; then
            su opendj -c "$EXPORT_LDIF --backendID userRoot --offline --ldifFile $OPENDJ_TMP/userRoot.ldif --includeBranch '$BASE_DN' --no-prompt " 2>&1 | tee -a "${UPL_LOG}"
          else
            su opendj -c "$EXPORT_LDIF --backendID userRoot --includeBranch '$BASE_DN' --ldifFile $OPENDJ_TMP/userRoot.ldif" 2>&1 | tee -a "${UPL_LOG}"
          fi
          
          rr=${PIPESTATUS[0]}
          if [ $rr -ne 0 ]; then
             LogMessage "ERROR: failed to export userRoot backend to LDIF file" 2>&1 | tee -a "${UPL_LOG}"
             error "Failed to export userRoot backend to LDIF file"
             return 1
          else
             LogMessage "INFO: Successfully exported LDIF to a file" 2>&1 | tee -a "${UPL_LOG}"
          fi
      else
         LogMessage "INFO: Not a 3pp uplift, no ExportLDIF required"
         info "Not a 3pp uplift, no ExportLDIF required"
         return 0
      fi
   else
      LogMessage "INFO: Not a vapp install, no ExportLDIF required"
      info "Not a vapp install, no ExportLDIF required"
      return 0
   fi

   LogMessage "INFO: ExportLDIF completed"
   info "ExportLDIF completed"
   return 0
}

#################################################################
# ImportLDIF: Import LDIF for the 3pp uplift vapp only
# Arguments: None
# Returns:
#   0      Success
#   1      Failure
#################################################################
ImportLDIF()
{
   LogMessage "INFO: ImportLDIF Vapp invoked, processing request .........." | tee -a "${UPL_LOG}"
   su opendj -c "$IMPORT_LDIF --backendID userRoot --offline --includeBranch "$BASE_DN" --ldifFile $OPENDJ_TMP/userRoot.ldif --no-prompt" 2>&1 | tee -a "${UPL_LOG}"
   rr=${PIPESTATUS[0]}
   if [ $rr -ne 0 ]; then
       LogMessage "ERROR: failed to import userRoot backend from LDIF file - Vapp only" | tee -a "${UPL_LOG}"
       error "Failed to import userRoot backend from LDIF file - Vapp only"
       return 1
   else
       LogMessage "INFO: Successfully imported LDIF file to the userRoot backend - Vapp only" | tee -a "${UPL_LOG}"
   fi

   LogMessage "INFO: Removing temporary folder $OPENDJ_TMP along with exported LDIF"
   ${RM_RF} $OPENDJ_TMP
   if [ $? != 0 ] ; then
       LogMessage "ERROR: Can't remove the $OPENDJ_TMP folder"
       return 1
   fi

   LogMessage "INFO: ImportLDIF Vapp completed"
   info "ImportLDIF Vapp completed"
   return 0
}

#######################################################
# Improve Parameters for Heap Memory usage
#    je-backend-shared-cache-enabled:false  
#
# Arguments: None
# Returns:
#   0      Success
#   1      Failure
########################################################
ImproveConfigParametersHeapMemory()
{
    LogMessage "INFO: ImproveConfigParametersHeapMemory invoked, processing request......"

    #Setting backend-shared 
    $DSCONFIG set-global-configuration-prop -h localhost -p $ADMIN_CONNECTOR_PORT -D "$DM_DN" -w "$DM_PWD" --trustAll -n --set je-backend-shared-cache-enabled:false --no-prompt
    rr=${PIPESTATUS[0]}
    if [ $rr -ne 0 ]; then
         LogMessage "INFO: failed to set je-backend-shared-cache-enabled"
         info "Failed to set je-backend-shared-cache-enabled"
    else
         LogMessage "INFO: Set je-backend-shared-cache-enabled"
    fi

    LogMessage "INFO: ImproveConfigParametersHeapMemory completed"
    info "ImproveConfigParametersHeapMemory completed"
    return 0 

}


#######################################################
# Security settings:
# Set unauthenticated-requests-policy: allow-discovery
#
# Arguments: None
# Returns:
#   0      Success
#   1      Failure
########################################################
SetUnauthenticatedRequestsPolicy()
{
    LogMessage "INFO: SetUnauthenticatedRequestsPolicy invoked, processing request......"

    #Setting backend-shared 
    $DSCONFIG set-global-configuration-prop -h localhost -p $ADMIN_CONNECTOR_PORT -D "$DM_DN" -w "$DM_PWD" --trustAll -n --set unauthenticated-requests-policy:allow --no-prompt
    rr=${PIPESTATUS[0]}
    if [ $rr -ne 0 ]; then
         LogMessage "INFO: failed to set unauthenticated-requests-policy:allow"
         info "Failed to set unauthenticated-requests-policy:allow"
    else
         LogMessage "INFO: Set unauthenticated-requests-policy:allow"
    fi

    LogMessage "INFO: SetUnauthenticatedRequestsPolicy completed"
    info "SetUnauthenticatedRequestsPolicy completed"
    return 0 

}

#######################################################
# SetUidNumberAsIndex
#    - read uidNumber parameter;
#    - if UidNumber is not Index than it is set to Index
#    - finally a rebuild is made for uidNumber parameter
#
# Arguments: None
# Returns:
#   0      Success
#   1      Failure
########################################################
SetUidNumberAsIndex()
{
    LogMessage "INFO: SetUidNumberAsIndex invoked, processing request......"
    info "SetUidNumberAsIndex invoked, processing request......"

    LogMessage "INFO: Getting list of all indexes ......"
    info "Getting list of all indexes ......"

    IS_UIDNUMBER_INDEX=`$DSCONFIG list-backend-indexes --backend-name userRoot -h localhost -p $ADMIN_CONNECTOR_PORT  -D "$DM_DN" -w "$DM_PWD" --trustAll --no-prompt| grep uidNumber| grep equality| wc -l`
    rr=${PIPESTATUS[0]}
    if [ $rr -ne 0 ]; then
         LogMessage "ERROR: failed to get indexes"
         error "Failed to to get indexes"
	 return 1
    else
         if [ $IS_UIDNUMBER_INDEX -ne 0 ]; then
            LogMessage "INFO: uidNumber is already set as Index: exit ..."
            info "uidNumber is already set as Index: exit ..."
	    return 0
         else
            LogMessage "INFO: uidNumber will be set as Index"
            info "uidNumber will be set as Index"
         fi
    fi

    LogMessage "INFO: Setting uidNumber as Index ......"
    info "Setting uidNumber as Index ......"

    $DSCONFIG create-backend-index -h localhost -p $ADMIN_CONNECTOR_PORT -D "$DM_DN" -w "$DM_PWD" --backend-name userRoot --set "index-type:equality" --type generic --index-name uidNumber --trustAll --no-prompt
    rr=${PIPESTATUS[0]}
    if [ $rr -ne 0 ]; then
         LogMessage "ERROR: failed to set uidNumber as Index: exit ..."
         error "Failed to set uidNumber as Index: exit ..."
	 return 1
    else
         LogMessage "INFO: Set uidNumber as Index with success"
	 info "Set uidNumber as Index with success"
    fi

    LogMessage "INFO: rebuilding indexes for uidNUmber ......"
    info "rebuilding indexes for uidNUmber ......"

    $REBUILD_INDEX -h localhost -p $ADMIN_CONNECTOR_PORT -D "$DM_DN" -w "$DM_PWD" --baseDN "$BASE_DN" --index uidNumber --trustAll --no-prompt
    rr=${PIPESTATUS[0]}
    if [ $rr -ne 0 ]; then
         LogMessage "ERROR: failed to rebuild indexes for uidNumber: exit ..."
         error "Failed to rebuild indexes for uidNumber: exit ..."
         return 1
    else
         LogMessage "INFO: rebuild indexes for uidNumber completed"
         info "rebuild indexes for uidNumber completed"
    fi

    LogMessage "INFO:  SetUidNumberAsIndex completed"
    info " SetUidNumberAsIndex completed"
    return 0

}

#######################################################
# Changelog option disabled for heap memory perfs
#    changelog-enabled:disabled
#
# Arguments: None
# Returns:
#   0      Success
#   1      Failure
########################################################
ChangelogEnabledDisable()
{
    LogMessage "INFO: ChangelogEnabledDisable invoked, processing request......"

    $DSCONFIG set-replication-server-prop -h localhost -p $ADMIN_CONNECTOR_PORT -D "$DM_DN" -w "$DM_PWD" --trustAll -n --provider-name "Multimaster Synchronization" --set changelog-enabled:disabled --no-prompt
    rr=${PIPESTATUS[0]}
    if [ $rr -ne 0 ]; then
         LogMessage "INFO: failed to set changelog-enabled"
         info "Failed to set changelog-enabled"
    else
         LogMessage "INFO: Set changelog-enabled"
    fi

    LogMessage "INFO: ChangelogEnabledDisable completed"
    info "ChangelogEnabledDisable completed"
    return 0 

}

#######################################################
# Change purge delay for replication
#    replication-purge-delay:8h
#
# Arguments: None
# Returns:
#   0      Success
#   1      Failure
########################################################
ChangePurgeDelay()
{
    LogMessage "INFO: ChangePurgeDelay invoked, processing request......"

    if [ "${DDC_ON_CLOUD}" == TRUE ] || [ "${cENM_DEPLOYMENT}" == TRUE ] ; then
        LogMessage "INFO: Setting PurgeDelay for CLOUD : $REPLICATION_PURGE_DELAY_CLOUD"
        $DSCONFIG set-synchronization-provider-prop -h localhost -p $ADMIN_CONNECTOR_PORT -D "$DM_DN" -w "$DM_PWD" --trustAll -n --provider-name "Multimaster Synchronization" --set replication-purge-delay:$REPLICATION_PURGE_DELAY_CLOUD --no-prompt
    else
        LogMessage "INFO: Setting PurgeDelay for pENM : $REPLICATION_PURGE_DELAY_pENM"
        $DSCONFIG set-synchronization-provider-prop -h localhost -p $ADMIN_CONNECTOR_PORT -D "$DM_DN" -w "$DM_PWD" --trustAll -n --provider-name "Multimaster Synchronization" --set replication-purge-delay:$REPLICATION_PURGE_DELAY_pENM --no-prompt
    fi

    rr=${PIPESTATUS[0]}
    if [ $rr -ne 0 ]; then
         LogMessage "INFO: failed to set replication-purge-delay with error $rr"
         info "Failed to set replication-purge-delay with error $rr"
    else
         LogMessage "INFO: Set replication-purge-delay"
    fi

    LogMessage "INFO: ChangePurgeDelay completed"
    info "ChangePurgeDelay completed"
    return 0

}

########################################################
# Apply patches for OpenDJ
# Arguments: None
# Returns:
#   0      Success
#   1      Failure
########################################################
ApplyPatches() 
{
  LogMessage "INFO: Applying OpenDJ patches"

  OPENDJ_PATCHES=${IDENMGMT_ROOT}/opendj/pkg/OpenDJ-6.5.0-patches.tar

  #Removes old patches before applying new ones
  if [ -d $OPENDJ_ROOT/classes ]; then
     ${RM_RF} $OPENDJ_ROOT/classes
     if [ $? != 0 ] ; then
         LogMessage "ERROR: Failed to remove old patches"
         error "Failed to remove old patches"
         return 1
     else
         LogMessage "INFO: Successfully removed old patches"
     fi
  fi

  tar --overwrite -xvf $OPENDJ_PATCHES -C $OPENDJ_ROOT/
  if [ $? != 0 ]; then
      LogMessage "ERROR: failed to expand OpenDJ-6.5.0-patches.tar"
      error "Failed to expand OpenDJ-6.5.0-patches.tar"
      return 1
  fi

  $CHOWN -R opendj:opendj $OPENDJ_ROOT
  if [ $? -ne 0 ]; then
    LogMessage "ERROR: failed to chown $OPENDJ_ROOT"
    error "Failed to chown $OPENDJ_ROOT"
    return 1
  fi

  LogMessage "INFO: OPENDJ patches applied successfully"
  info "OPENDJ patches applied successfully"
  return 0
}


########################################################
# HardenBinFiles:755 permission on bin files 
#
# Arguments: None
# Returns:
#   0      Success
#   1      Failure
########################################################
HardenBinFiles()
{
    LogMessage "INFO: HardenBinFiles, processing request......"

    $CHMOD 755 $OPENDJ_ROOT/bin/*
    if [ $? -ne 0 ]; then
        LogMessage "ERROR: failed to chmod 755 $OPENDJ_ROOT/bin/*"
        error "Failed to chmod 755 $OPENDJ_ROOT/bin/*"
        return 1
    fi


    $CHMOD 755 $OPENDJ_ROOT/lib/*
    if [ $? -ne 0 ]; then
        LogMessage "ERROR: failed to chmod 755 $OPENDJ_ROOT/lib/*"
        error "Failed to chmod 755 $OPENDJ_ROOT/lib/*"
        return 1
    fi

    $CHMOD go-w -R $OPENDJ_ROOT
    if [ $? -ne 0 ]; then
        LogMessage "ERROR: failed to chmod go-w -R $OPENDJ_ROOT"
        error "Failed to chmod go-w -R $OPENDJ_ROOT"
        return 1
    fi

    return 0
}

#######################################
# Function: AdminCleanUp
#
# Description: This function checks:
#              - both DS have a version >= 7.3.3
#              - there was an upg from version 6.5.0/6.5.5
#              - there are still no more used data from rel 6.5.0/6.5.5
#
# Action: clean no more used data coming from rel 6.5.0/6.5.5
#
# Arguments:
#   None
#
# Returns:
#   0 - success
#   1 - failure
#######################################
AdminCleanUp(){

if [ "$OLD_OPENDJ_VERSION" == "6.5.0" ] || [ "$OLD_OPENDJ_VERSION" == "6.5.5" ]; then
     $DSCONFIG get-replication-domain-prop --provider-name "Multimaster Synchronization" --domain-name $BASE_DN -h $LDAP_PEER -p $ADMIN_CONNECTOR_PORT -D "$DM_DN" -X -w "$DM_PWD" -n
     ret=$?
     if [ $ret == 0 ]; then

     LogMessage "INFO: Starting AdminCleanUp ..."
     info "Starting AdminCleanUp ..."


        # To Run some commands on both the instances of opendj
        HOSTLIST=("$LDAP_PEER" "$LDAP_HOST")


        # Admin Data cleaning
        LogMessage "INFO: start cleaning admin data ..."
        info "start cleaning admin data ..."

        # Delete data of add_pre_topolopy
        $DSREPLICATION \
        cleanup-migrated-pre-7-0-topology \
        --bindDn "$DM_DN" \
        --bindPassword "$DM_PWD" \
        --hostname localhost \
        --port $ADMIN_CONNECTOR_PORT \
        -X \
        --no-prompt

        rr=$?
        if [ $rr -ne 0 ]; then
           LogMessage "ERROR: failed to delete data for old repl. mngt." 2>&1 | tee -a "${UPL_LOG}"
           error "Failed to delete data for old repl. mngt"
        else
           LogMessage "INFO: Successfully deleted data for old repl. mngt." 2>&1 | tee -a "${UPL_LOG}"
           info "Successfully deleted data for old repl. mngt."
        fi


        for ds in ${HOSTLIST[@]}; do

            # Delete "Crypto Manager Key Manager" 20 1)  Crypto Manager Key Manager
            $DSCONFIG \
            delete-key-manager-provider \
            --provider-name "Crypto Manager Key Manager" \
            --hostname $ds \
            --port $ADMIN_CONNECTOR_PORT \
            --bindDn "$DM_DN" \
            -X \
            --bindPassword "$DM_PWD" \
            --no-prompt

            rr=$?
            if [ $rr -ne 0 ] && [ $rr -ne 32 ] ; then
               LogMessage "ERROR: Failed to delete Crypto Manager Key Manager; error code is [$rr]" | tee -a "${UPL_LOG}"
               error "Failed to to delete Crypto Manager Key Manager; error code is [$rr]"
            else
               LogMessage "INFO: Successfully deleted Crypto Manager Key Manager." 2>&1 | tee -a "${UPL_LOG}"
               info "Successfully deleted Crypto Manager Key Manager."
            fi


            # Delete "Replication Key Manager 20 4)  Replication Key Manager"

            $DSCONFIG \
            delete-key-manager-provider \
            --provider-name "Replication Key Manager" \
            --hostname $ds \
            --port $ADMIN_CONNECTOR_PORT \
            --bindDn "$DM_DN" \
            -X \
            --bindPassword "$DM_PWD" \
            --no-prompt

            rr=$?
            if [ $rr -ne 0 ] && [ $rr -ne 32 ] ; then
               LogMessage "ERROR: Failed to delete Replication Key Manager; error code is [$rr]" | tee -a "${UPL_LOG}"
               error "Failed to to delete Replication Key Manager; error code is [$rr]"
            else
               LogMessage "INFO: Successfully deleted Replication Key Manager." 2>&1 | tee -a "${UPL_LOG}"
               info "Successfully deleted Replication Key Manager."
            fi

            # Delete "Replication Trust Manager 38 5)  Replication Trust Manager

            $DSCONFIG \
            delete-trust-manager-provider \
            --provider-name "Replication Trust Manager" \
            --hostname $ds \
            --port $ADMIN_CONNECTOR_PORT \
            --bindDn "$DM_DN" \
            -X \
            --bindPassword "$DM_PWD" \
            --no-prompt

            rr=$?
            if [ $rr -ne 0 ] && [ $rr -ne 32 ] ; then
               LogMessage "ERROR: Failed to delete Replication Trust Manager; error code is [$rr]" | tee -a "${UPL_LOG}"
               error "Failed to to delete Replication Trust Manager; error code is [$rr]"
            else
               LogMessage "INFO: Successfully deleted Replication Trust Manager." 2>&1 | tee -a "${UPL_LOG}"
               info "Successfully deleted Replication Trust Manager."
            fi

            # Delete "cn=admin data" replication domain 31 1
            $DSCONFIG delete-replication-domain \
            --provider-name Multimaster\ Synchronization \
            --domain-name cn=admin\ data \
            --hostname $ds \
            --port $ADMIN_CONNECTOR_PORT \
            --bindDn "$DM_DN" \
            -X \
            --bindPassword "$DM_PWD" \
            --no-prompt

            rr=$?
            if [ $rr -ne 0 ] && [ $rr -ne 32 ] ; then
               LogMessage "ERROR: Failed to delete cn=admin data replication domain; error code is [$rr]" | tee -a "${UPL_LOG}"
               error "Failed to delete cn=admin data replication domain; error code is [$rr]"
            else
               LogMessage "INFO: Successfully deleted cn=admin data replication domain." 2>&1 | tee -a "${UPL_LOG}"
               info "Successfully deleted cn=admin data replication domain."
            fi

            # Delete "adminRoot" backend 6 1
            $DSCONFIG \
            delete-backend \
            --backend-name adminRoot \
            --hostname $ds \
            --port $ADMIN_CONNECTOR_PORT \
            --bindDn "$DM_DN" \
            -X \
            --bindPassword "$DM_PWD" \
            --no-prompt

            rr=$?
            if [ $rr -ne 0 ] && [ $rr -ne 32 ] ; then
               LogMessage "ERROR: Failed to delete adminRoot backend; error code is [$rr]" | tee -a "${UPL_LOG}"
               error "Failed to delete adminRoot backend; error code is [$rr]"
            else
               LogMessage "INFO: Successfully deleted adminRoot backend." 2>&1 | tee -a "${UPL_LOG}"
               info "Successfully deleted adminRoot backend."
            fi
            # REPLICATION SERVER 32 2   3)  changelog-enabled-excluded-domains  cn=admin data, cn=schema
            #     Specifies the base DNs of domains to exclude from the change number
            #    indexing when changelog is enabled.
            #
            #    Syntax:  DN
            #
            #The "changelog-enabled-excluded-domains" property has the following values:
            #
            #    *)  cn=admin data
            #    *)  cn=schema
            #
            #Do you want to modify the "changelog-enabled-excluded-domains" property?
            #
            #    1)  Keep these values
            #    2)  Add one or more values
            #    3)  Remove one or more values
            #    4)  Reset to the default behavior: When changelog is enabled, searches
            #        using "change numbers" is available for all domains (in other words,
            #        change number indexing includes all domains).

            $DSCONFIG set-replication-server-prop \
            --provider-name Multimaster\ Synchronization \
            --reset changelog-enabled-excluded-domains \
            --hostname $ds \
            --port $ADMIN_CONNECTOR_PORT \
            --bindDn "$DM_DN" \
            -X \
            --bindPassword "$DM_PWD" \
            --no-prompt

            rr=$?
            if [ $rr -ne 0 ]; then
               LogMessage "ERROR: failed to reset changelog-enabled-excluded-domains." 2>&1 | tee -a "${UPL_LOG}"
               error "Failed to reset changelog-enabled-excluded-domains."
            else
               LogMessage "INFO: Successfully reset changelog-enabled-excluded-domains." 2>&1 | tee -a "${UPL_LOG}"
               info "Successfully reset changelog-enabled-excluded-domains."
            fi
            # Synchronization Provider 37 2 no su entrambe PKCS12
            #$DSCONFIG set-synchronization-provider-prop \
            # --provider-name Multimaster\ Synchronization \
            # --remove trust-manager-provider:Admin\ Data \
            # --hostname $ds \
            # --port $ADMIN_CONNECTOR_PORT \
            # --bindDn "$DM_DN" \
            # -X \
            # --bindPassword "$DM_PWD" \
            # --no-prompt

            #rr=$?
            #if [ $rr -ne 0 ]; then
            #   LogMessage "ERROR: failed to remove trust-manager-provider Admin Data from Multimaster Synchronization." 2>&1 | tee -a "${UPL_LOG}"
            #   error "Failed to remove trust-manager-provider Admin Data from Multimaster Synchronization."
            #else
            #   LogMessage "INFO: Successfully removed trust-manager-provider Admin Data from Multimaster Synchronization." 2>&1 | tee -a "${UPL_LOG}"
            #   info "Successfully removed trust-manager-provider Admin Data from Multimaster Synchronization."
            #fi

            # 38)  Trust Manager Provider non c'e su opendj-0
            #
            #$DSCONFIG set-trust-manager-provider-prop \
            # --provider-name Admin\ Data \
            # --set enabled:false \
            # --hostname $ds \
            # --port $ADMIN_CONNECTOR_PORT \
            # --bindDn "$DM_DN" \
            # -X \
            # --bindPassword "$DM_PWD" \
            # --no-prompt
            #
            #rr=$?
            #if [ $rr -ne 0 ] && [ $rr -ne 32 ]; then
            #   LogMessage "ERROR: failed to disable trust-manager-provider Admin Data; error code is [$rr]." 2>&1 | tee -a "${UPL_LOG}"
            #   error "Failed to disable trust-manager-provider Admin Data; error code is [$rr]."
            #else
            #   LogMessage "INFO: Successfully disable trust-manager-provider Admin Data." 2>&1 | tee -a "${UPL_LOG}"
            #   info "Successfully disable trust-manager-provider Admin Data."
            #fi

            # 38)  Trust Manager Provider non c'e su opendj-0
            #$DSCONFIG delete-trust-manager-provider \
            # --provider-name Admin\ Data \
            # --hostname $ds \
            # --port $ADMIN_CONNECTOR_PORT \
            # --bindDn "$DM_DN" \
            # -X \
            # --bindPassword "$DM_PWD" \
            # --no-prompt
            #
            #rr=$?
            #if [ $rr -ne 0 ] && [ $rr -ne 32 ]; then
            #   LogMessage "ERROR: failed to remove trust-manager-provider Admin Data; error code is [$rr]." 2>&1 | tee -a "${UPL_LOG}"
            #   error "Failed to remove trust-manager-provider Admin Data; error code is [$rr]."
            #else
            #   LogMessage "INFO: Successfully removed trust-manager-provider Admin Data." 2>&1 | tee -a "${UPL_LOG}"
            #   info "Successfully removed trust-manager-provider Admin Data."
            #fi

            # create plugin "Entity Tag"
            $DSCONFIG create-plugin \
             --plugin-name "Entity Tag" \
             --type entity-tag \
             --set enabled:true \
             --set invoke-for-internal-operations:true \
             --hostname $ds \
             --port $ADMIN_CONNECTOR_PORT \
             --bindDN "$DM_DN" \
             --bindPassword "$DM_PWD" \
             -X \
             --no-prompt

            rr=$?
            if [ $rr -ne 0 ] && [ $rr -ne 68 ] ; then
               LogMessage "ERROR: Failed to create plugin Entity Tag; error code is [$rr]" | tee -a "${UPL_LOG}"
               error "Failed to create plugin Entity Tag; error code is [$rr]"
            else
               LogMessage "INFO: Successfully created plugin Entity Tag." 2>&1 | tee -a "${UPL_LOG}"
               info "Successfully created plugin Entity Tag."
            fi

        done

        if [ "$cENM_DEPLOYMENT" == TRUE ] ; then
           ${RM_RF} /ericsson/opendj/opendj/db/adminRoot
           ${RM_RF} $OPENDJ_ROOT/db/adminRoot
        else
           ${RM_RF} $OPENDJ_ROOT/db/adminRoot
        fi
        if [ $? != 0 ] ; then
           LogMessage "ERROR: Failed to remove $OPENDJ_ROOT/db/adminRoot dir."
           error "Failed to remove /../opendj/db/adminRoot dir."
        else
           LogMessage "INFO: Successfully removed $OPENDJ_ROOT/db/adminRoot dir."
        fi

        if [ "$cENM_DEPLOYMENT" == TRUE ] ; then
           ${RM_RF} /ericsson/opendj/opendj/db/ads-truststore
           ${RM_RF} $OPENDJ_ROOT/db/ads-truststore
        else
           ${RM_RF} $OPENDJ_ROOT/db/ads-truststore
        fi
        if [ $? != 0 ] ; then
           LogMessage "ERROR: Failed to remove $OPENDJ_ROOT/db/ads-truststore dir."
           error "Failed to remove /../opendj/db/ads-truststore dir."
        else
           LogMessage "INFO: Successfully removed $OPENDJ_ROOT/db/ads-truststore dir."
        fi

   LogMessage "INFO: AdminCleanUp completed ..."
   info "AdminCleanUp completed ..."
   fi
fi
return 0

}

#######################################
# Function: RemoveOldAdminDataDB
#
# Description: This function checks:
#              - both DS have a version >= 7.3.3
#              - there was an upg from version 6.5.0/6.5.5
#              - there are still no more used data from rel 6.5.0/6.5.5
#
# Action: clean no more used data coming from rel 6.5.0/6.5.5
#
# Arguments:
#   None
#
# Returns:
#   0 - success
#   1 - failure
#######################################
RemoveOldAdminDataDB(){

$DSCONFIG get-replication-domain-prop --provider-name "Multimaster Synchronization" --domain-name $BASE_DN -h $LDAP_PEER -p $ADMIN_CONNECTOR_PORT -D "$DM_DN" -X -w "$DM_PWD" -n
ret1=$?

# $DSCONFIG get-backend-prop --backend-name adminRoot --hostname localhost -p $ADMIN_CONNECTOR_PORT -D "$DM_DN" -X -w "$DM_PWD" -n
$DSCONFIG --offline get-backend-prop --backend-name adminRoot -n
ret2=$?
if [ $ret1 == 0 ] && [ $ret2 == 32 ]; then

    if [ -d $OPENDJ_ROOT/db/adminRoot ] ; then

        LogMessage "INFO: Starting RemoveOldAdminDataDB ..."
        info "Starting RemoveOldAdminDataDB ..."

        if [ "$cENM_DEPLOYMENT" == TRUE ] ; then
           ${RM_RF} /ericsson/opendj/opendj/db/adminRoot
           ${RM_RF} $OPENDJ_ROOT/db/adminRoot
        else
           ${RM_RF} $OPENDJ_ROOT/db/adminRoot
        fi
        if [ $? != 0 ] ; then
           LogMessage "ERROR: Failed to remove /../opendj/db/adminRoot dir."
           error "Failed to remove /../opendj/db/adminRoot dir."
        else
           LogMessage "INFO: Successfully removed /../opendj/db/adminRoot dir."
        fi

        if [ "$cENM_DEPLOYMENT" == TRUE ] ; then
           ${RM_RF} /ericsson/opendj/opendj/db/ads-truststore
           ${RM_RF} $OPENDJ_ROOT/db/ads-truststore
        else
           ${RM_RF} $OPENDJ_ROOT/db/ads-truststore
        fi
        if [ $? != 0 ] ; then
           LogMessage "ERROR: Failed to remove /../opendj/db/ads-truststore dir."
           error "Failed to remove /../opendj/db/ads-truststore dir."
        else
           LogMessage "INFO: Successfully removed /../opendj/db/ads-truststore dir."
        fi

       LogMessage "INFO: RemoveOldAdminDataDB completed ..."
       info "RemoveOldAdminDataDB completed ..."
    fi

fi
return 0

}

#################################################################
# MakeHybridReplicationWork
# Arguments: no parameter
#
# Description: this function make replication work between
#              the first DS upgraded to rel 7.3.3 with the other
#              DS still in rel 6.5.0/6.5.5
#
# Returns:
#   0      Success
#   1      Failure
#################################################################
MakeHybridReplicationWork()
{

LogMessage "INFO: MakeHybridReplicationWork invoked, processing request .........."

IsSingleOpendj
if [ $? == 0 ]; then
   LogMessage "Vapp or vENM transport installiation, no MakeHybridReplicationWork needed ..."
   return 0
fi

$DSCONFIG get-replication-domain-prop --provider-name "Multimaster Synchronization" --domain-name $BASE_DN -h $LDAP_PEER -p $ADMIN_CONNECTOR_PORT -D "$DM_DN" -X -w "$DM_PWD" -n 

ret=$?
if [ $ret == 9 ]; then

   $DSREPLICATION add-local-server-to-pre-7-0-topology \
   --hostname $LDAP_PEER \
   --port $ADMIN_CONNECTOR_PORT \
   --bindDn "cn=$REPLICATION_ADMIN_UID,cn=Administrators,cn=admin data" \
   --bindPassword "$DM_PWD" \
   --baseDn "$BASE_DN" \
   --trustAll \
   --no-prompt

   if [ $? -ne 0 ]; then
      LogMessage "ERROR: failed to setup hybrid replication between $LDAP_LOCAL and $LDAP_PEER" | tee -a "${UPL_LOG}"
      error "Failed to setup hybrid replication between $LDAP_LOCAL and $LDAP_PEER"
      return 1
   else
      LogMessage "INFO: Hybrid Replication successfully created between $LDAP_LOCAL and $LDAP_PEER" | tee -a "${UPL_LOG}"
      info "Hybrid Replication successfully created between $LDAP_LOCAL and $LDAP_PEER"
   fi

elif [ $ret == 91 ]; then

   LogMessage "ERROR: Enable to connect to DS $LDAP_PEER" | tee -a "${UPL_LOG}"
   error "Enable to connect to DS $LDAP_PEER"

elif [ $ret == 0 ]; then

   LogMessage "INFO: Both DS are in 7.3.3, no MakeHybridReplicationWork needed ..."
   info "Both DS are in 7.3.3, no MakeHybridReplicationWork needed ..."

else

   LogMessage "ERROR: Received error=$ret while connecting to ds $LDAP_PEER" | tee -a "${UPL_LOG}"
   error "Received error=$ret while connecting to ds $LDAP_PEER"

fi

LogMessage "INFO: MakeHybridReplicationWork complete"
info "MakeHybridReplicationWork complete"
return 0

}

#################################################################
# SetSecurityModel 
# Arguments: no parameter 
#                      
#
# Returns:
#   0      Success
#   1      Failure
#################################################################
SetSecurityModel()
{

OLD_ALIAS=server-cert
NEW_ALIAS=ssl-key-pair

OPENDJ_BIN=$OPENDJ_ROOT/bin
OPENDJ_CONFIG=$OPENDJ_ROOT/config
OPENDJ_DB=$OPENDJ_ROOT/db

# Add a shared master key based on the deployment ID:
su opendj -c "$DSKEYMGR export-master-key-pair --alias master-key --deploymentId $DEPLOYMENT_ID --deploymentIdPassword $DEPLOYMENT_ID_PASSWORD --keyStoreFile $OPENDJ_CONFIG/keystore --keyStorePassword:file $OPENDJ_CONFIG/keystore.pin"
if [ $? != 0 ] ; then
   LogMessage "ERROR: dskeymgr failure"
   return 1
else
   LogMessage "DSKEYMGR MASTER KEY OK"
fi

# Import ads-truststore in keystore:
su opendj -c "$JAVA_KEYTOOL -importkeystore -srckeystore $OPENDJ_DB/ads-truststore/ads-truststore -srcstorepass:file $OPENDJ_DB/ads-truststore/ads-truststore.pin -destkeystore $OPENDJ_CONFIG/keystore -deststoretype PKCS12 -deststorepass:file $OPENDJ_CONFIG/keystore.pin"
if [ $? != 0 ] ; then
   LogMessage "ERROR: keytool failure"
   return 1
else
   LogMessage "ADS-TRUSTSTORE IMPORT OK"
fi

# Update some schema files
su opendj -c "cp $OPENDJ_ROOT/template/db/schema/00-core.ldif $OPENDJ_ROOT/db/schema"
su opendj -c "cp $OPENDJ_ROOT/template/db/schema/03-pwpolicyextension.ldif $OPENDJ_ROOT/db/schema"
su opendj -c "cp $OPENDJ_ROOT/template/db/schema/04-rfc2307bis.ldif $OPENDJ_ROOT/db/schema"

LogMessage "UPDATE SCHEMA FILES OK"

# first start of opendj 7.3.3
su opendj -c "${START_DS}"
if [ $? != 0 ] ; then
   LogMessage "ERROR: Failed first start of OpenDJ DS"
   error "Failed first start of OpenDJ DS"
   return 1
fi

if [ "$cENM_DEPLOYMENT" != TRUE ] ; then
    EnableTls_All
    if [ "$?" != "0" ] ; then
      LogMessage "ERROR: EnableTls_All failed"
      error "EnableTls_All failed"
      return 1
    fi
else
    EnableTls
    if [ "$?" != "0" ] ; then
      LogMessage "ERROR: EnableTls failed"
      error "EnableTls failed"
      return 1
    fi
fi

# Configure the server to wrap new secret keys
# using the new shared master key:
$OPENDJ_BIN/dsconfig set-crypto-manager-prop \
 --set key-manager-provider:"Default Key Manager" \
 --set master-key-alias:master-key \
 --reset digest-algorithm \
 --reset mac-algorithm \
 --reset key-wrapping-transformation \
 --hostname localhost \
 --port $ADMIN_CONNECTOR_PORT \
 --bindDN "$DM_DN" \
 --bindPassword "$DM_PWD" \
 --trustAll \
 --no-prompt

if [ $? != 0 ] ; then
   LogMessage "ERROR: dsconfig set-crypto-manager-prop failure"
   error "dsconfig set-crypto-manager-prop failure"
   return 1
else
   LogMessage "dsconfig set-crypto-manager-prop OK"
fi

$OPENDJ_BIN/dsconfig create-trust-manager-provider \
 --set enabled:true \
 --set trust-store-file:$OPENDJ_CONFIG/keystore \
 --set trust-store-pin:\&{file:$OPENDJ_CONFIG/keystore.pin} \
 --set trust-store-type:PKCS12 \
 --type file-based \
 --provider-name PKCS12 \
 --hostname localhost \
 --port $ADMIN_CONNECTOR_PORT \
 --bindDN "$DM_DN" \
 --bindPassword "$DM_PWD" \
 --trustAll \
 --no-prompt

if [ $? != 0 ] ; then
   LogMessage "ERROR: dsconfig create-trust-manager-provider PKCS12 failure"
   error"dsconfig create-trust-manager-provider PKCS12 failure"
   return 1
else
   LogMessage "dsconfig create-trust-manager-provider PKCS12 OK"
fi

$OPENDJ_BIN/dsconfig set-synchronization-provider-prop \
 --provider-name "Multimaster Synchronization" \
 --set key-manager-provider:"Default Key Manager" \
 --set ssl-cert-nickname:ssl-key-pair \
 --set trust-manager-provider:PKCS12 \
 --hostname localhost \
 --port $ADMIN_CONNECTOR_PORT \
 --bindDN "$DM_DN" \
 --bindPassword "$DM_PWD" \
 --trustAll \
 --no-prompt

if [ $? != 0 ] ; then
   LogMessage "ERROR: dsconfig set-synchronization-provider failure"
   error"dsconfig set-synchronization-provider failure"
   return 1
else
   LogMessage "dsconfig set-synchronization-provider ssl-cert-nickname:ssl-key-pair OK"
fi

# Switch to the new keys for other secure communications:
$OPENDJ_BIN/dsconfig set-connection-handler-prop \
 --handler-name HTTP \
 --set ssl-cert-nickname:ssl-key-pair \
 --set trust-manager-provider:PKCS12 \
 --hostname localhost \
 --port $ADMIN_CONNECTOR_PORT \
 --bindDN "$DM_DN" \
 --bindPassword "$DM_PWD" \
 --trustAll \
 --no-prompt

if [ $? != 0 ] ; then
   LogMessage "ERROR: dsconfig set-connection-handler-prop HTTP failure"
   error"dsconfig set-connection-handler-prop HTTP failure"
   return 1
else
   LogMessage "dsconfig set-connection-handler-prop HTTP ssl-cert-nickname:ssl-key-pair OK"
fi

$OPENDJ_BIN/dsconfig set-connection-handler-prop \
 --handler-name LDAPS \
 --set ssl-cert-nickname:ssl-key-pair \
 --set trust-manager-provider:PKCS12 \
 --hostname localhost \
 --port $ADMIN_CONNECTOR_PORT \
 --bindDN "$DM_DN" \
 --bindPassword "$DM_PWD" \
 --trustAll \
 --no-prompt

if [ $? != 0 ] ; then
   LogMessage "ERROR: dsconfig set-connection-handler-prop LDAPS failure"
   error"dsconfig set-connection-handler-prop LDAPS failure"
   return 1
else
   LogMessage "dsconfig set-connection-handler-prop LDAPS ssl-cert-nickname:ssl-key-pair OK"
fi

$OPENDJ_BIN/dsconfig set-connection-handler-prop \
 --handler-name JMX \
 --set ssl-cert-nickname:ssl-key-pair \
 --hostname localhost \
 --port $ADMIN_CONNECTOR_PORT \
 --bindDN "$DM_DN" \
 --bindPassword "$DM_PWD" \
 --trustAll \
 --no-prompt

if [ $? != 0 ] ; then
   LogMessage "ERROR: dsconfig set-connection-handler-prop JMX failure"
   error"dsconfig set-connection-handler-prop JMX failure"
   return 1
else
   LogMessage "dsconfig set-connection-handler-prop JMX ssl-cert-nickname:ssl-key-pair OK"
fi

# Switch to the new keys to secure
# administrative and replication communications:
$OPENDJ_BIN/dsconfig \
 set-administration-connector-prop \
 --set ssl-cert-nickname:ssl-key-pair \
 --set trust-manager-provider:PKCS12 \
 --hostname localhost \
 --port $ADMIN_CONNECTOR_PORT \
 --bindDN "$DM_DN" \
 --bindPassword "$DM_PWD" \
 --trustAll \
 --no-prompt

if [ $? != 0 ] ; then
   LogMessage "ERROR: dsconfig set-administration-connector-prop failure"
   error"dsconfig set-administration-connector-prop failure"
   return 1
else
   LogMessage "dsconfig set-administration-connector-prop ssl-cert-nickname:ssl-key-pair OK"
fi

su opendj -c "$JAVA_KEYTOOL -changealias -alias $OLD_ALIAS -destalias $NEW_ALIAS -keystore $OPENDJ_CONFIG/keystore < $OPENDJ_CONFIG/keystore.pin"
if [ $? != 0 ] ; then
   LogMessage "ERROR: changealias to $NEW_ALIAS failure"
   error"changealias to $NEW_ALIAS failure"
   exit 1
else
   LogMessage "Change alias on keystore from $OLD_ALIAS to $NEW_ALIAS OK"
fi

su opendj -c "${STOP_DS}"
if [ $? != 0 ] ; then
   LogMessage "ERROR: Failed to stop OpenDJ DS"
   error"Failed to stop OpenDJ DS"
   return 1
fi

LogMessage "INFO: SecurityModel completed"
info "SecurityModel completed"

return 0

}

########################################################
# UpgradeOpendj: Upgrades Opendj after a 3PP upversionning
#
# Arguments: None
# Returns:
#   0      Success
#   1      Failure
########################################################
UpgradeOpendj()
{
    LogMessage "INFO: UpgradeOpendj invoked, processing request......"

    #Setting logging to higher level for the upgrade
    $DSCONFIG set-log-publisher-prop \
      --publisher-name File-Based\ Debug\ Logger \
      --set enabled:true \
      --hostname localhost \
      --port $ADMIN_CONNECTOR_PORT \
      --bindDn "$DM_DN" \
      --bindPassword "$DM_PWD" \
      --trustAll \
      --no-prompt

    $CHMOD +x $OPENDJ_ROOT/upgrade $OPENDJ_ROOT/bin/* $OPENDJ_ROOT/lib/*
    if [ $? -ne 0 ]; then
        LogMessage "ERROR: failed to chmod +x $OPENDJ_ROOT/upgrade $OPENDJ_ROOT/bin/* $OPENDJ_ROOT/lib/*"
        error "Failed to chmod +x $OPENDJ_ROOT/upgrade $OPENDJ_ROOT/bin/* $OPENDJ_ROOT/lib/*"
        return 1
    fi

    $CHOWN -R opendj:opendj $OPENDJ_ROOT
    if [ $? -ne 0 ]; then
        LogMessage "ERROR: failed to chown $OPENDJ_ROOT"
        error "Failed to chown $OPENDJ_ROOT"
        return 1
    fi

    if [ "$LDAP_HOST" == $LDAP_LOCAL ]; then
       LogMessage "Vapp install,no StopDs needed"
    else
       StopDS
       if [ $? != 0 ] ; then
          LogMessage "ERROR: StopDS failed"
          error "StopDS failed during Opendj Upgrade"
          return 1
       fi
    fi

    #Removes je.jar file which may cause problems during upgrade, if present
    if [ -f $OPENDJ_ROOT/lib/je.jar ]; then
       ${RM_RF} $OPENDJ_ROOT/lib/je.jar
       if [ $? != 0 ] ; then
           LogMessage "ERROR: Failed to remove je.jar"
           error "Failed to remove je.jar"
           return 1
       else
           LogMessage "INFO: Successfully removed je.jar"
       fi
    fi

    LogMessage "INFO: Running OpenDJ upgrade command" | tee -a "${UPL_LOG}"
    su opendj -c "$UPGRADE --acceptLicense --no-prompt --force" 2>&1 | tee -a "${UPL_LOG}"
    rr=${PIPESTATUS[0]}
    if [ $rr -ne 0 ]; then
        LogMessage "ERROR: failed to upgrade opendj" | tee -a "${UPL_LOG}"
        error "Failed to upgrade opendj"
        if [[ "${DDC_ON_CLOUD}" == TRUE ]]; then
            LogMessage "INFO: On cloud, removing changelogDb (probably corrupted)" | tee -a "${UPL_LOG}"
            $RM_RF -rf $OPENDJ_ROOT/changelogDb
            su opendj -c "$UPGRADE --acceptLicense --no-prompt --force" 2>&1 | tee -a "${UPL_LOG}"
            rr=${PIPESTATUS[0]}
            if [ $rr -ne 0 ]; then
                LogMessage "ERROR: failed to upgrade opendj second time on cloud, exiting" | tee -a "${UPL_LOG}"
                error "Failed to upgrade opendj second time on cloud, exiting"
                return 1
            fi
        else
            return 1
        fi
    fi

    # NEW SECTION for upgrade from 6.5.0/6.5.5 to 7.3.3
    if [ "$OLD_OPENDJ_VERSION" == "6.5.0" ] || [ "$OLD_OPENDJ_VERSION" == "6.5.5" ]; then

       SetSecurityModel
       if [ $? -ne 0 ]; then
          LogMessage "ERROR: SetSecurityModel Failed"
          error "SetSecurityModel Failed"
          return 1
       fi

       MakeHybridReplicationWork
       if [ $? -ne 0 ]; then
          LogMessage "ERROR: MakeHybridReplicationWork Failed"
          error "MakeHybridReplicationWork Failed"
          return 1
       fi

    fi

#    ApplyPatches
#   if [ $? -ne 0 ]; then
#       LogMessage "ERROR: failed to apply OpenDJ patches"
#       error "Failed to apply OpenDJ patches"
#       exit 1
#    fi

    if [ "$LDAP_HOST" == $LDAP_LOCAL ]; then
        ImportLDIF
        if [ $? -ne 0 ]; then
            LogMessage "ERROR: ImportLDIF Failed"
            error "ImportLDIF Failed"
            return 1
        fi

        StartDS
        if [ $? != 0 ] ; then
            LogMessage "ERROR: StartDS failed"
            error "StartDS failed after ImportLDIF"
            return 1
        fi

        # setAllow-zero-length-values to true to permit empty mail
        setAllow-zero-length-values
        if [ $? != 0 ] ; then
           LogMessage "ERROR: setAllow-zero-length-values failed "
           error "setAllow-zero-length-values failed"
           return 1
        fi

        ReconfigureCache
        if [ $? != 0 ] ; then
            LogMessage "ERROR: ReconfigureCache failed"
            error "ReconfigureCache failed"
            return 1
        fi
        
        ReconfigureDiskThresholdsBackend
        if [ $? != 0 ] ; then
            LogMessage "ERROR: ReconfigureDiskThresholdsBackend  failed"
            error "ReconfigureDiskThresholdsBackend failed"
            return 1
        fi
        
    else
        LogMessage "INFO: Not a Vapp upgrade, starting initializing OpenDJ replication on $LDAP_HOST"

#        UpdateToJeImport
#        if [ $? != 0 ] ; then
#            LogMessage "ERROR: UpdateToJeImport failed."
#            error "UpdateToJeImport failed."
#            exit 1
#        fi

        StartDS
        if [ $? != 0 ] ; then
            LogMessage "ERROR: StartDS failed"
            error "StartDS failed"
            return 1
        fi

        # setAllow-zero-length-values to true to permit empty mail
        setAllow-zero-length-values
        if [ $? != 0 ] ; then
           LogMessage "ERROR: setAllow-zero-length-values failed "
           error "setAllow-zero-length-values failed"
           return 1
        fi

        # Clean admin data only if "$OLD_OPENDJ_VERSION" is 6.5.0 or 6.5.5 and is the last opendj to be upgrade to 7.x
        AdminCleanUp
        if [ $? != 0 ] ; then
           LogMessage "ERROR: AdminCleanUp  failed"
           error "AdminCleanUp failed"
           return 1
        fi
        ##############################################################################################################

        ReconfigureCache
        if [ $? != 0 ] ; then
            LogMessage "ERROR: ReconfigureCache failed"
            error "ReconfigureCache failed"
            return 1
        fi
        
        ReconfigureDiskThresholdsBackend
        if [ $? != 0 ] ; then
            LogMessage "ERROR: ReconfigureDiskThresholdsBackend  failed"
            error "ReconfigureDiskThresholdsBackend failed"
            return 1
        fi

        # only if not in single opendj configuration (trasport and extra small)
        IsSingleOpendj
        if [ $? != 0 ] ; then
         if [[ "${DDC_ON_CLOUD}" != TRUE ]]; then
	  # perhaps "dsrepl initialize" is no more necessary with repl. mngt. in DS 7.3
	  # moreover in DS 7.3 "dsrepl initialize" needs as parameter "serverId" not already set in this phase
          # ReplicationInit
          # if [ $? -ne 0 ]; then
          #  LogMessage "ERROR: failed to initialize OpenDJ replication on the current server"
          #  error "Failed to initialize OpenDJ replication on the current server"
          #  return 1
          # else
          #  LogMessage "INFO: ReplicationInit successful"
          # fi

          ReconfigureDiskThresholdsReplication
          if [ $? != 0 ] ; then
            LogMessage "ERROR: ReconfigureDiskThresholdsReplication  failed"
            error "ReconfigureDiskThresholdsReplication failed"
            return 1
          fi
          
          #If it fails it does not return error, not checking
          ChangelogEnabledDisable

         fi
         
         # cn=repadmin does no more exist in DS 7.3
         # UpdateRepAdminPrivileges
         # if [ $? != 0 ] ; then
         #   LogMessage "ERROR: UpdateRepAdminPrivileges failed"
         #   error "UpdateRepAdminPrivileges failed"
         #   return 1
         # fi

        fi

    fi

    #Setting logging back to default level for the upgrade
    $DSCONFIG -h localhost -p $ADMIN_CONNECTOR_PORT -D "$DM_DN" -w "$DM_PWD" --trustAll set-log-publisher-prop --publisher-name "File-Based Error Logger" --remove default-severity:all --no-prompt
    
    $DSCONFIG -h localhost -p $ADMIN_CONNECTOR_PORT -D "$DM_DN" -w "$DM_PWD" --trustAll set-log-publisher-prop --publisher-name "File-Based Debug Logger" --set enabled:false --no-prompt

    #Removal of old pdb backend
    if [ "$OLD_OPENDJ_VERSION" == "3.0.0" ]; then
        $RM_RF -f $OPENDJ_ROOT/db/userRoot/dj*
    fi

    LogMessage "INFO: UpgradeOpendj completed"
    info "UpgradeOpendj completed"

    return 0
}

##################################################################
# Function: Update RepAdmin Privileges when upgrading from < 6.5.0
# Arguments: None
# Returns:
#   0      Success
#   1      Failure
##################################################################

UpdateRepAdminPrivileges()
{
    LogMessage "INFO: Starting to update administrator privileges after upgrade"

  $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt << EOT | tee -a $LOG_FILE
dn: cn=$REPLICATION_ADMIN_UID,cn=Administrators,cn=admin data
changetype: modify
add: ds-privilege-name
ds-privilege-name: bypass-lockdown
ds-privilege-name: monitor-read
ds-privilege-name: server-lockdown
EOT

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ] && [ $rr -ne 20 ] ; then
    LogMessage "INFO: Failed to update administrator privileges and the error code from DS is [$rr]"
    error "Failed to update administrator privileges and the error code from DS is [$rr]"
    return 1
  fi

  LogMessage "INFO: UpdateRepAdminPrivileges complete"
  info "UpdateRepAdminPrivileges complete"
  return 0
}

########################################################
# Function: InitializeOpenDJ Replication
# Arguments: None
# Returns:
#   0      Success
#   1      Failure
########################################################

ReplicationInit()
{
    LogMessage "INFO: Starting OpenDJ replication initialization, processing request......" | tee -a "${UPL_LOG}"
    if [ "$LDAP_HOST" == "$OPENDJHOST0" ]; then
        $DSREPLICATION  initialize --baseDN "$BASE_DN" --adminUID $REPLICATION_ADMIN_UID --adminPassword "$DM_PWD" --hostSource $OPENDJHOST1 --portSource $ADMIN_CONNECTOR_PORT --hostDestination $OPENDJHOST0 --portDestination $ADMIN_CONNECTOR_PORT -X -n 2>&1 | tee -a "${UPL_LOG}"
        rr=${PIPESTATUS[0]}
        if [ $rr -ne 0 ]; then
            LogMessage "ERROR: failed to initialize replication froum source $OPENDJHOST1 to destination $OPENDJHOST0" | tee -a "${UPL_LOG}"
            error "Failed to initialize replication froum source $OPENDJHOST1 to destination $OPENDJHOST0"
            return 1
        else
            LogMessage "INFO: Replication successfully initialized froum source $OPENDJHOST1 to destination $OPENDJHOST0" | tee -a "${UPL_LOG}"
        fi
    elif [ "$LDAP_HOST" == "$OPENDJHOST1" ]; then
        $DSREPLICATION  initialize --baseDN "$BASE_DN" --adminUID $REPLICATION_ADMIN_UID --adminPassword "$DM_PWD" --hostSource $OPENDJHOST0 --portSource $ADMIN_CONNECTOR_PORT --hostDestination $OPENDJHOST1 --portDestination $ADMIN_CONNECTOR_PORT -X -n 2>&1 | tee -a "${UPL_LOG}"
        rr=${PIPESTATUS[0]}
        if [ $rr -ne 0 ]; then
            LogMessage "ERROR: failed to initialize replication froum source $OPENDJHOST0 to destination $OPENDJHOST1" | tee -a "${UPL_LOG}"
            error "Failed to initialize replication froum source $OPENDJHOST0 to destination $OPENDJHOST1"
            return 1
        else
            LogMessage "INFO: Replication successfully initialized  froum source $OPENDJHOST0 to destination $OPENDJHOST1" | tee -a "${UPL_LOG}"
        fi
    else
        LogMessage "INFO: Vapp install, replication not used" | tee -a "${UPL_LOG}"
    fi

    LogMessage "INFO: ReplicationInit complete"
    info "ReplicationInit complete"
    return 0
}

################################################################################
# Function: DisableOpendjReplication
# Description: Disable opendj replication. After calling this function, opendj
#            replication functionality is disabled. This is necessary for uplift
# Parameters: none
# Return: 0 (Succeed)
#         1 (Failed)
################################################################################
function DisableOpendjReplication(){
    LogMessage "INFO: DisableOpendjReplication request is received...... Processing request"

    if [ "$LDAP_HOST" == "$OPENDJHOST0" ]; then
       $DSREPLICATION unconfigure --host1 $LDAP_HOST --port1 $ADMIN_CONNECTOR_PORT --bindDN1 "$DM_DN" --bindPassword1 "$DM_PWD" --replicationPort1 $REPLICATION_PORT --host2 $OPENDJHOST1 --port2 $ADMIN_CONNECTOR_PORT --bindDN2 "$DM_DN" --bindPassword2 "$DM_PWD" --replicationPort2 $REPLICATION_PORT --secureReplication2 --adminUID $REPLICATION_ADMIN_UID --adminPassword "$DM_PWD" --baseDN "$BASE_DN" -X -n 2>&1 | tee -a "${UPL_LOG}"
        rr=${PIPESTATUS[0]}
        if [ $rr -ne 0 ]; then
            LogMessage "ERROR: failed to disable replication froum source $OPENDJHOST1 to destination $OPENDJHOST0" | tee -a "${UPL_LOG}"
            error "Failed to initialize replication froum source $OPENDJHOST1 to destination $OPENDJHOST0"
            return 1
        else
            LogMessage "INFO: Replication successfully disabled froum source $OPENDJHOST1 to destination $OPENDJHOST0" | tee -a "${UPL_LOG}"
        fi
    elif [ "$LDAP_HOST" == "$OPENDJHOST1" ]; then
       $DSREPLICATION unconfigure --host1 $LDAP_HOST --port1 $ADMIN_CONNECTOR_PORT --bindDN1 "$DM_DN" --bindPassword1 "$DM_PWD" --replicationPort1 $REPLICATION_PORT --host2 $OPENDJHOST0 --port2 $ADMIN_CONNECTOR_PORT --bindDN2 "$DM_DN" --bindPassword2 "$DM_PWD" --replicationPort2 $REPLICATION_PORT --secureReplication2 --adminUID $REPLICATION_ADMIN_UID --adminPassword "$DM_PWD" --baseDN "$BASE_DN" -X -n 2>&1 | tee -a "${UPL_LOG}"
        rr=${PIPESTATUS[0]}
        if [ $rr -ne 0 ]; then
            LogMessage "ERROR: failed to disable replication froum source $OPENDJHOST0 to destination $OPENDJHOST1" | tee -a "${UPL_LOG}"
            error "Failed to disable replication froum source $OPENDJHOST0 to destination $OPENDJHOST1"
            return 1
        else
            LogMessage "INFO: Replication successfully disabled froum source $OPENDJHOST0 to destination $OPENDJHOST1" | tee -a "${UPL_LOG}"
        fi
    else
        LogMessage "INFO: Vapp install, replication not used" | tee -a "${UPL_LOG}"
    fi

    LogMessage "INFO: DisableOpendjReplication completed successfully"
    return 0
}

########################################################
# Function: Reconfigure OpenDJ Replication for 3pp upversioning
# Arguments: None
# Returns:
#   0      Success
#   1      Failure
########################################################
ReconfigureOpendj()
{

    LogMessage "INFO: Starting OpenDJ reconfiguration, processing request......" | tee -a "${UPL_LOG}"

    #Reconfigure Replication
    if [ "$LDAP_HOST" == "$OPENDJHOST0" ]; then
        $DSCONFIG -h localhost -p $ADMIN_CONNECTOR_PORT -D "$DM_DN" -w "$DM_PWD" --trustAll -n set-replication-server-prop --provider-name "Multimaster Synchronization" --set source-address:$OPENDJHOST0 2>&1 | tee -a "${UPL_LOG}"
        rr=${PIPESTATUS[0]}
        if [ $rr -ne 0 ]; then
            LogMessage "ERROR: failed to set replication source-address property on the node to $OPENDJHOST0" | tee -a "${UPL_LOG}"
            error "Failed to set replication source-address property on the node to $OPENDJHOST0"
            return 1
        else
            LogMessage "INFO: Set replication source-address property on the node to $OPENDJHOST0" | tee -a "${UPL_LOG}"
        fi
    elif [ "$LDAP_HOST" == "$OPENDJHOST1" ]; then
        $DSCONFIG -h localhost -p $ADMIN_CONNECTOR_PORT -D "$DM_DN" -w "$DM_PWD" --trustAll -n set-replication-server-prop --provider-name "Multimaster Synchronization" --set source-address:$OPENDJHOST1 2>&1 | tee -a "${UPL_LOG}"
        rr=${PIPESTATUS[0]}
        if [ $rr -ne 0 ]; then
            LogMessage "ERROR: failed to set replication source-address property on the node to $OPENDJHOST1" | tee -a "${UPL_LOG}"
            error "Failed to set replication source-address property on the node to $OPENDJHOST1"
            return 1
        else
            LogMessage "INFO: Set replication source-address property on the node to $OPENDJHOST1" | tee -a "${UPL_LOG}"
        fi
    else
        $DSCONFIG -h localhost -p $ADMIN_CONNECTOR_PORT -D "$DM_DN" -w "$DM_PWD" --trustAll -n set-replication-server-prop --provider-name "Multimaster Synchronization" --set source-address:$LDAP_LOCAL 2>&1 | tee -a "${UPL_LOG}"
        rr=${PIPESTATUS[0]}
        if [ $rr -ne 0 ]; then
            LogMessage "ERROR: failed to set replication source-address property on the node to $LDAP_LOCAL" | tee -a "${UPL_LOG}"
            error "Failed to set replication source-address property on the node to $LDAP_LOCAL"
            return 1
        else
            LogMessage "INFO: Set replication source-address property on the node to $LDAP_LOCAL" | tee -a "${UPL_LOG}"
        fi
    fi

    LogMessage "INFO: ReconfigureOpendj completed"
    info "ReconfigureOpendj completed"

    return 0
}

########################################################
# Function: Reconfigure OpenDJ Cache Size
# Arguments: None
# Returns:
#   0      Success
#   1      Failure
########################################################

ReconfigureCache()
{
    #Reconfigure Cache Size - parameter changed to localhost
    $DSCONFIG -h localhost -p $ADMIN_CONNECTOR_PORT -D "$DM_DN" -w "$DM_PWD" --trustAll -n set-backend-prop --backend-name userRoot --set db-cache-percent:15 2>&1 | tee -a "${LOG_FILE}"
    rr=${PIPESTATUS[0]}
    if [ $rr -ne 0 ]; then
        LogMessage "ERROR: failed to reconfigure OpenDJ cache size"
        error "Failed to reconfigure OpenDJ cache size"
        return 1
    else
        LogMessage "INFO: Opendj cache reconfiguration completed successfully"
        info "Opendj cache reconfiguration completed successfully"
    fi
   return 0
}

########################################################
# Function: Reconfigure OpenDJ Disk Thresholds Backend
# Arguments: None
# Returns:
#   0      Success
#   1      Failure
########################################################

ReconfigureDiskThresholdsBackend()
{
    #Reconfigure OpenDJ Disk Thresholds for Backend
    $DSCONFIG -h localhost -p $ADMIN_CONNECTOR_PORT -D "$DM_DN" -w "$DM_PWD" --trustAll -n set-backend-prop --backend-name userRoot --set "disk-low-threshold:200 MB" --set "disk-full-threshold:100 MB" 2>&1 | tee -a "${LOG_FILE}"
    rr=${PIPESTATUS[0]}
    if [ $rr -ne 0 ]; then
        LogMessage "ERROR: failed to reconfigure opendj disk thresholds for backend"
        error "Failed to reconfigure opendj disk thresholds for backend"
        return 1
    else
        LogMessage "INFO: Opendj disk thresholds reconfiguration for backend completed successfully"
        info "Opendj disk thresholds reconfiguration for backend completed successfully"
    fi
        
    return 0
}

#############################################################
# Function: Reconfigure OpenDJ Disk Thresholds Replication
# Arguments: None
# Returns:
#   0      Success
#   1      Failure
#############################################################

ReconfigureDiskThresholdsReplication()
{    
    #Reconfigure OpenDJ Disk Thresholds for Replication Server
    $DSCONFIG -h localhost -p $ADMIN_CONNECTOR_PORT -D "$DM_DN" -w "$DM_PWD" --trustAll -n set-replication-server-prop --provider-name "Multimaster Synchronization" --set "disk-low-threshold:200 MB" --set "disk-full-threshold:100 MB" 2>&1 | tee -a "${LOG_FILE}"
    rr=${PIPESTATUS[0]}
    if [ $rr -ne 0 ]; then
        LogMessage "ERROR: failed to reconfigure opendj disk thresholds for replication server"
        error "Failed to reconfigure opendj disk thresholds for replication server"
        return 1
    else
        LogMessage "INFO: Opendj disk thresholds reconfiguration for replication server completed successfully"
        info "Opendj disk thresholds reconfiguration for replication server completed successfully"
    fi
    
    return 0
}


#############################################################
# Function: DisableChangelog-enabled
# Arguments: None
# Returns:
#   0      Success
#   1      Failure
#############################################################

DisableChangelog-enabled()
{
    #Set Changelog-enabled option to disabled
    $DSCONFIG -h localhost -p $ADMIN_CONNECTOR_PORT -D "$DM_DN" -w "$DM_PWD" --trustAll -n set-replication-server-prop --provider-name "Multimaster Synchronization" --set changelog-enabled:disabled 2>&1 | tee -a "${LOG_FILE}"
    rr=${PIPESTATUS[0]}
    if [ $rr -ne 0 ]; then
        LogMessage "ERROR: failed to set changelog-enabled option to disable for replication server"
        error "Failed to set changelog-enabled option to disable for replication server"
        return 1
    else
        LogMessage "INFO: set changelog-enabled option to disable for replication server completed successfully"
        info "Set changelog-enabled option to disable for replication server completed successfully"
    fi

    return 0
}


########################################################
# unzip the source tarball.
# Arguments: None
# Returns:
#   0      Success
#   1      Failure
########################################################
UnzipSource()
{
  unzip -o ${IDENMGMT_ROOT}/opendj/pkg/opendj.zip -d ${OPENDJ_ROOT_PARENT}
  if [ $? != 0 ]; then
      LogMessage "ERROR: failed to expand opendj.zip"
      error "Failed to expand opendj.zip"
      return 1
  fi

  USERS_JSON=${IDENMGMT_ROOT}/opendj/config/users-v1.json

  $SED -e "s/BASE_DN/$BASE_DN/g" $USERS_JSON > /tmp/users-v1.json
  if [ $? -ne 0 ]; then
     LogMessage "ERROR: failed to update $USERS_JSON"
     error "Failed to update $USERS_JSON"
     return 1
  fi

  ${RM_RF} -f ${OPENDJ_ROOT}/template/config/rest2ldap/endpoints/api/*
  if [ $? -ne 0 ]; then
     LogMessage "ERROR: failed to cleanup rest2ldap resources folder"
     error "Failed to cleanup rest2ldap resources folder"
     return 1
  fi

  $CP /tmp/users-v1.json ${OPENDJ_ROOT}/template/config/rest2ldap/endpoints/api/users-v1.json
  if [ $? -ne 0 ]; then
     LogMessage "ERROR: failed to copy users-v1.json"
     error "Failed to copy users-v1.json"
     return 1
  fi

  ${RM_RF} /tmp/users-v1.json

  $CHOWN -R opendj:opendj $OPENDJ_ROOT
  if [ $? -ne 0 ]; then
    LogMessage "ERROR: failed to chown $OPENDJ_ROOT"
    error "Failed to chown $OPENDJ_ROOT"
    return 1
  fi

  return 0
}

################################################################
# Function: CreateContainers
# This is to create ou=people and ou=groups containers
# under $BASEDN
################################################################
CreateContainers()
{
  LogMessage "INFO: CreateContainers request has been received...... Processing request"

  $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt << EOT | tee -a $LOG_FILE
dn: $BASE_DN
objectClass: domain
objectClass: clientConfig
objectClass: top
dc: $CONTAINER_BASE
EOT

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ] && [ $rr -ne 68 ] ; then
    LogMessage "INFO: Failed to add [$BASE_DN] and the error code from DS is [$rr]"
    error "Failed to add [$BASE_DN] and the error code from DS is [$rr]"
    return 1
  fi

  ############################################################################################################
  # TORF-721184 delay added in order to prevent opendj objects creation at the same time during installation #
  #
  ############################################################################################################
  if [ $LDAP_HOST == "opendjhost1" ] || [ $LDAP_HOST == "opendj-2" ] || [ $LDAP_HOST == "opendj-1.opendj" ] ; then
      LogMessage "INFO: Entering in loop to wait ou=people on $LDAP_HOST"
      $LDAPSEARCH -h localhost -p $COM_INF_LDAP_PORT -D "$DM_DN" -w "$DM_PWD" -X -Z -b "ou=People,$BASE_DN" ou=people  >/dev/null 2>&1
      ret=$?
      while [ $ret -ne 0 ];
      do
        LogMessage "INFO: waiting for 5 seconds"
        sleep 5
        $LDAPSEARCH -h localhost -p $COM_INF_LDAP_PORT -D "$DM_DN" -w "$DM_PWD" -X -Z -b "ou=People,$BASE_DN" ou=people >/dev/null 2>&1
        ret=$?
      done
      LogMessage "INFO: ou=People found on $LDAP_HOST"
	  sleep 30
	  LogMessage "INFO: 30 second wait completed"
  fi

  LogMessage "INFO: create People"
  $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt << EOT | tee -a $LOG_FILE
dn: ou=People,$BASE_DN
objectClass: top
objectClass: organizationalUnit
ou: People
EOT

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ] && [ $rr -ne 68 ] ; then
    LogMessage "INFO: Failed to add [ou=People] container and the error code from DS is [$rr]"
    error "Failed to add [ou=People] container and the error code from DS is [$rr]"
    return 1
  fi

  $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt << EOT | tee -a $LOG_FILE
dn: ou=Groups,$BASE_DN
objectClass: top
objectClass: organizationalUnit
ou: Groups
EOT

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ] && [ $rr -ne 68 ] ; then
     LogMessage "ERROR: Failed to add [ou=Groups] container and the error code from DS is [$rr]"
     error "Failed to add [ou=Groups] container and the error code from DS is [$rr]"
     return 1
  fi

  $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt << EOT | tee -a $LOG_FILE
dn: ou=Roles,$BASE_DN
objectClass: OrganizationalUnit
objectClass: top
ou: Roles
description: This is a container for all ENM Roles
EOT

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ] && [ $rr -ne 68 ] ; then
     LogMessage "ERROR: Failed to add [ou=Roles] container and the error code from DS is [$rr]"
     error "Failed to add [ou=Roles] container and the error code from DS is [$rr]"
     return 1
  fi

  $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt << EOT | tee -a $LOG_FILE
dn: ou=TargetGroups,$BASE_DN
objectClass: top
objectClass: organizationalUnit
ou: TargetGroups
EOT

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ] && [ $rr -ne 68 ] ; then
     LogMessage "ERROR: Failed to add [ou=TargetGroups] container and the error code from DS is [$rr]"
     error "Failed to add [ou=TargetGroups] container and the error code from DS is [$rr]"
     return 1
  fi

  $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt << EOT | tee -a $LOG_FILE
dn: ou=NE_ACCESS,ou=TargetGroups,$BASE_DN
objectClass: organizationalUnit
objectClass: top
description: This is the predefined TargetGroup that all NEs will be assigned to
ou: NE_ACCESS
EOT

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ] && [ $rr -ne 68 ] ; then
     LogMessage "ERROR: Failed to add [ou=NE_ACCESS] container and the error code from DS is [$rr]"
     error "Failed to add [ou=NE_ACCESS] container and the error code from DS is [$rr]"
     return 1
  fi

  $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt << EOT | tee -a $LOG_FILE
dn: ou=Scopes,$BASE_DN
objectClass: OrganizationalUnit
objectClass: top
ou: Scopes
description: This is a container for all scopes
EOT

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ] && [ $rr -ne 68 ] ; then
     LogMessage "ERROR: Failed to add [ou=Scopes] container and the error code from DS is [$rr]"
     error "Failed to add [ou=Scopes] container and the error code from DS is [$rr]"
     return 1
  fi

  $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt <<EOT | tee -a $LOG_FILE
dn: ou=M2MUsers,$BASE_DN
objectClass: organizationalUnit
objectClass: top
description: This is a container for all the M2M users
ou: M2MUsers
EOT

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ] && [ $rr -ne 68 ] ; then
     LogMessage "ERROR: Failed to create the [ou=M2MUsers] container and the error code from DS is [$rr]"
     error "Failed to create the [ou=M2MUsers] container and the error code from DS is [$rr]"
     return 1
  fi

  $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt <<EOT | tee -a $LOG_FILE
dn: ou=Profiles,$BASE_DN
objectClass: organizationalUnit
objectClass: top
description: This is a container for all the Proxy Agent Accounts
ou: Profiles
EOT

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ] && [ $rr -ne 68 ] ; then
     LogMessage "ERROR: Failed to create the [ou=Profiles] container and the error code from DS is [$rr]"
     error "Failed to create the [ou=Profiles] container and the error code from DS is [$rr]"
     return 1
  fi

  LogMessage "INFO: CreateContainers completed successfully"
  info "CreateContainers completed successfully"
  return 0
}

################################################################
# Function: CreateContainerForProxyagent
# This is to create ou=proxyagent inside ou=com container
# under $BASEDN
################################################################
CreateProxyagentContainer()
{
    LogMessage "INFO: CreateContainerForProxyagent request has been received...... Processing request"

    $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt <<EOT | tee -a $LOG_FILE
dn: ou=com,$BASE_DN
objectClass: organizationalUnit
objectClass: top
description: This is a container for proxyagent and proxyagentlockable containers
ou: com
EOT

    rr=${PIPESTATUS[0]}
    if [ $rr -ne 0 ] && [ $rr -ne 68 ] ; then
        LogMessage "ERROR: Failed to create the [ou=com] container and the error code from DS is [$rr]"
        error "Failed to create the [ou=com] container and the error code from DS is [$rr]"
        return 1
    fi

    if [ $rr -eq 68 ]; then
        LogMessage "INFO: the [ou=com] container already created"
    fi

    $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt <<EOT | tee -a $LOG_FILE
dn: ou=proxyagent,ou=com,$BASE_DN
objectClass: organizationalUnit
objectClass: top
description: This is a container for all the Proxy Agent Accounts
ou: proxyagent
EOT

    rr=${PIPESTATUS[0]}
    if [ $rr -ne 0 ] && [ $rr -ne 68 ] ; then
        LogMessage "ERROR: Failed to create the [ou=proxyagent,ou=com] container and the error code from DS is [$rr]"
        error "Failed to create the [ou=proxyagent,ou=com] container and the error code from DS is [$rr]"
        return 1
    fi

    if [ $rr -eq 68 ]; then
        LogMessage "INFO: the [ou=proxyagent,ou=com] container already created"
    fi

    LogMessage "INFO: CreateContainerForProxyagent completed successfully"
    info "CreateContainerForProxyagent completed successfully"
    return 0
}

################################################################
# Function: CreateProxyagentContainerLockable
# This is to create ou=proxyagentlockable inside ou=com container
# under $BASEDN
################################################################
CreateProxyagentContainerLockable()
{
    LogMessage "INFO: CreateProxyagentContainerLockable request has been received...... Processing request"

    $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt <<EOT | tee -a $LOG_FILE
dn: ou=com,$BASE_DN
objectClass: organizationalUnit
objectClass: top
description: This is a container for proxyagent and proxyagentlockable containers
ou: com
EOT

    rr=${PIPESTATUS[0]}
    if [ $rr -ne 0 ] && [ $rr -ne 68 ] ; then
        LogMessage "ERROR: Failed to create the [ou=com] container and the error code from DS is [$rr]"
        error "Failed to create the [ou=com] container and the error code from DS is [$rr]"
        return 1
    fi

    if [ $rr -eq 68 ]; then
        LogMessage "INFO: the [ou=com] container already created"
    fi

    $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt <<EOT | tee -a $LOG_FILE
dn: ou=proxyagentlockable,ou=com,$BASE_DN
objectClass: organizationalUnit
objectClass: top
description: This is a container for all the Proxy Agent Lockable Accounts
ou: proxyagentlockable
EOT

    rr=${PIPESTATUS[0]}
    if [ $rr -ne 0 ] && [ $rr -ne 68 ] ; then
        LogMessage "ERROR: Failed to create the [ou=proxyagentlockable,ou=com] container and the error code from DS is [$rr]"
        error "Failed to create the [ou=proxyagentlockable,ou=com] container and the error code from DS is [$rr]"
        return 1
    fi

    if [ $rr -eq 68 ]; then
        LogMessage "INFO: the [ou=proxyagentlockable,ou=com] container already created"
    fi

    LogMessage "INFO: CreateProxyagentContainerLockable completed successfully"
    info "CreateProxyagentContainerLockable completed successfully"
    return 0

}

###########################################################################################
# Function: EnableReferentialIntegrity
# Description: This function enables Opendj's referential integrity plugin
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################
EnableReferentialIntegrity()
{
   LogMessage "INFO: EnableReferentialIntegrity request has been received...... Processing request"

   $DSCONFIG set-plugin-prop --port $ADMIN_CONNECTOR_PORT --hostname localhost \
      --bindDN "$DM_DN" --bindPassword "$DM_PWD" --plugin-name "Referential Integrity" \
      --set enabled:true --trustAll --no-prompt | tee -a $LOG_FILE

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ]; then
     LogMessage "ERROR: Failed to enable Referential Integrity and the error code from DS is [$rr]"
     error "Failed to enable Referential Integrity and the error code from DS is [$rr]"
     return 1
  fi
  LogMessage "INFO: EnableReferentialIntegrity completed successfully"
  info "EnableReferentialIntegrity completed successfully"
  return 0
}

###########################################################################################
# Function: EnableSHA256PasswordStorageScheme
# Description: This function is to enable SHA256 password storage scheme
# Parameters: None
# Return:  0        succeed
#          1        failed
###########################################################################################
EnableSHA256PasswordStorageScheme()
{
   LogMessage "INFO: EnableSHA256PasswordStorageScheme request has been received...... Processing request"

   $DSCONFIG set-password-storage-scheme-prop \
          --scheme-name Salted\ SHA-256 \
          --set enabled:true \
          --hostname localhost \
          --port $ADMIN_CONNECTOR_PORT \
          --bindDn "$DM_DN" \
          --bindPassword "$DM_PWD" \
          --trustAll \
          --no-prompt | tee -a $LOG_FILE

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ]; then
     LogMessage "ERROR: Failed to enable SHA256 storage scheme and the error code from DS is [$rr]"
     error "Failed to enable SHA256 storage scheme and the error code from DS is [$rr]"
     return 1
  fi

  LogMessage "INFO:EnableSHA256PasswordStorageScheme completed successfully"
  info "EnableSHA256PasswordStorageScheme completed successfully"
  return 0

}   

###########################################################################################
# Function: ConfigDefaultPasswordPolicy
# Description: This function is to configure the default password policies for noraml users
#              The policies includes:
#              1. Define the standard time stamp format for last login time
#              2. Use a more secure algorithm SHA-256 other than the default one SHA-1
#              3. The account will be locked for 3 min after 3 consecutive failed login attempts
#                 within 5 mins
#              4. Enable password history, so user's password cannot be changed to what is currently used.
# Parameters: None
# Return:  0        succeed
#          1        failed
###########################################################################################
# removed line "--set deprecated-password-storage-scheme:"Salted SHA-1"" 
# SHA-1 is disabled so we do not declare it as "deprecated"
ConfigDefaultPasswordPolicy()
{
   LogMessage "INFO: ConfigDefaultPasswordPolicy request has been received...... Processing request"

   $DSCONFIG set-password-policy-prop --port $ADMIN_CONNECTOR_PORT --hostname localhost \
      --bindDN "$DM_DN" --bindPassword "$DM_PWD"  \
      --policy-name "$DEFAULT_PASSWD_POLICY" \
      --set last-login-time-attribute:lastLoginTime \
      --set last-login-time-format:"yyyyMMddHHmmssZ" \
      --set previous-last-login-time-format:"yyyyMMddHHmmssZ" \
      --set default-password-storage-scheme:"Salted SHA-256" \
      --set lockout-failure-count:3 \
      --set lockout-duration:3m \
      --set lockout-failure-expiration-interval:5m \
      --set password-history-count:1 \
      --set password-history-duration:1s \
      --set force-change-on-add:false \
      --set force-change-on-reset:true \
      --set max-password-age:97d \
      --set password-expiration-warning-interval:7d \
      --set allow-pre-encoded-passwords:true \
      --set expire-passwords-without-warning:true \
      --reset password-validator \
      --trustAll \
      --no-prompt | tee -a $LOG_FILE

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ]; then
     LogMessage "ERROR: Failed to configure the Default Password Policy and the error code from DS is [$rr]"
     error "Failed to configure the Default Password Policy and the error code from DS is [$rr]"
     return 1
  fi
  LogMessage "INFO: ConfigDefaultPasswordPolicy completed successfully"
  info "ConfigDefaultPasswordPolicy completed successfully"
  return 0
}


###########################################################################################
# Function: SetENM_UserSubentryPasswordPolicy
# Description: This function is to set subentry password policy for normal user which overrides Default Password Policy
#              The policies includes:
#              1. Set pwdMaxAge attribute default value to 7776000 seconds
#              2. Set pwdExpireWarning attribute default value to 604800 seconds
#              3. Set pwdGraceAuthNLimit attribute default value to 0
# Parameters: None
# Return:  0        succeed
#          3        failed in case of rollback - restore  TORF-726754
#          1        failed
###########################################################################################
SetENM_UserSubentryPasswordPolicy()
{
    LogMessage "Setting up ENM_User Subentry Password Policy"

    $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt <<EOT | tee -a $LOG_FILE
dn: cn=ENM_Users Default Subentry Password Policy,$BASE_DN
objectClass: top
objectClass: subentry
objectClass: pwdPolicy
cn: ENM_Users Default Subentry Password Policy
pwdAttribute: userPassword
pwdExpireWarning: 604800
pwdMaxAge: 7776000
pwdGraceAuthNLimit: 3
subtreeSpecification:  {base "ou=people"}
EOT

    rr=${PIPESTATUS[0]}
    if [ $rr -ne 0 ] && [ $rr -ne 68 ] ; then
        if [ "${DDC_ON_CLOUD}" == TRUE ] && [ $rr -eq 53 ] ; then
            LogMessage "WARNING: Subentry Password Policy. The response is [$rr]"
            info "WARNING: Default Subentry Password Policy. The response is [$rr]"
            return 3
        fi        

        LogMessage "ERROR: Failed to set ENM_Users Default Subentry Password Policy. The response is [$rr]"
        error "Failed to set ENM_Users Default Subentry Password Policy. The response is [$rr]"
        return 1
    fi

    $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt <<EOT | tee -a $LOG_FILE
dn: cn=ENM_Users Default Subentry Password Policy,$BASE_DN
changetype: modify
add: pwdLockout
pwdLockout: true
-
add: pwdMaxFailure
pwdMaxFailure: 3
-
add: pwdLockoutDuration
pwdLockoutDuration: 180
-
add: pwdFailureCountInterval
pwdFailureCountInterval: 300
EOT

    rr=${PIPESTATUS[0]}
    if [ $rr -ne 0 ] && [ $rr -ne 20 ] ; then
        LogMessage "ERROR: Failed to set account lockout policy for ENM_Users Default Subentry Password Policy.The response is [$rr]"
        error "Failed to set account lockout policy for ENM_Users Default Subentry Password Policy.The response is [$rr]"
        return 1
    fi

    LogMessage "ENM_Users Default Subentry Password Policy successfully set"
}

###########################################################################################
# Function: SetPasswordPolicyForProxyUsersLockable
# Description: This function is to set subentry password policy for Proxy Lockable Users
#              The policy includes:
#              1. Set pwdMaxAge attribute to 0 so passwords never expire
#              2. About lockout policy:
#                  2.1 pwdMaxFailure is set to 3
#                  2.2 pwdLockoutDuration is set to 180
#	           2.3 pwdFailureCountInterval is set to 300
# Parameters: None
# Return:  0        succeed
#          1        failed
###########################################################################################
SetPasswordPolicyForProxyUsersLockable()
{
    LogMessage "INFO: SetPasswordPolicyForProxyUsersLockable request has been received. Processing request..."

    $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt <<EOT | tee -a $LOG_FILE
dn: cn=Proxy Agent Lockable Password Never Expire Subentry Policy,$BASE_DN
changetype: add
objectClass: top
objectClass: subentry
objectClass: pwdPolicy
cn: Proxy Agent Lockable Password Never Expire Subentry Policy
pwdMaxAge: 0
pwdAttribute: userPassword
subtreeSpecification: {base "ou=proxyagentlockable,ou=com"}
EOT

    rr=${PIPESTATUS[0]}
    if [ $rr -ne 0 ] && [ $rr -ne 68 ] ; then
      LogMessage "ERROR: Failed to configure pwd policy for ou=proxyagentlockable,ou=com and the error code from DS is [$rr]"
      error "Failed to configure pwd policy for ou=proxyagentlockable,ou=com and the error code from DS is [$rr]"
      return 1
    fi

    if [ $rr -eq 68 ]; then
      LogMessage "INFO: Pwd policy for ou=proxyagentlockable,ou=com already configured"
    else
      LogMessage "INFO: Configuration of pwd policy without exp. for ou=proxyagentlockable,ou=com successfully"
    fi

    $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt <<EOT | tee -a $LOG_FILE
dn: cn=Proxy Agent Lockable Password Never Expire Subentry Policy,$BASE_DN
changetype: modify
add: pwdLockout
pwdLockout: true
-
add: pwdMaxFailure
pwdMaxFailure: 3
-
add: pwdLockoutDuration
pwdLockoutDuration: 180
-
add: pwdFailureCountInterval
pwdFailureCountInterval: 300
EOT

    rr=${PIPESTATUS[0]}
    if [ $rr -ne 0 ] && [ $rr -ne 20 ] ; then
        LogMessage "ERROR: Failed to set account lockout policy for ou=proxyagentlockable,ou=com.The response is [$rr]"
        error "Failed to set account lockout policy for ou=proxyagentlockable,ou=com.The response is [$rr]"
        return 1
    fi

    LogMessage "Configuration of account lockout policy for ou=proxyagentlockable,ou=com successfully"
}

################################################################################
# Function: ConfigSuperuserPasswdPolicy
# Description: This function is to configure the password policy for super user
#              and SSO user (read only user). The password policies includes:
#              1. Never expired
#              2. No password change is required at the first login
#              3. Use more secure algorithm SHA-256
#              4. The account will be locked for 3 min after 3 consecutive failed login attempts
#                 within 5 mins
#              5. Enable password history, so user's password cannot be changed to what is currently used.
# Parameters: none
# Return:     0  Succeed
#             1  Failed
################################################################################
# removed line "--set deprecated-password-storage-scheme:"Salted SHA-1""
# SHA-1 is disabled so we do not declare it as "deprecated"
ConfigSuperuserPasswdPolicy() {
     LogMessage "INFO: ConfigSuperuserPasswdPolicy request has been received...... Processing request"
     $DSCONFIG create-password-policy --port $ADMIN_CONNECTOR_PORT \
                                      --hostname localhost \
                                      --bindDN "$DM_DN"  \
                                      --bindPassword "$DM_PWD"  \
                                      --policy-name "$SUPER_USER_PASSWD_POLICY" \
                                      --set last-login-time-attribute:lastLoginTime \
                                      --set last-login-time-format:"yyyyMMddHHmmssZ" \
                                      --set previous-last-login-time-format:"yyyyMMddHHmmssZ" \
                                      --set default-password-storage-scheme:"Salted SHA-256"  \
                                      --set lockout-failure-count:0 \
                                      --set lockout-duration:0s \
                                      --set lockout-failure-expiration-interval:0s \
                                      --set password-attribute:userPassword \
                                      --set password-history-count:1 \
                                      --set password-history-duration:1s \
                                      --set allow-pre-encoded-passwords:true \
                                      --type password-policy \
                                      --trustAll --no-prompt | tee -a $LOG_FILE
     rr=${PIPESTATUS[0]}
     if [ $rr -ne 0 ]; then
         LogMessage "ERROR: Failed to configure the superuser and sso user Password Policy and the error code from DS is [$rr]"
         error "Failed to configure the superuser and sso user Password Policy and the error code from DS is [$rr]"
         return 1
      fi
      LogMessage "INFO: ConfigSuperuserPasswdPolicy completed successfully"
      info "ConfigSuperuserPasswdPolicy completed successfully"
      return 0
}

################################################################################
# Function: ConfigHttpConnectionHandler
# Description: This function is to configure and enable the HTTP Connection Handler
#              1. listen to port 8447
#              2. user ssl connection
#              3. key-manager-provider: Default Key Manager
#              4. trust-manager-provider: Default Trust Manager
# Parameters: none
# Return:     0  Succeed
#             1  Failed
################################################################################
ConfigHttpConnectionHandler() {
     LogMessage "INFO: ConfigHttpConnectionHandler request has been received...... Processing request"

     rtMess="$($DSCONFIG get-connection-handler-prop --port $ADMIN_CONNECTOR_PORT \
     --hostname localhost \
     --bindDN "$DM_DN" \
     --bindPassword "$DM_PWD" \
     --handler-name HTTP \
     --trustAll --no-prompt )"

     if [[ $rtMess != *"Property"* ]]
     then
	# DS install
        LogMessage "INFO: Creating Http connection manager"

        $DSCONFIG create-connection-handler   --port $ADMIN_CONNECTOR_PORT \
                                              --hostname localhost \
                                              --bindDN "$DM_DN"  \
                                              --bindPassword "$DM_PWD"  \
                                              --handler-name HTTP \
                                              --type http \
                                              --set enabled:true \
                                              --set listen-port:8447 \
                                              --set key-manager-provider:"PKCS12" \
                                              --set trust-manager-provider:"PKCS12" \
                                              --set use-ssl:true \
                                              --trustAll --no-prompt | tee -a $LOG_FILE
        rr=${PIPESTATUS[0]}
        if [ $rr -eq 0 ]; then
            LogMessage "INFO: Http Connection Handler created successfully"
            info "Http Connection Handler created successfully"
            return 0
        else
            LogMessage "ERROR: HTTP connector creation failed"
            error "HTTP connector creation failed"
            return 1
        fi
     else
	# upgrade
        LogMessage "INFO: Enabling Http connection manager"

        $DSCONFIG set-connection-handler-prop   --port $ADMIN_CONNECTOR_PORT \
                                                --hostname localhost \
                                                --bindDN "$DM_DN"  \
                                                --bindPassword "$DM_PWD"  \
                                                --handler-name HTTP \
                                                --set enabled:true \
                                                --trustAll --no-prompt | tee -a $LOG_FILE
        rr=${PIPESTATUS[0]}
        if [ $rr -ne 0 ]; then
            LogMessage "ERROR: Failed to enable the HTTP Connection Handler and the error code from DS is [$rr]"
            error "Failed to enable the HTTP Connection Handler and the error code from DS is [$rr]"
            return 1
        fi
        LogMessage "INFO: Http Connection Handler enabled successfully"
        info "Http Connection Handler created successfully"
        return 0
     fi
}

###########################################################################################
# Function: CreateReadOnlyUser
# Description: This function creates a read only user for openAM
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################
CreateReadOnlyUser()
{

  LogMessage "CreateReadOnlyUser request has been received. Processing request..."

  $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt <<EOT | tee -a $LOG_FILE
dn: $SSO_USER_DN
objectClass: person
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: top
uid: ssouser
cn: sso_user
sn: sso_user
userPassword: $SSO_USER_PWD
ds-pwp-password-policy-dn: cn=$SUPER_USER_PASSWD_POLICY,cn=Password Policies,cn=config
EOT

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ] && [ $rr -ne 68 ] ; then
     LogMessage "ERROR: Failed to create a read only user for OpenAM and the error code from DS is [$rr]"
     error "Failed to create a read only user for OpenAM and the error code from DS is [$rr]"
     return 1
  fi

  LogMessage "CreateReadOnlyUser completed successfully"
  info "CreateReadOnlyUser completed successfully"
  return 0
}

####################################################################################
# Function: UpdateSsoUserPriv
# Description: This function updates ssouser adding some privileges
# Parameters: None
# Return:  0 everything ok, 1 fail
####################################################################################
UpdateSsoUserPriv()
{

  LogMessage "INFO: UpdateSsoUserPriv request has been received. Processing request..."
  info "UpdateSsoUserPriv request has been received. Processing request..."

  $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt << EOT | tee -a $LOG_FILE
dn: $SSO_USER_DN
changetype: modify
add: ds-privilege-name
ds-privilege-name: unindexed-search
EOT

  rr=${PIPESTATUS[0]}
  if [ $rr = 0 ] ; then
       LogMessage "INFO: Schema is up-to-date now: ds-privilege-name set to unindexed-search for ssouser"
       info "Schema is up-to-date now: ds-privilege-name set to unindexed-search for ssouser"
  else
      if [ $rr = 20 ] ; then
          LogMessage "INFO: Schema is already up-to-date: ds-privilege-name already set to unindexed-search for ssouser"
          info "Schema is already up-to-date: ds-privilege-name already set to unindexed-search for ssouser"
      else 
          LogMessage "ERROR: Failed to set ds-privilege-name to unindexed-search for ssouser"
          error "Failed to set ds-privilege-name to unindexed-search for ssouser and the error code from DS is [$rr]"
          return 1
      fi
  fi

  $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt <<EOT | tee -a $LOG_FILE
dn: $SSO_USER_DN
changetype: modify
add: ds-rlim-size-limit
ds-rlim-size-limit: 0
-
add: ds-rlim-lookthrough-limit
ds-rlim-lookthrough-limit: 0
-
add: ds-rlim-time-limit
ds-rlim-time-limit: 0
EOT

  rr=${PIPESTATUS[0]}
  if [ $rr = 0 ] ; then
       LogMessage "INFO: Schema is up-to-date now: ds-rlim-size-limit, ds-rlim-lookthrough-limit and ds-rlim-time-limit set for ssouser"
       info "Schema is up-to-date now: ds-rlim-size-limit, ds-rlim-lookthrough-limit and ds-rlim-time-limit set for ssouser"
  else
      if [ $rr = 20 ] ; then
          LogMessage "INFO: Schema is already up-to-date: ds-rlim-size-limit, ds-rlim-lookthrough-limit and ds-rlim-time-limit for ssouser already set"
          info "Schema is already up-to-date: ds-rlim-size-limit, ds-rlim-lookthrough-limit and ds-rlim-time-limit for ssouser already set"
      else 
          LogMessage "ERROR: Failed to set ds-rlim-size-limit, ds-rlim-lookthrough-limit and ds-rlim-time-limit for ssouser"
          error "Failed to set ds-rlim-size-limit, ds-rlim-lookthrough-limit and ds-rlim-time-limit for ssouser and the error code from DS is [$rr]"
          return 1
      fi
  fi

  LogMessage "UpdateSsoUserPriv completed successfully"
  info "UpdateSsoUserPriv completed successfully"
  return 0
}


###########################################################################################
# Function:PrimeSecData
# Description: This function creates the default security data
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################
PrimeSecData()
{

  LogMessage "PrimeSecData request has been received. Processing request..."

  $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt <<EOT | tee -a $LOG_FILE
dn: cn=DEFAULT_SCOPE,ou=Scopes,$BASE_DN
objectClass: groupOfUniqueNames
objectClass: top
cn: DEFAULT_SCOPE
description: This is the Default Scope
EOT

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ] && [ $rr -ne 68 ] ; then
     LogMessage "ERROR: Failed to create the [DEFAULT_SCOPE] Default scope and the error code from DS is [$rr]"
     error "Failed to create the [DEFAULT_SCOPE] Default scope and the error code from DS is [$rr]"
     return 1
  fi

  $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt <<EOT | tee -a $LOG_FILE
dn: cn=Read Only,ou=NE_ACCESS,ou=TargetGroups,$BASE_DN
objectClass: groupOfUniqueNames
objectClass: top
cn: Read Only
description: Read Only task profile
EOT

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ] && [ $rr -ne 68 ] ; then
     LogMessage "ERROR: Failed to create the [cn=Read Only] TaskProfile and the error code from DS is [$rr]"
     error "Failed to create the [cn=Read Only] TaskProfile and the error code from DS is [$rr]"
     return 1
  fi

  $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt <<EOT | tee -a $LOG_FILE
dn: cn=CM Normal,ou=NE_ACCESS,ou=TargetGroups,$BASE_DN
objectClass: groupOfUniqueNames
objectClass: top
cn: CM Normal
description: CM Normal task profile
EOT

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ] && [ $rr -ne 68 ] ; then
     LogMessage "ERROR: Failed to create the [cn=CM Normal] TaskProfile and the error code from DS is [$rr]"
     error "Failed to create the [cn=CM Normal] TaskProfile and the error code from DS is [$rr]"
     return 1
  fi

  $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt <<EOT | tee -a $LOG_FILE
dn: cn=CM Advanced,ou=NE_ACCESS,ou=TargetGroups,$BASE_DN
objectClass: groupOfUniqueNames
objectClass: top
cn: CM Advanced
description: CM Advanced
EOT

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ] && [ $rr -ne 68 ] ; then
     LogMessage "ERROR: Failed to create the [cn=CM Advanced] TaskProfile and the error code from DS is [$rr]"
     error "Failed to create the [cn=CM Advanced] TaskProfile and the error code from DS is [$rr]"
     return 1
  fi

  $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt <<EOT | tee -a $LOG_FILE
dn: cn=FM Normal,ou=NE_ACCESS,ou=TargetGroups,$BASE_DN
objectClass: groupOfUniqueNames
objectClass: top
cn: FM Normal
description: FM Normal task profile
EOT

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ] && [ $rr -ne 68 ] ; then
     LogMessage "ERROR: Failed to create the [cn=FM Normal] TaskProfile and the error code from DS is [$rr]"
     error "Failed to create the [cn=FM Normal] TaskProfile and the error code from DS is [$rr]"
     return 1
  fi

  $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt <<EOT | tee -a $LOG_FILE
dn: cn=FM Advanced,ou=NE_ACCESS,ou=TargetGroups,$BASE_DN
objectClass: groupOfUniqueNames
objectClass: top
cn: CM Advanced
description: FM Advanced
EOT

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ] && [ $rr -ne 68 ] ; then
     LogMessage "ERROR: Failed to create the [cn=FM Advanced] TaskProfile and the error code from DS is [$rr]"
     error "Failed to create the [cn=FM Advanced] TaskProfile and the error code from DS is [$rr]"
     return 1
  fi

  $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt <<EOT | tee -a $LOG_FILE
dn: cn=PM Normal,ou=NE_ACCESS,ou=TargetGroups,$BASE_DN
objectClass: groupOfUniqueNames
objectClass: top
cn: PM Normal
description: PM Normal task profile
EOT

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ] && [ $rr -ne 68 ] ; then
     LogMessage "ERROR: Failed to create the [cn=PM Normal] TaskProfile and the error code from DS is [$rr]"
     error "Failed to create the [cn=PM Normal] TaskProfile and the error code from DS is [$rr]"
     return 1
  fi

  $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt <<EOT | tee -a $LOG_FILE
dn: cn=PM Advanced,ou=NE_ACCESS,ou=TargetGroups,$BASE_DN
objectClass: groupOfUniqueNames
objectClass: top
cn: PM Advanced
description: PM Advanced
EOT

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ] && [ $rr -ne 68 ] ; then
     LogMessage "ERROR: Failed to create the [cn=PM Advanced] TaskProfile and the error code from DS is [$rr]"
     error "Failed to create the [cn=PM Advanced] TaskProfile and the error code from DS is [$rr]"
     return 1
  fi

  $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt <<EOT | tee -a $LOG_FILE
dn: cn=Security Management,ou=NE_ACCESS,ou=TargetGroups,$BASE_DN
objectClass: groupOfUniqueNames
objectClass: top
cn: Security Management
description: Security Management
EOT

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ] && [ $rr -ne 68 ] ; then
     LogMessage "ERROR: Failed to create the [cn=Security Management] TaskProfile and the error code from DS is [$rr]"
     error "Failed to create the [cn=Security Management] TaskProfile and the error code from DS is [$rr]"
     return 1
  fi

  $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt <<EOT | tee -a $LOG_FILE
dn: cn=Ericsson Support,ou=NE_ACCESS,ou=TargetGroups,$BASE_DN
objectClass: groupOfUniqueNames
objectClass: top
cn: Ericsson Support
description: Ericsson Support
EOT

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ] && [ $rr -ne 68 ] ; then
     LogMessage "ERROR: Failed to create the [cn=Ericsson Support] TaskProfile and the error code from DS is [$rr]"
     error "Failed to create the [cn=Ericsson Support] TaskProfile and the error code from DS is [$rr]"
     return 1
  fi

  LogMessage "PrimeSecData completed successfully"
  info "PrimeSecData completed successfully"

  return 0
}

###########################################################################################
# Function: DeleteOldHTTPConnector
# Description: This function delete the old HTTP connectors when upgrading from 3.0.0
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################
DeleteOldHTTPConnector()
{

    LogMessage "INFO: Deleting HTTP old connector"
    $DSCONFIG delete-connection-handler --port $ADMIN_CONNECTOR_PORT \
                                          --hostname localhost \
                                          --bindDN "$DM_DN"  \
                                          --bindPassword "$DM_PWD"  \
                                          --handler-name "HTTP Connection Handler" \
                                          --trustAll --no-prompt | tee -a $LOG_FILE
     rr=${PIPESTATUS[0]}
     if [ $rr -ne 0 ]; then
         LogMessage "ERROR: Failed to delete the old HTTP Connection Handler and the error code from DS is [$rr]"
         error "Failed to delete the old HTTP Connection Handler and the error code from DS is [$rr]"
         return 1
     fi

    LogMessage "INFO: Deleted HTTP old connector"
}

###########################################################################################
# Function: DeleteOldLDAPSConnector
# Description: This function delete the old LDAPS connectors when upgrading from 3.0.0
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################
DeleteOldLDAPSConnector()
{

    LogMessage "INFO: Deleting LDAPS old connector"
    $DSCONFIG delete-connection-handler --port $ADMIN_CONNECTOR_PORT \
                                          --hostname localhost \
                                          --bindDN "$DM_DN"  \
                                          --bindPassword "$DM_PWD"  \
                                          --handler-name "LDAPS Connection Handler" \
                                          --trustAll --no-prompt | tee -a $LOG_FILE
     rr=${PIPESTATUS[0]}
     if [ $rr -ne 0 ]; then
         LogMessage "ERROR: Failed to delete the old LDAPS Connection Handler and the error code from DS is [$rr]"
         error "Failed to delete the old LDAPS Connection Handler and the error code from DS is [$rr]"
         return 1
     fi

    LogMessage "INFO: Deleted LDAPS old connector"
}

###########################################################################################
# Function: DeleteOldJMXConnector
# Description: This function delete the old JMX connectors when upgrading from 3.0.0
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################
DeleteOldJMXConnector()
{

    LogMessage "INFO: Deleting JMX old connector"
    $DSCONFIG delete-connection-handler --port $ADMIN_CONNECTOR_PORT \
                                          --hostname localhost \
                                          --bindDN "$DM_DN"  \
                                          --bindPassword "$DM_PWD"  \
                                          --handler-name "JMX Connection Handler" \
                                          --trustAll --no-prompt | tee -a $LOG_FILE
     rr=${PIPESTATUS[0]}
     if [ $rr -ne 0 ]; then
         LogMessage "ERROR: Failed to delete the old HTTP Connection Handler and the error code from DS is [$rr]"
         error "Failed to delete the old HTTP Connection Handler and the error code from DS is [$rr]"
         return 1
     fi

    LogMessage "INFO: Deleted JMX old connector"
}

###########################################################################################
# Function: DeleteOldConnectors
# Description: This function delete old connectors when upgrading from 3.0.0
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################
DeleteOldConnectors()
{

    LogMessage "INFO: Deleting old connectors from 3.0.0"

    DeleteOldHTTPConnector
    if [ "$?" != "0" ] ; then
      LogMessage "ERROR: DisableOldHTTPConnector failed"
      error "DisableOldHTTPConnectors failed"
      return 1
    fi

    DeleteOldLDAPSConnector
    if [ "$?" != "0" ] ; then
      LogMessage "ERROR: DisableOldLDAPSConnector failed"
      error "DisableOldLDAPSConnector failed"
      return 1
    fi

    DeleteOldJMXConnector
    if [ "$?" != "0" ] ; then
      LogMessage "ERROR: DisableOldJMXConnector failed"
      error "DisableOldJMXConnector failed"
      return 1
    fi

    LogMessage "INFO: Old connectors from 3.0.0 deleted"
}

###########################################################################################
# Function: UpdateCiphersSuites 
# Description: This function update ciphers suites 
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################
UpdateCiphersSuites()
{

  LogMessage "INFO: Updating ciphers suites for  LDAPS connection handler"
  #Enable TLS protocols for existing LDAPS Connection Handler
  $DSCONFIG set-connection-handler-prop \
      --port $ADMIN_CONNECTOR_PORT \
      --hostname localhost \
      --bindDN "$DM_DN" \
      --bindPassword "$DM_PWD" \
      --handler-name LDAPS \
      --reset ssl-cipher-suite \
      ${ALLOWED_SUITES[@]/#/--set ssl-cipher-suite:} \
      --trustAll --no-prompt | tee -a $LOG_FILE

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ]; then
     LogMessage "ERROR: Failed to update  ciphers  for the LDPAS Connection Handler and the error code from DS is [$rr]"
     error "Failed to update  ciphers  for the LDPAS Connection Handler and the error code from DS is [$rr]"
     return 1
  fi


  LogMessage "INFO: Completed Updating ciphers suites for  LDAPS connection handler"

  LogMessage "INFO: Updating ciphers for HTTP Connection Handler "
  $DSCONFIG set-connection-handler-prop \
      --port $ADMIN_CONNECTOR_PORT \
      --hostname localhost \
      --bindDN "$DM_DN" \
      --bindPassword "$DM_PWD" \
      --handler-name HTTP \
      --reset ssl-cipher-suite \
      ${ALLOWED_SUITES[@]/#/--set ssl-cipher-suite:} \
      --trustAll --no-prompt | tee -a $LOG_FILE

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ]; then
     LogMessage "ERROR: Failed to update ciphers for the HTTP Connection Handler and the error code from DS is [$rr]"
     error "Failed to update ciphers for the HTTP Connection Handler and the error code from DS is [$rr]"
     return 1
  fi

  LogMessage "INFO: Update ciphers for crypto manager"
  $DSCONFIG set-crypto-manager-prop \
      --port $ADMIN_CONNECTOR_PORT \
      --hostname localhost \
      --bindDN "$DM_DN" \
      --bindPassword "$DM_PWD" \
      --reset ssl-cipher-suite \
      ${ALLOWED_SUITES[@]/#/--set ssl-cipher-suite:} \
      --trustAll --no-prompt | tee -a $LOG_FILE

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ]; then
     LogMessage "ERROR: Failed to update ciphers for the Crypto Manager and the error code from DS is [$rr]"
     error "Failed to update ciphers for the Crypto Manager and the error code from DS is [$rr]"
     return 1
  fi

  LogMessage "INFO: update ciphers for the administration connection handler"
  $DSCONFIG set-administration-connector-prop \
      --port $ADMIN_CONNECTOR_PORT \
      --hostname localhost \
      --bindDN "$DM_DN" \
      --bindPassword "$DM_PWD" \
      --reset ssl-cipher-suite \
      ${ALLOWED_SUITES[@]/#/--set ssl-cipher-suite:} \
      --trustAll --no-prompt | tee -a $LOG_FILE

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ]; then
     LogMessage "ERROR: Failed to update ciphers for the Admin Connection Handler and the error code from DS is [$rr]"
     error "Failed to update ciphers for the Admin Connection Handler and the error code from DS is [$rr]"
     return 1
  fi

  LogMessage "UpdateCiphersSuites completed successfully"


}
###########################################################################################
# Function: EnableTls
# Description: This function enable TLS protocols
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################
EnableTls()
{
  LogMessage "EnableTls request has been received. Processing request..."

  LogMessage "INFO: Checking LDAPS connection handler presence"
rtMess="$($DSCONFIG get-connection-handler-prop --port $ADMIN_CONNECTOR_PORT \
 --hostname localhost \
 --bindDN "$DM_DN" \
 --bindPassword "$DM_PWD" \
 --handler-name LDAPS \
 --trustAll --no-prompt )"

if [[ $rtMess != *"Property"* ]]
then
  LogMessage "INFO: Creating LDAPS connection handler and enabling TLS protocols"
    rtMess="$($DSCONFIG create-connection-handler \
 --hostname localhost  \
 --port $ADMIN_CONNECTOR_PORT \
 --bindDN "$DM_DN" \
 --bindPassword "$DM_PWD" \
 --handler-name LDAPS \
 --type ldap \
 --set listen-port:$COM_INF_LDAP_PORT \
 --set key-manager-provider:"PKCS12" \
 --set trust-manager-provider:"PKCS12" \
 --set ssl-cert-nickname:ssl-key-pair \
 --set use-ssl:true \
 --set ssl-protocol:TLSv1.3 \
 --set ssl-protocol:TLSv1.2 \
 ${ALLOWED_SUITES[@]/#/--set ssl-cipher-suite:} \
 --set enabled:true  --trustAll --no-prompt)"

    if [ "$?" == "0" ]
        then
            LogMessage "INFO: LDAPS connection handler created successfully"
    else
        LogMessage "ERROR: LDAPS creation failed"
        error "LDAPS connector creation failed"
        return 1
    fi
else
  # install or upgrade	
  LogMessage "INFO: Enabling TLS protocols for existing LDAPS connection handler"
  #Enable TLS protocols for existing LDAPS Connection Handler
  $DSCONFIG set-connection-handler-prop \
      --port $ADMIN_CONNECTOR_PORT \
      --hostname localhost \
      --bindDN "$DM_DN" \
      --bindPassword "$DM_PWD" \
      --handler-name LDAPS \
      --reset ssl-protocol \
      --set ssl-protocol:TLSv1.3 \
      --set ssl-protocol:TLSv1.2 \
      --reset ssl-cipher-suite \
      ${ALLOWED_SUITES[@]/#/--set ssl-cipher-suite:} \
      --trustAll --no-prompt | tee -a $LOG_FILE

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ]; then
     LogMessage "ERROR: Failed to enable TLS protocols for the LDPAS Connection Handler and the error code from DS is [$rr]"
     error "Failed to enable TLS protocols for the LDPAS Connection Handler and the error code from DS is [$rr]"
     return 1
  fi

  LogMessage "INFO: LDAPS connection handler updated successfully  "
fi

  # install or upgrade
  LogMessage "INFO: Enable TLS protocols for HTTP Connection Handler "
  $DSCONFIG set-connection-handler-prop \
      --port $ADMIN_CONNECTOR_PORT \
      --hostname localhost \
      --bindDN "$DM_DN" \
      --bindPassword "$DM_PWD" \
      --handler-name HTTP \
      --reset ssl-protocol \
      --set ssl-protocol:TLSv1.3 \
      --set ssl-protocol:TLSv1.2 \
      --reset ssl-cipher-suite \
      ${ALLOWED_SUITES[@]/#/--set ssl-cipher-suite:} \
      --trustAll --no-prompt | tee -a $LOG_FILE

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ]; then
     LogMessage "ERROR: Failed to enable TLS protocols for the HTTP Connection Handler and the error code from DS is [$rr]"
     error "Failed to enable TLS protocols for the HTTP Connection Handler and the error code from DS is [$rr]"
     return 1
  fi

  # removed crypto manager management
  # crypto manager has no more "ssl-protocol" and "allowed suites" properties

  LogMessage "INFO: Enable TLS protocols for the administration connection handler"
  $DSCONFIG set-administration-connector-prop \
      --port $ADMIN_CONNECTOR_PORT \
      --hostname localhost \
      --bindDN "$DM_DN" \
      --bindPassword "$DM_PWD" \
      --reset ssl-protocol \
      --set ssl-protocol:TLSv1.3 \
      --set ssl-protocol:TLSv1.2 \
      --reset ssl-cipher-suite \
      ${ALLOWED_SUITES[@]/#/--set ssl-cipher-suite:} \
      --trustAll --no-prompt | tee -a $LOG_FILE

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ]; then
     LogMessage "ERROR: Failed to enable TLS protocols for the Admin Connection Handler and the error code from DS is [$rr]"
     error "Failed to enable TLS protocols for the Admin Connection Handler and the error code from DS is [$rr]"
     return 1
  fi

  LogMessage "EnableTls completed successfully"
}



###########################################################################################
# Function: EnableTls_All
# Description: This function enable TLS protocols compatible with TLS1
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################
EnableTls_All()
{
  LogMessage "EnableTls_All request has been received. Processing request..."

  LogMessage "INFO: Checking LDAPS connection handler presence"
rtMess="$($DSCONFIG get-connection-handler-prop --port $ADMIN_CONNECTOR_PORT \
 --hostname localhost \
 --bindDN "$DM_DN" \
 --bindPassword "$DM_PWD" \
 --handler-name LDAPS \
 --trustAll --no-prompt )"

if [[ $rtMess != *"Property"* ]]
then
  LogMessage "INFO: Creating LDAPS connection handler and enabling TLS protocols"
    rtMess="$($DSCONFIG create-connection-handler \
 --hostname localhost  \
 --port $ADMIN_CONNECTOR_PORT \
 --bindDN "$DM_DN" \
 --bindPassword "$DM_PWD" \
 --handler-name LDAPS \
 --type ldap \
 --set listen-port:$COM_INF_LDAP_PORT \
 --set key-manager-provider:"PKCS12" \
 --set trust-manager-provider:"PKCS12" \
 --set ssl-cert-nickname:ssl-key-pair \
 --set use-ssl:true \
 --set ssl-protocol:TLSv1.3 \
 --set ssl-protocol:TLSv1.2 \
 --set ssl-protocol:TLSv1 \
 ${ALLOWED_SUITES_TLS1[@]/#/--set ssl-cipher-suite:} \
 --set enabled:true  --trustAll --no-prompt)"

    if [ "$?" == "0" ]
        then
            LogMessage "INFO: LDAPS connection handler created successfully"
    else
        LogMessage "ERROR: LDAPS creation failed"
        error "LDAPS connector creation failed"
        return 1
    fi
else
  # install or upgrade
  LogMessage "INFO: Enabling TLS protocols for existing LDAPS connection handler"
  #Enable TLS protocols for existing LDAPS Connection Handler
  $DSCONFIG set-connection-handler-prop \
      --port $ADMIN_CONNECTOR_PORT \
      --hostname localhost \
      --bindDN "$DM_DN" \
      --bindPassword "$DM_PWD" \
      --handler-name LDAPS \
      --reset ssl-protocol \
      --set ssl-protocol:TLSv1.3 \
      --set ssl-protocol:TLSv1.2 \
      --set ssl-protocol:TLSv1 \
      --reset ssl-cipher-suite \
      ${ALLOWED_SUITES_TLS1[@]/#/--set ssl-cipher-suite:} \
      --trustAll --no-prompt | tee -a $LOG_FILE

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ]; then
     LogMessage "ERROR: Failed to enable TLS protocols for the LDPAS Connection Handler and the error code from DS is [$rr]"
     error "Failed to enable TLS protocols for the LDPAS Connection Handler and the error code from DS is [$rr]"
     return 1
  fi

  LogMessage "INFO: LDAPS connection handler updated successfully  "
fi

  # install or upgrade
  LogMessage "INFO: Enable TLS protocols for HTTP Connection Handler "
  $DSCONFIG set-connection-handler-prop \
      --port $ADMIN_CONNECTOR_PORT \
      --hostname localhost \
      --bindDN "$DM_DN" \
      --bindPassword "$DM_PWD" \
      --handler-name HTTP \
      --reset ssl-protocol \
      --set ssl-protocol:TLSv1.3 \
      --set ssl-protocol:TLSv1.2 \
      --set ssl-protocol:TLSv1 \
      --reset ssl-cipher-suite \
      ${ALLOWED_SUITES_TLS1[@]/#/--set ssl-cipher-suite:} \
      --trustAll --no-prompt | tee -a $LOG_FILE

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ]; then
     LogMessage "ERROR: Failed to enable TLS protocols for the HTTP Connection Handler and the error code from DS is [$rr]"
     error "Failed to enable TLS protocols for the HTTP Connection Handler and the error code from DS is [$rr]"
     return 1
  fi

  # removed crypto manager management
  # crypto manager has no more "ssl-protocol" and "allowed suites" properties

  LogMessage "INFO: Enable TLS protocols for the administration connection handler"
  $DSCONFIG set-administration-connector-prop \
      --port $ADMIN_CONNECTOR_PORT \
      --hostname localhost \
      --bindDN "$DM_DN" \
      --bindPassword "$DM_PWD" \
      --reset ssl-protocol \
      --set ssl-protocol:TLSv1.3 \
      --set ssl-protocol:TLSv1.2 \
      --set ssl-protocol:TLSv1 \
      --reset ssl-cipher-suite \
      ${ALLOWED_SUITES_TLS1[@]/#/--set ssl-cipher-suite:} \
      --trustAll --no-prompt | tee -a $LOG_FILE

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ]; then
     LogMessage "ERROR: Failed to enable TLS protocols for the Admin Connection Handler and the error code from DS is [$rr]"
     error "Failed to enable TLS protocols for the Admin Connection Handler and the error code from DS is [$rr]"
     return 1
  fi

  LogMessage "EnableTls_All completed successfully"
}



###########################################################################################
# Function: setGdprAcis
# Description: This function hardens OpenDJ:
#              It sets access-control-properties for GDPR
#              see TORF-494389                         
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################

setGdprAcis()
{
  LogMessage "setGdprAcis request has been received."
  info "INFO: setGdprAcis request has been received."
  GDPREnabled="mail||givenName||sn||"


  enabled=$(grep "mail||givenName||sn" ${OPENDJ_ROOT}/config/config.ldif | grep -o "Authenticated users read access")

  if [ -z "$enabled" ]; then
    LogMessage "setGdprAcis Processing request..."
    info "INFO: setGdprAcis Processing request..."

    $DSCONFIG set-access-control-handler-prop \
--port $ADMIN_CONNECTOR_PORT \
--hostname localhost \
--bindDN "$DM_DN" --bindPassword "$DM_PWD" \
--remove global-aci:\(targetattr!=\"userPassword\|\|authPassword\|\|changes\|\|changeNumber\|\|changeType\|\|changeTime\|\|targetDN\|\|newRDN\|\|newSuperior\|\|deleteOldRDN\|\|targetEntryUUID\|\|changeInitiatorsName\|\|changeLogCookie\|\|includedAttributes\"\)\(version\ 3.0\;\ acl\ \"Authenticated\ users\ read\ access\"\;\ allow\ \(read,search,compare\)\ userdn=\"ldap:///all\"\;\) \
--add global-aci:\(targetattr!=\"mail\|\|givenName\|\|sn\|\|userPassword\|\|authPassword\|\|changes\|\|changeNumber\|\|changeType\|\|changeTime\|\|targetDN\|\|newRDN\|\|newSuperior\|\|deleteOldRDN\|\|targetEntryUUID\|\|changeInitiatorsName\|\|changeLogCookie\|\|includedAttributes\"\)\(version\ 3.0\;\ acl\"Authenticated\ users\ read\ access\"\;\ allow\(read,search,compare\)\ userdn=\"ldap:///all\"\;\) \
--add global-aci:\(targetattr=\"mail\|\|givenName\|\|sn\|\|userPassword\|\|authPassword\"\)\(version\ 3.0\;\ acl\"Self\ entry\ read\"\;\ allow\ \(read,search,compare\)userdn=\"ldap:///self\"\;\) \
--trustAll --no-prompt | tee -a $LOG_FILE

    rr=${PIPESTATUS[0]}
     if [ $rr -ne 0 ]; then
        LogMessage "ERROR: \"Self entry read and Authenticated users read access\" setting failed [$rr]"
        error "ERROR: \"Self entry read and Authenticated users read access\" setting failed [$rr]"
        return 1
     fi
  fi
  LogMessage "setGdprAcis completed successfully"
  info "INFO: setGdprAcis completed successfully"
  return 0
}



###########################################################################################
# Function: HardenOpendj
# Description: This function hardens OpenDJ:
#              It adds the needed ACIs to make ssouser a read-only user
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################
HardenOpendj()
{
  LogMessage "HardenOpendj request has been received. Processing request..."
  #Disable non SSL port
  $DSCONFIG create-connection-handler \
      --port $ADMIN_CONNECTOR_PORT \
      --hostname localhost \
      --bindDN "$DM_DN" \
      --bindPassword "$DM_PWD" \
      --handler-name LDAP \
      --type ldap \
      --set listen-port:1389 \
      --set enabled:false \
      --trustAll --no-prompt | tee -a $LOG_FILE

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ]; then
     LogMessage "ERROR: Failed to disable the non secure port and the error code from DS is [$rr]"
     error "Failed to disable the non secure port and the error code from DS is [$rr]"
     return 1
  fi

  # Set ACIs for ssouser
  $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt <<EOT | tee -a $LOG_FILE
dn: $BASE_DN
changetype: modify
add: aci
aci: (targetattr="*")(version 3.0;acl "Allow entry search"; allow ( search, read)(userdn = "ldap:///$SSO_USER_DN");)
aci: (targetattr="*")(version 3.0;acl "Modify config entry"; allow (write)( userdn = "ldap:///$SSO_USER_DN");)
aci: (targetcontrol="2.16.840.1.113730.3.4.3")(version 3.0;acl "Allow  persistent search"; allow (search, read)(userdn = "ldap:///$SSO_USER_DN");)
aci: (version 3.0;acl "Add config entry"; allow (add)(userdn = "ldap:///$SSO_USER_DN");)
aci: (version 3.0;acl "Delete config entry"; allow (delete)(userdn = "ldap:///$SSO_USER_DN");)
EOT

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ] && [ $rr -ne 68 ] && [ $rr -ne 20 ] ; then
     LogMessage "ERROR: Failed to add ACI for OpenAM read only user and the error code from DS is [$rr]"
     error "Failed to add ACI for OpenAM read only user and the error code from DS is [$rr]"
     return 1
  fi

# TEMPORARY  
#  $DSCONFIG set-access-control-handler-prop \
#      --port $ADMIN_CONNECTOR_PORT \
#      --hostname localhost \
#      --bindDN "$DM_DN" --bindPassword "$DM_PWD" \
#      --remove global-aci:'(targetattr!="userPassword||authPassword||debugsearchindex||changes||changeNumber||changeType||change#Time||targetDN||newRDN||newSuperior||deleteOldRDN")(version 3.0; acl "Anonymous read access"; allow (read,search,compare) userdn#="ldap:///anyone";)' \
#      --trustAll --no-prompt | tee -a $LOG_FILE

#  rr=${PIPESTATUS[0]}
#  if [ $rr -ne 0 ] && [ $rr -ne 68 ] && [ $rr -ne 20 ] ; then
#     LogMessage "ERROR: Failed to remove \"Anonymous read access\" aci and the error code from DS is [$rr]"
#     error "Failed to remove \"Anonymous read access\" aci and the error code from DS is [$rr]"
#     return 1
#  fi

  $DSCONFIG set-access-control-handler-prop \
      --port $ADMIN_CONNECTOR_PORT \
      --hostname localhost \
      --bindDN "$DM_DN" --bindPassword "$DM_PWD" \
      --add global-aci:'(targetattr!="userPassword||authPassword||changes||changeNumber||changeType||changeTime||targetDN||newRDN||newSuperior||deleteOldRDN||targetEntryUUID||changeInitiatorsName||changeLogCookie||includedAttributes")(version 3.0; acl "Authenticated users read access"; allow (read,search,compare) userdn="ldap:///all";)' \
      --trustAll --no-prompt | tee -a $LOG_FILE

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ]; then
     LogMessage "ERROR: Failed to add \"Authenticated users read access\" aci and the error code from DS is [$rr]"
     error "Failed to add \"Authenticated users read access\" aci and the error code from DS is [$rr]"
     return 1
  fi

# TEMPORARY  
#  $DSCONFIG set-access-control-handler-prop \
#      --port $ADMIN_CONNECTOR_PORT \
#      --hostname localhost \
#      --bindDN "$DM_DN" --bindPassword "$DM_PWD" \
#      --remove global-aci:'(targetattr="createTimestamp||creatorsName||modifiersName||modifyTimestamp||entryDN||entryUUID||subschemaSubentry||etag||governingStructureRule||structuralObjectClass||hasSubordinates||numSubordinates||isMemberOf||alive||healthy")(version 3.0; acl "User-Visible Operational Attributes"; allow (read,search,compare) userdn="ldap:///anyone";)' \
#      --trustAll --no-prompt | tee -a $LOG_FILE

#  rr=${PIPESTATUS[0]}
#  if [ $rr -ne 0 ]; then
#     LogMessage "ERROR: Failed to remove \"User-Visible Operational Attributes\" aci and the error code from DS is [$rr]"
#     error "Failed to remove \"User-Visible Operational Attributes\" aci and the error code from DS is [$rr]"
#     return 1
#  fi


  $DSCONFIG set-access-control-handler-prop \
      --port $ADMIN_CONNECTOR_PORT \
      --hostname localhost \
      --bindDN "$DM_DN" --bindPassword "$DM_PWD" \
      --add global-aci:'(targetattr="createTimestamp||creatorsName||modifiersName||modifyTimestamp||entryDN||entryUUID||subschemaSubentry")(version 3.0; acl "User-Visible Operational Attributes"; allow (read,search,compare) userdn="ldap:///all";)' \
      --trustAll --no-prompt | tee -a $LOG_FILE

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ]; then
     LogMessage "ERROR: Failed to add \"User-Visible Operational Attributes\" aci and the error code from DS is [$rr]"
     error "Failed to add \"User-Visible Operational Attributes\" aci and the error code from DS is [$rr]"
     return 1
  fi


  # Enable anonymous access to certain attributes of users under ou=people M2Musers
  $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt <<EOT | tee -a $LOG_FILE
dn: ou=people,$BASE_DN
changetype: modify
add: aci
aci: (targetattr!="ds-pwp-account-disabled||pwdReset||ds-pwp-password-expiration-time||etag||subschemaSubentry||createTimestamp||numSubordinates||structuralObjectClass||ds-sync-hist||hasSubordinates||entryDN||entryUUID||creatorsName||modifyTimestamp||modifiersName||isMemberOf||ds-pwp-password-policy-dn||pwdPolicySubentry||pwdChangedTime||lastLoginTime||givenName||cn||userType||sn||mail||dn||userpassword||authPassword||changes||changeNumber||changeType||changeTime||targetDN||newRDN||newSuperior||deleteOldRDN||targetEntryUUID||changeInitiatorsName||changeLogCookie||includedAttributes")(version 3.0;acl "Anonymous read access to certain attributes of users under ou=people container"; allow (read,search,compare) (userdn="ldap:///anyone");)
EOT

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ] && [ $rr -ne 68 ] && [ $rr -ne 20 ] ; then
     LogMessage "ERROR: Failed to enable anonymous access to certain attributes of users under ou=people container and the error code from DS is [$rr]"
     error "Failed to enable anonymous access to certain attributes of users under ou=people container and the error code from DS is [$rr]"
     return 1
  fi

# Enable anonymous access to certain attributes of ou=Groups
  $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt <<EOT | tee -a $LOG_FILE
dn: ou=Groups,$BASE_DN
changetype: modify
add: aci
aci: (targetattr!="ds-pwp-account-disabled||pwdReset||ds-pwp-password-expiration-time||etag||subschemaSubentry||createTimestamp||numSubordinates||structuralObjectClass||ds-sync-hist||hasSubordinates||entryDN||entryUUID||creatorsName||modifyTimestamp||modifiersName||isMemberOf||ds-pwp-password-policy-dn||pwdPolicySubentry||pwdChangedTime||lastLoginTime||givenName||userType||sn||mail||dn||userpassword||authPassword||changes||changeNumber||changeType||changeTime||targetDN||newRDN||newSuperior||deleteOldRDN||targetEntryUUID||changeInitiatorsName||changeLogCookie||includedAttributes")(version 3.0;acl "Anonymous read access to certain attributes of users under ou=people container"; allow (read,search,compare) (userdn="ldap:///anyone");)
EOT

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ] && [ $rr -ne 68 ] && [ $rr -ne 20 ] ; then
     LogMessage "ERROR: Failed to enable anonymous access to certain attributes of users under ou=Groups container and the error code from DS is [$rr]"
     error "Failed to enable anonymous access to certain attributes of users under ou=Groups container and the error code from DS is [$rr]"
     return 1
  fi

  # Enable anonymous access to certain attributes of M2Musers
  $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt <<EOT | tee -a $LOG_FILE
dn: ou=M2MUsers,$BASE_DN
changetype: modify
add: aci
aci: (targetattr!="ds-pwp-account-disabled||pwdReset||ds-pwp-password-expiration-time||etag||subschemaSubentry||createTimestamp||numSubordinates||structuralObjectClass||ds-sync-hist||hasSubordinates||entryDN||entryUUID||creatorsName||modifyTimestamp||modifiersName||isMemberOf||ds-pwp-password-policy-dn||pwdPolicySubentry||pwdChangedTime||lastLoginTime||givenName||cn||userType||sn||mail||dn||userpassword||authPassword||changes||changeNumber||changeType||changeTime||targetDN||newRDN||newSuperior||deleteOldRDN||targetEntryUUID||changeInitiatorsName||changeLogCookie||includedAttributes")(version 3.0;acl "Anonymous read access to certain attributes of m2m users"; allow (read,search,compare) (userdn="ldap:///anyone");)
EOT

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ] && [ $rr -ne 68 ] && [ $rr -ne 20 ] ; then
     LogMessage "ERROR: Failed to enable anonymous access to certain attributes of m2musers and the error code from DS is [$rr]"
     error "Failed to enable anonymous access to certain attributes of m2musers and the error code from DS is [$rr]"
     return 1
  fi

  setGdprAcis
  if [ "$?" != "0" ] ; then
     return 1
  fi

  LogMessage "HardenOpendj completed successfully"
  info "HardenOpendj completed successfully"
  return 0
}

###########################################################################################
# Function: UpdatePasswords
# Description: This function updates the Directory Manager and SSO user passwords
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################
UpdatePasswords()
{
  LogMessage "UpdatePasswords request has been received. Processing request..."

  if [[ -z "${COM_INF_LDAP_ADMIN_ACCESS}" || -z "${LDAP_ADMIN_PASSWORD}" ]]; then
    LogMessage "ERROR: COM_INF_LDAP_ADMIN_ACCESS or LDAP_ADMIN_PASSWORD is not set in ${GLOBAL_PROPERTY_FILE}"
    error "COM_INF_LDAP_ADMIN_ACCESS or LDAP_ADMIN_PASSWORD is not set in ${GLOBAL_PROPERTY_FILE}"
    return 1
  fi

  if [ -r ${SSOLDAP_PASSKEY} ]; then
    SSO_USER_PWD=`echo ${COM_INF_LDAP_ADMIN_ACCESS} | ${OPENSSL} enc -a -d -md md5 -aes-128-cbc -salt -kfile ${SSOLDAP_PASSKEY}`
    if [ -z "${SSO_USER_PWD}" ]; then
      LogMessage "ERROR: Failed to decrypt COM_INF_LDAP_ADMIN_ACCESS from ${GLOBAL_PROPERTY_FILE}"
      error "Failed to decrypt COM_INF_LDAP_ADMIN_ACCESS from ${GLOBAL_PROPERTY_FILE}"
      return 1
    fi
  else
    LogMessage "INFO: ${SSOLDAP_PASSKEY} does not exist or is not readable"
    return 1
  fi

  if [ -r ${OPENDJ_PASSKEY} ]; then
    DM_PWD=`echo ${LDAP_ADMIN_PASSWORD} | ${OPENSSL} enc -a -d -md md5 -aes-128-cbc -salt -kfile ${OPENDJ_PASSKEY}`
    if [ -z "${DM_PWD}" ]; then
      LogMessage "ERROR: Failed to decrypt LDAP_ADMIN_PASSWORD from ${GLOBAL_PROPERTY_FILE}"
      error "Failed to decrypt LDAP_ADMIN_PASSWORD from ${GLOBAL_PROPERTY_FILE}"
      return 1
    fi
  else
    LogMessage "INFO: ${OPENDJ_PASSKEY} does not exist or is not readable"
    return 1
  fi

  LogMessage "UpdatePasswords completed successfully"
  info "UpdatePasswords completed successfully"
  return 0
}

###########################################################################################
# Function: UpdateRandomPasswordGenerator
# Description: This function updates the Random Password Generator attribiutes
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################
UpdateRandomPasswordGenerator()
{
    LogMessage "UpdateRandomPasswordGenerator request has been received. Processing request ......"

    rtMessage="$($DSCONFIG set-password-generator-prop --port $ADMIN_CONNECTOR_PORT \
                                         --hostname localhost \
                                         --bindDN "$DM_DN" \
                                         --bindPassword "$DM_PWD" \
                                         --generator-name "${RANDOM_PASSWD_GENERATOR}" \
                                         --set password-character-set:alpha:abcdefghijklmnopqrstuvwxyz \
                                         --set password-character-set:numeric:0123456789 \
                                         --set password-format:alpha:3,numeric:2,alpha:3 \
                                         -X -n 2>&1 > /dev/null)"
    if [ $? != 0 ]
    then
        LogMessage "ERROR: $rtMessage"
        LogMessage "ERROR: Failed to Set Random Password Generator"
        error "$rtMessage"
        error "Failed to Set Random Password Generator"
        return 1
    else
        LogMessage "Succeed to Set Random Password Generator"
    fi
    LogMessage "UpdateRandomPasswordGenerator completed successfully "
    info "UpdateRandomPasswordGenerator completed successfully "
    return 0
}

################################################################################
# Function:    DefineLogRotationPolicies
# Description: Set the properties for OpenDJ Log Rotation Policies
# Parameters:  None
#
# Returns:
#             0      Succeed
#             1      Failed
################################################################################
function DefineLogRotationPolicies() {
    LogMessage "DefineLogRotationPolicies has been received. Processing request ......"
    LogMessage "Start to set properties for \"$TIME_LIMIT_ROTATION_POLICY\" "
    rtMessage="$($DSCONFIG set-log-rotation-policy-prop --port $ADMIN_CONNECTOR_PORT \
                                           --hostname localhost \
                                           --bindDN "$DM_DN" \
                                           --bindPassword "$DM_PWD" \
                                           --policy-name "$TIME_LIMIT_ROTATION_POLICY" \
                                           --set "rotation-interval:$LOG_ROTATION_TIME_LIMIT" \
                                           -X -n 2>&1 > /dev/null)"
    if [ $? != 0 ]
    then
        LogMessage "ERROR: $rtMessage"
        LogMessage "ERROR: Fail to set properties for \"$TIME_LIMIT_ROTATION_POLICY\" "
        error "$rtMessage"
        error "Fail to set properties for \"$TIME_LIMIT_ROTATION_POLICY\" "
        return 1
    else
        LogMessage "Succeed to set properties for \"$TIME_LIMIT_ROTATION_POLICY\" "
    fi

    LogMessage "Start to configure \"$SIZE_LIMIT_ROTATION_POLICY\" "

    rtMessage="$($DSCONFIG set-log-rotation-policy-prop --port $ADMIN_CONNECTOR_PORT \
                                           --hostname localhost \
                                           --bindDN "$DM_DN" \
                                           --bindPassword "$DM_PWD" \
                                           --policy-name "$SIZE_LIMIT_ROTATION_POLICY" \
                                           --set "file-size-limit:$LOG_ROTATION_FILE_SIZE_LIMIT" \
                                           -X -n 2>&1 > /dev/null)"
    if [ $? != 0 ]
    then
        LogMessage "ERROR: $rtMessage"
        LogMessage "ERROR: Fail to set properties for \"$SIZE_LIMIT_ROTATION_POLICY\" "
        error "$rtMessage"
        error "Fail to set properties for \"$SIZE_LIMIT_ROTATION_POLICY\" "
        return 1
    else
        LogMessage "Succeed to set properties for \"$SIZE_LIMIT_ROTATION_POLICY\" "
    fi

    LogMessage "DefineLogRotationPolicies completed successfully"
    info "DefineLogRotationPolicies completed successfully"
    return 0
}

################################################################################
# Function:    DefineLogRetentionPolicies
# Description: Set Properties for Opendj Log Retention Policies
# Parameters:  None
#
# Returns:
#             0      Succeed
#             1      Failed
################################################################################
function DefineLogRetentionPolicies () {
    LogMessage "DefineLogRetentionPolicies request has been reveived. Processing request..."
    LogMessage "Start to set properties for \"$FILE_COUNT_RETENTION_POLICY\" "
    rtMessage="$($DSCONFIG set-log-retention-policy-prop --port $ADMIN_CONNECTOR_PORT \
               --hostname localhost \
              --bindDN "$DM_DN" \
              --bindPassword "$DM_PWD" \
              --policy-name "$FILE_COUNT_RETENTION_POLICY"  \
              --set "number-of-files:$LOG_RETENTION_FILE_NUMBER_LIMIT" \
              -X -n 2>&1 > /dev/null)"
    if [ $? != 0 ]
    then
        LogMessage "ERROR: $rtMessage"
        LogMessage "ERROR: Fail to set properties for \"$FILE_COUNT_RETENTION_POLICY\" "
        error "$rtMessage"
        error "Fail to set properties for \"$FILE_COUNT_RETENTION_POLICY\" "
        return 1
    else
        LogMessage "Succeed to set properties for \"$FILE_COUNT_RETENTION_POLICY\" "
    fi
    LogMessage "Start to set properties for \"$SIZE_LIMIT_RETENTION_POLICY\" "

    rtMessage="$($DSCONFIG set-log-retention-policy-prop --port $ADMIN_CONNECTOR_PORT \
                                            --hostname localhost \
                                            --bindDN "$DM_DN" \
                                            --bindPassword "$DM_PWD" \
                                            --policy-name "$SIZE_LIMIT_RETENTION_POLICY" \
                                            --set "disk-space-used:$LOG_RETENTION_TOTAL_SIZE_LIMIT" \
                                            -X -n 2>&1 > /dev/null)"
    if [ $? != 0 ]
    then
        LogMessage "ERROR: $rtMessage"
        LogMessage "ERROR: Fail to set properties for \"Size Limit Retention Policy\" "
        error "$rtMessage"
        error "Fail to set properties for \"Size Limit Retention Policy\" "
        return 1
    else
        LogMessage "Succeed to set properties for \"Size Limit Retention Policy\" "
    fi

    LogMessage "Create \"$SIZE_LIMIT_RETENTION_POLICY_ACCESS\" "
    rtMessage="$($DSCONFIG create-log-retention-policy --port $ADMIN_CONNECTOR_PORT \
                                            --hostname localhost \
                                            --bindDN "$DM_DN" \
                                            --bindPassword "$DM_PWD" \
                                            --policy-name "$SIZE_LIMIT_RETENTION_POLICY_ACCESS" \
                                            --type "size-limit" \
                                            --set "disk-space-used:$LOG_RETENTION_TOTAL_SIZE_LIMIT" \
                                            -X -n 2>&1 > /dev/null)"
    if [ $? != 0 ]
    then
        LogMessage "ERROR: $rtMessage"
        LogMessage "ERROR: Fail to create policy \"Size Limit Retention Policy Access\" "
        error "$rtMessage"
        error "Fail to create policy \"Size Limit Retention Policy Access\" "
        return 1
    else
        LogMessage "Succeed to create policy \"Size Limit Retention Policy Access\" "
    fi

    LogMessage "Create \"$SIZE_LIMIT_RETENTION_POLICY_AUDIT\" "
    rtMessage="$($DSCONFIG create-log-retention-policy --port $ADMIN_CONNECTOR_PORT \
                                            --hostname localhost \
                                            --bindDN "$DM_DN" \
                                            --bindPassword "$DM_PWD" \
                                            --policy-name "$SIZE_LIMIT_RETENTION_POLICY_AUDIT" \
                                            --type "size-limit" \
                                            --set "disk-space-used:$LOG_RETENTION_TOTAL_SIZE_LIMIT" \
                                            -X -n 2>&1 > /dev/null)"
    if [ $? != 0 ]
    then
        LogMessage "ERROR: $rtMessage"
        LogMessage "ERROR: Fail to create policy \"Size Limit Retention Policy Audit\" "
        error "$rtMessage"
        error "Fail to create policy \"Size Limit Retention Policy Audit\" "
        return 1
    else
        LogMessage "Succeed to create policy \"Size Limit Retention Policy Audit\" "
    fi

    LogMessage "Create \"$SIZE_LIMIT_RETENTION_POLICY_ERROR\" "
    rtMessage="$($DSCONFIG create-log-retention-policy --port $ADMIN_CONNECTOR_PORT \
                                            --hostname localhost \
                                            --bindDN "$DM_DN" \
                                            --bindPassword "$DM_PWD" \
                                            --policy-name "$SIZE_LIMIT_RETENTION_POLICY_ERROR" \
                                            --type "size-limit" \
                                            --set "disk-space-used:$LOG_RETENTION_TOTAL_SIZE_LIMIT" \
                                            -X -n 2>&1 > /dev/null)"
    if [ $? != 0 ]
    then
        LogMessage "ERROR: $rtMessage"
        LogMessage "ERROR: Fail to create policy \"Size Limit Retention Policy Error\" "
        error "$rtMessage"
        error "Fail to create policy \"Size Limit Retention Policy Error\" "
        return 1
    else
        LogMessage "Succeed to create policy \"Size Limit Retention Policy Error\" "
    fi

    LogMessage "Create \"$SIZE_LIMIT_RETENTION_POLICY_REPLICATION\" "
    rtMessage="$($DSCONFIG create-log-retention-policy --port $ADMIN_CONNECTOR_PORT \
                                            --hostname localhost \
                                            --bindDN "$DM_DN" \
                                            --bindPassword "$DM_PWD" \
                                            --policy-name "$SIZE_LIMIT_RETENTION_POLICY_REPLICATION" \
                                            --type "size-limit" \
                                            --set "disk-space-used:$LOG_RETENTION_TOTAL_SIZE_LIMIT" \
                                            -X -n 2>&1 > /dev/null)"
    if [ $? != 0 ]
    then
        LogMessage "ERROR: $rtMessage"
        LogMessage "ERROR: Fail to create policy \"Size Limit Retention Policy Replication\" "
        error "$rtMessage"
        error "Fail to create policy \"Size Limit Retention Policy Replication\" "
        return 1
    else
        LogMessage "Succeed to create policy \"Size Limit Retention Policy Replication\" "
    fi

    LogMessage "DefineLogRetentionPolicies compelted successfully!"
    info "DefineLogRetentionPolicies compelted successfully!"
    return 0
}

################################################################################
# Function:    AssignLogPoliciesToLogPublisher
# Description: Assign Log Rotation and Retention Policies to each Logger Publisher
# Parameters:  None
#
# Returns:
#             0      Succeed
#             1      Failed
################################################################################
function AssignLogPoliciesToLogPublisher() {
    LogMessage "AssignLogPoliciesToLogPublisher request has been received. Processing request ......"
    TMP_SIZE_LIMIT_RETENTION_POLICY=$SIZE_LIMIT_RETENTION_POLICY

    for (( i=0; i<"${#LOG_PUBLISHERS[@]}"; i++ )) {
        LogMessage "Start to set Log Policies to log publisher \"${LOG_PUBLISHERS[$i]}\" "
        
        #From 6.5.0 default for access logger has been changed from file-based only to json, so it is re-enabled back
        case ${LOG_PUBLISHERS[$i]} in
          'File-Based Access Logger')
            TMP_SIZE_LIMIT_RETENTION_POLICY=$SIZE_LIMIT_RETENTION_POLICY_ACCESS
            $DSCONFIG set-log-publisher-prop --port $ADMIN_CONNECTOR_PORT --hostname localhost --bindDN "$DM_DN" --bindPassword "$DM_PWD" --publisher-name "File-Based Access Logger" --set enabled:true -X -n 2>&1 > /dev/null
            $DSCONFIG set-log-publisher-prop --port $ADMIN_CONNECTOR_PORT --hostname localhost --bindDN "$DM_DN" --bindPassword "$DM_PWD" --publisher-name "Json File-Based Access Logger" --set enabled:false -X -n 2>&1 > /dev/null
            $DSCONFIG set-log-publisher-prop --port $ADMIN_CONNECTOR_PORT --hostname localhost --bindDN "$DM_DN" --bindPassword "$DM_PWD" --publisher-name "Filtered Json File-Based Access Logger" --set enabled:false -X -n 2>&1 > /dev/null
          ;;
          'File-Based Audit Logger')
            TMP_SIZE_LIMIT_RETENTION_POLICY=$SIZE_LIMIT_RETENTION_POLICY_AUDIT
          ;;
          'File-Based Error Logger')
            TMP_SIZE_LIMIT_RETENTION_POLICY=$SIZE_LIMIT_RETENTION_POLICY_ERROR
          ;;
          *)
            TMP_SIZE_LIMIT_RETENTION_POLICY=$SIZE_LIMIT_RETENTION_POLICY
          ;;
        esac
        rtMessage="$($DSCONFIG set-log-publisher-prop --port $ADMIN_CONNECTOR_PORT \
                                         --hostname localhost \
                                         --bindDN "$DM_DN" \
                                         --bindPassword "$DM_PWD" \
                                         --publisher-name "${LOG_PUBLISHERS[$i]}" \
                                         --set "retention-policy:$FILE_COUNT_RETENTION_POLICY" \
                                         --set "retention-policy:$TMP_SIZE_LIMIT_RETENTION_POLICY" \
                                         --set "rotation-policy:$TIME_LIMIT_ROTATION_POLICY" \
                                         --set "rotation-policy:$SIZE_LIMIT_ROTATION_POLICY" \
                                         -X -n 2>&1 > /dev/null)"
       if [ $? != 0 ]
       then
           LogMessage "ERROR: $rtMessage"
           LogMessage "ERROR: Fail to assign Log Policies to log publisher \"${LOG_PUBLISHERS[$i]}\" "
           error "$rtMessage"
           error "Fail to assign Log Policies to log publisher \"${LOG_PUBLISHERS[$i]}\" "
           return 1
       else
           LogMessage "Succeed to set Log policies to log publisher \"${LOG_PUBLISHERS[$i]}\" "
       fi
    }
    LogMessage "AssignLogPoliciesToLogPublisher completed successfully "
    info "AssignLogPoliciesToLogPublisher completed successfully "
    return 0
}

################################################################################
# Function:    EnableAuditLogPublisher
# Description: Enable Audit Log Publisher
# Parameters:  None
#
# Returns:
#             0      Succeed
#             1      Failed
################################################################################
function EnableAuditLogPublisher() {
    LogMessage "EnableAuditLogPublisher request has been received. Processing request ......"
    LogMessage "Start to Enable Audit Log Publisher"
    rtMessage="$($DSCONFIG set-log-publisher-prop --port $ADMIN_CONNECTOR_PORT \
                                         --hostname localhost \
                                         --bindDN "$DM_DN" \
                                         --bindPassword "$DM_PWD" \
                                         --publisher-name "$AUDITLOGPUBLISHER" \
                                         --set enabled:true \
                                         -X -n 2>&1 > /dev/null)"
    if [ $? != 0 ]
    then
        LogMessage "ERROR: $rtMessage"
        LogMessage "ERROR: Failed to Enable Audit Log Publisher"
        error "$rtMessage"
        error "Failed to Enable Audit Log Publisher"
        return 1
    else
        LogMessage "Succeed to Enable Audit Log Publisher"
    fi
    LogMessage "EnableAuditLogPublisher completed successfully "
    info "EnableAuditLogPublisher completed successfully "
    return 0
}

################################################################################
# Function:    EnableCustomLogPolicies
# Description: Enable customized log policies for log publishers during upgrade
#              if needed
# Parameters:  None
#
# Returns:
#             0      Succeed
#             1      Failed
################################################################################
function EnableCustomLogPolicies() {
    LogMessage "EnableCustomLogPolicies request has been received. Processing request ......"
    LogMessage "Start to Enable Custom Log Policies"

    LogMessage "Check existence of \"$SIZE_LIMIT_RETENTION_POLICY_ACCESS\" "
    rtMessage="$($DSCONFIG get-log-retention-policy-prop --port $ADMIN_CONNECTOR_PORT \
                                            --hostname localhost \
                                            --bindDN "$DM_DN" \
                                            --bindPassword "$DM_PWD" \
                                            --policy-name "$SIZE_LIMIT_RETENTION_POLICY_ACCESS" \
                                            -X -n )"
    if [[ $rtMessage == *"Property"* ]]
    then
        LogMessage "Policy \"Size Limit Retention Policy Access\" already exists, no further actions required "
        info "Policy \"Size Limit Retention Policy Access\" already exists, no further actions required "
        LogMessage "Disable Filtered Json File-BAsed Access Logger "
        info "Disable Filtered Json File-BAsed Access Logger "
        $DSCONFIG set-log-publisher-prop --port $ADMIN_CONNECTOR_PORT --hostname localhost --bindDN "$DM_DN" --bindPassword "$DM_PWD" --publisher-name "Filtered Json File-Based Access Logger" --set enabled:false -X -n 2>&1 > /dev/null

        return 0
    else
        LogMessage " Policy \"Size Limit Retention Policy Access\" does not exists, custom retention policies will be created"
        info "Policy \"Size Limit Retention Policy Access\" does not exists, custom retention policies will be created"
    fi

    DefineLogRetentionPolicies
    if [ $? != 0 ]
    then
        LogMessage "ERROR: Failed to re-define retention log policies to Enable Custom Log Policies"
        error "Failed to re-define retention log policies to Enable Custom Log Policies"
        return 1
    else
        LogMessage "Succeed to re-define retention log policies to Enable Custom Log Policies"
    fi

    DefineLogRotationPolicies
    if [ $? != 0 ]
    then
        LogMessage "ERROR: Failed to re-define rotation log policies to Enable Custom Log Policies"
        error "Failed to re-define rotation log policies to Enable Custom Log Policies"
        return 1
    else
        LogMessage "Succeed to re-define rotation log policies to Enable Custom Log Policies"
    fi

    AssignLogPoliciesToLogPublisher
    if [ $? != 0 ]
    then
        LogMessage "ERROR: Failed to assign log policies to Enable Custom Log Policies"
        error "Failed to assign log policies to Enable Custom Log Policies"
        return 1
    else
        LogMessage "Succeed to assign log policies to Enable Custom Log Policies"
    fi

    LogMessage "EnableCustomLogPolicies completed successfully "
    info "EnableCustomLogPolicies completed successfully "
    return 0
}

################################################################################
# Function:    SetSuperUserPasswordPolicy
# Description: Set Super User Password Policy
# Parameters:  None
#
# Returns:
#             0      Succeed
#             1      Failed
################################################################################
function SetSuperUserPasswordPolicy() {
    LogMessage "SetSuperUserPasswordPolicy request has been received. Processing request ......"

    rtMessage="$($DSCONFIG set-password-policy-prop --port $ADMIN_CONNECTOR_PORT \
                                         --hostname localhost \
                                         --bindDN "$DM_DN" \
                                         --bindPassword "$DM_PWD" \
                                         --policy-name "${SUPER_USER_PASSWD_POLICY}" \
                                         --set allow-pre-encoded-passwords:true \
                                         --reset lockout-failure-count \
                                         --reset lockout-duration \
                                         --reset lockout-failure-expiration-interval \
                                         -X -n 2>&1 > /dev/null)"
    if [ $? != 0 ]
    then
        LogMessage "ERROR: $rtMessage"
        LogMessage "ERROR: Failed to Set Super User Password Policy"
        error "$rtMessage"
        error "Failed to Set Super User Password Policy"
        return 1
    else
        LogMessage "Succeed to Set Super User Password Policy"
    fi
    LogMessage "SetSuperUserPasswordPolicy completed successfully "
    info "SetSuperUserPasswordPolicy completed successfully "
    return 0
}

################################################################################
# Function:    setAllow-zero-length-values
# Description: Set Allow-zero-length-values to true
#              used to permit mail with zero-length values
# Parameters:  None
#
# Returns:
#             0      Succeed
#             1      Failed
################################################################################
function setAllow-zero-length-values() {
    LogMessage "setAllow-zero-length-values request has been received. Processing request ......"

    rtMessage="$($DSCONFIG  set-schema-provider-prop --provider-name Core\ Schema \
    --set allow-zero-length-values-directory-string:true \
    --hostname $LDAP_HOST \
    -p $ADMIN_CONNECTOR_PORT -D "$DM_DN" -w $DM_PWD -X \
    --no-prompt 2>&1 > /dev/null)"
    if [ $? != 0 ]
    then
        LogMessage "ERROR: $rtMessage"
        LogMessage "ERROR: Failed to Set Allow-zero-length-values"
        error "$rtMessage"
        error "Failed to Set Allow-zero-length-values"
        return 1
    else
        LogMessage "Succeed to Set Allow-zero-length-values"
    fi
    LogMessage "setAllow-zero-length-values completed successfully "
    info "setAllow-zero-length-values completed successfully "
    return 0
}

###########################################################################################
# Function: InstallOpendj
# Description: This function installs Opendj software
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################
InstallOpendj()
{

  LogMessage "Install Opendj request has been received. Processing request..."

  LogMessage "Creating an Opendj instance..."


     LogMessage "setup command on opendj $LDAP_HOST ..."
     info "setup command on opendj $LDAP_HOST ..."

     cmd="$OPENDJ_ROOT/setup \
       --acceptLicense \
       -h $LDAP_HOST \
       -Z $COM_INF_LDAP_PORT \
       --adminConnectorPort $ADMIN_CONNECTOR_PORT \
       -D \"$DM_DN\" \
       -w \"$DM_PWD\" \
       --serverId $SERVERID \
       --deploymentId \"$DEPLOYMENT_ID\" \
       --deploymentIdPassword \"$DEPLOYMENT_ID_PASSWORD\" \
       --replicationPort $REPLICATION_PORT \
       --bootstrapReplicationServer "$LDAP_PEER:$REPLICATION_PORT" \
       --profile ds-user-data \
       --set ds-user-data/backendName:userRoot \
       --set ds-user-data/baseDn:$BASE_DN"

  logcmd=$(echo $cmd | sed -e "s/$DM_PWD/********/g" | sed -e "s/$DEPLOYMENT_ID/********/g" | sed -e "s/$DEPLOYMENT_ID_PASSWORD/********/g")
  LogMessage "Running command: $logcmd"

  LogMessage "opendj_java_home=$OPENDJ_JAVA_HOME"
  export OPENDJ_JAVA_HOME

  # OPENDJ_JAVA_HOME for opendj user
  if [ -f /home/opendj/.bashrc ]; then
      BASHRC_OPENDJ_JAVA_HOME=$(grep "^OPENDJ_JAVA_HOME" /home/opendj/.bashrc |cut -d"=" -f2)
      info "OLD OPENDJ_JAVA_HOME for user opendj: $BASHRC_OPENDJ_JAVA_HOME"
      if [ -z $BASHRC_OPENDJ_JAVA_HOME ]; then
          info "Writing OPENDJ_JAVA_HOME for user opendj (install_opendj)"
          echo "OPENDJ_JAVA_HOME=$OPENDJ_JAVA_HOME" >> /home/opendj/.bashrc
          echo "export OPENDJ_JAVA_HOME" >> /home/opendj/.bashrc
      else
          info "Changing OPENDJ_JAVA_HOME for user opendj (install_opendj)"
          sed -i "s|$BASHRC_OPENDJ_JAVA_HOME|$OPENDJ_JAVA_HOME|g" /home/opendj/.bashrc
      fi
  fi

  (su -c "$cmd" - opendj 2>&1) > /var/tmp/setup.out
  rc=$?
  cat /var/tmp/setup.out | tee -a $LOG_FILE
  ${RM_RF} /var/tmp/setup.out
  if [ $rc != 0 ] ; then
     LogMessage "ERROR: Output from setup cmd: "
     error "Output from setup cmd: "
     return 1
  fi




#$DSCONFIG  set-synchronization-provider-prop \
#          --provider-name Multimaster\ Synchronization \
#          --set enabled:false \
#          --offline \
#          --configFile ${OPENDJ_ROOT}/config/config.ldif \
#          --no-prompt
#  if [ $? != 0 ] ; then
#     LogMessage "ERROR: disabling  replication failure"
#     error "replication disabling failure  "
#     return 1
#  fi
#  LogMessage "replication disabled successfully"
#  info "replication disabled successfully"

  $DSCONFIG --offline --no-prompt --batch << END_OF_COMMAND_INPUT
set-password-storage-scheme-prop --scheme-name Argon2 --set enabled:false
END_OF_COMMAND_INPUT
  if [ $? != 0 ] ; then
     LogMessage "ERROR: disabling Argon failure"
     error "Argon2  disabling failure  "
     return 1
  fi
  LogMessage "Argon2 disabled successfully"
  info "Argon2 disabled successfully"
  
  $CHOWN -R opendj:opendj $OPENDJ_ROOT
  if [ $? != 0 ] ; then
    LogMessage "ERROR: Failed to chown directory $OPENDJ_ROOT"
    error "Failed to chown directory $OPENDJ_ROOT"
    return 1
  fi

###############################################################################
# Code to copy of DB and changelogDB to their mounting points                 #
 if [ "${DDC_ON_CLOUD}" != TRUE  ] && [ "${cENM_DEPLOYMENT}" != TRUE ] ; then

    SetupOpenDJDBPartition
    if [ $? != 0 ] ; then
       LogMessage "ERROR: SetupOpenDJDBPartition failed"
       error "SetupOpenDJDBPartition failed"
       return 1
    fi

    SetupOpenDJChangeLogDbPartition
    if [ $? != 0 ] ; then
       LogMessage "ERROR: SetupOpenDJChangeLogDbPartition failed"
       error "SetupOpenDJChangeLogDbPartition failed"
       return 1
    fi

 fi
#                                                                             #
###############################################################################

  StartDS
  if [ $? != 0 ] ; then
     LogMessage "ERROR: First StartDS failed"
     error "First StartDS failed"
     return 1
  fi


  LogMessage "Setup of Opendj completed successfully!!!..."
  info "Setup of Opendj completed successfully!!!..."
  return 0
}

###########################################################################################
# Function: javaCheck
# Description: This function set java version parameters
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################
javaCheck()
{
    JDK11=$(find /usr -name java | grep jdk11 | $SED "s|/bin/java||g")
    if [ -z $JDK11 ]; then
	LogMessage "Java 11 seems not installed!"
        info "Java 11 seems not installed!"
        return 1
    fi
    LATEST=$(readlink -f /usr/java/latest | grep jdk11)
    if [ -z $LATEST ]; then
        OPENDJ_JAVA_HOME=$JDK11
    else
        if [ $JDK11 == $LATEST ]; then
            OPENDJ_JAVA_HOME="/usr/java/latest"
        else
	    OPENDJ_JAVA_HOME=$JDK11
	fi
    fi
    JAVA_VERSION=$($JDK11/bin/java -version 2>&1 | $AWK -F '"' '/version/ {print $2}')
    JAVA_MAJOR_VERSION=$(echo $JAVA_VERSION | $CUT -d "." -f 1 )
    JAVA_UPDATE_VERSION=$(echo $JAVA_VERSION | $CUT -d "." -f 3 )

    LogMessage "OPENDJ_JAVA_HOME= $OPENDJ_JAVA_HOME"
    info "OPENDJ_JAVA_HOME= $OPENDJ_JAVA_HOME"
    LogMessage "JAVA_VERSION: $JAVA_VERSION"
    info "JAVA_VERSION: $JAVA_VERSION"
    LogMessage "JAVA_MAJOR_VERSION: $JAVA_MAJOR_VERSION"
    info "JAVA_MAJOR_VERSION: $JAVA_MAJOR_VERSION"
    LogMessage "JAVA_UPDATE_VERSION: $JAVA_UPDATE_VERSION"
    info "JAVA_UPDATE_VERSION: $JAVA_UPDATE_VERSION"

    return 0
}

###########################################################################################
# Function: SetJVMArgsOpendj
# Description: This function set JVM memory
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################
SetJVMArgsOpendj()
{
    LogMessage "Set JVM memory. Processing request..."

    # Copy the original ForgeRock java.properties
    $CP -pf $OPENDJ_ROOT/template/config/java.properties $OPENDJ_ROOT/config/java.properties
    if [ $? != 0 ] ; then
        LogMessage "WARNING: Failed to copy java.properties template"
        info "WARNING: Failed to copy java.properties template"
        return 1
    fi


   if [ "$cENM_DEPLOYMENT" != TRUE ] ; then
       TIME_ZONE=$(ls -l /etc/localtime | sed "s|zoneinfo/| |g" | rev | cut -d' ' -f1 | rev)
    else
       TIME_ZONE=$TZ
    fi
    LogMessage "INFO: SetJVMArgsOpendj TIME_ZONE: $TIME_ZONE"
    echo "SetJVMArgsOpendj TIME_ZONE: $TIME_ZONE"

    #change JVM arguments min and max amount of memory (-Xms2048m -Xmx2048m) and force UseCompressedOops in java.properties file
    #
    if [[ "$JAVA_MAJOR_VERSION" -gt "11" ]] || [[ "$JAVA_MAJOR_VERSION" -eq "11"  &&  "$JAVA_UPDATE_VERSION" -ge "6" ]]; then

	LogMessage "Found a proper Java version"
        info "Found a proper Java version"

        grep "dsrepl.java-args=-Xms8m -client" $OPENDJ_ROOT/config/java.properties
        if [ $? != 0 ] ; then
            echo "dsrepl.java-args=-Xms8m -client" >> $OPENDJ_ROOT/config/java.properties
        fi

        grep "status.java-args=-Xms8m -client" $OPENDJ_ROOT/config/java.properties
        if [ $? != 0 ] ; then
            echo "status.java-args=-Xms8m -client" >> $OPENDJ_ROOT/config/java.properties
        fi

        grep "status.java-args=-Xms8m -client" $OPENDJ_ROOT/config/java.properties
        if [ $? != 0 ] ; then
            echo "status.java-args=-Xms8m -client" >> $OPENDJ_ROOT/config/java.properties
        fi

        sed -e "s|start-ds.java-args=-server|start-ds.java-args=-Xms2048m -Xmx2048m -Dcom.sun.management.jmxremote -Ds=opendj -server -Duser.timezone=${TIME_ZONE} -XX:+UseCompressedOops -XX:+UseConcMarkSweepGC -XX:MaxTenuringThreshold=1 -XX:+DisableExplicitGC -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=$HPROF_LOG -Xlog:gc=debug:file=$OPENDJ_ROOT/logs/opendj-gc.log:time,uptime,level,tags:filecount=5,filesize=10m |" \
            -e "s/^dsrepl.java-args=-Xms8m -client/dsrepl.java-args=-Xms8m -client -Dcom.sun.jndi.ldap.object.disableEndpointIdentification=true/" \
            -e "s/^status.java-args=-Xms8m -client/status.java-args=-Xms8m -client -Dcom.sun.jndi.ldap.object.disableEndpointIdentification=true/" \
            -e "s:^default.java-home=.*:default.java-home=${OPENDJ_JAVA_HOME}:" \
            -e "s/import-ldif.offline.java-args=-server/import-ldif.offline.java-args=-server -XX:+UseCompressedOops/" \
            -e "s/rebuild-index.offline.java-args=-server/rebuild-index.offline.java-args=-server -XX:+UseCompressedOops/" \
            $OPENDJ_ROOT/config/java.properties > $OPENDJ_ROOT/config/java.properties_new
    else
	sed -e "s|start-ds.java-args=-server|start-ds.java-args=-Xms2048m -Xmx2048m -Dcom.sun.management.jmxremote -Ds=opendj -server -Duser.timezone=${TIME_ZONE} -XX:+UseCompressedOops -XX:+UseConcMarkSweepGC -XX:MaxTenuringThreshold=1 -XX:+DisableExplicitGC -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=$HPROF_LOG -Xlog:gc=debug:file=$OPENDJ_ROOT/logs/opendj-gc.log:time,uptime,level,tags:filecount=5,filesize=10m |" \
            -e "s:^default.java-home=.*:default.java-home=${OPENDJ_JAVA_HOME}:" \
            -e "s/import-ldif.offline.java-args=-server/import-ldif.offline.java-args=-server -XX:+UseCompressedOops/" \
            -e "s/rebuild-index.offline.java-args=-server/rebuild-index.offline.java-args=-server -XX:+UseCompressedOops/" \
            $OPENDJ_ROOT/config/java.properties > $OPENDJ_ROOT/config/java.properties_new
    fi

    if [ $? != 0 ] ; then
        LogMessage "WARNING: Failed to change JVM arguments"
        info "WARNING: Failed to change JVM arguments"
        return 1
    fi

    mv -f $OPENDJ_ROOT/config/java.properties_new $OPENDJ_ROOT/config/java.properties
    if [ $? != 0 ] ; then
        LogMessage "WARNING: Failed to move java.properties file"
        info "WARNING: Failed to move java.properties file"
        return 1
    fi

    $CHMOD 644 $OPENDJ_ROOT/config/java.properties
    if [ $? != 0 ] ; then
        LogMessage "WARNING: Failed to chmod java.properties"
        info "WARNING: Failed to chmod java.properties"
        return 1
    fi

    $CHOWN opendj:opendj $OPENDJ_ROOT/config/java.properties
    if [ $? != 0 ] ; then
        LogMessage "WARNING: Failed to chown java.properties"
        info "WARNING: Failed to chown java.properties"
        return 1
    fi

    LogMessage "Set of JVM memory completed successfully."
    info "Set of JVM memory completed successfully."
    return 0
}


###########################################################################################
# Function: SetJVMArgsOpendj_upgrade
# Description: This function set JVM memory
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################
SetJVMArgsOpendj_upgrade()
{
    LogMessage "Set JVM memory. Processing request for upgrade ..."

    # Copy the original ForgeRock java.properties
    $CP -pf $OPENDJ_ROOT/template/config/java.properties $OPENDJ_ROOT/config/java.properties
    if [ $? != 0 ] ; then
        LogMessage "WARNING: Failed to copy java.properties template"
        info "WARNING: Failed to copy java.properties template"
        return 1
    fi

    #change JVM arguments min and max amount of memory (-Xms2048m -Xmx2048m) and force UseCompressedOops in java.properties file
    #

    if [ "$cENM_DEPLOYMENT" != TRUE ] ; then
       TIME_ZONE=$(timedatectl | grep -i zone|awk '{ print $3 }')
    else
       TIME_ZONE=$TZ
    fi

    if [[ "$JAVA_MAJOR_VERSION" -gt "11" ]] || [[ "$JAVA_MAJOR_VERSION" -eq "11"  &&  "$JAVA_UPDATE_VERSION" -ge "6" ]]; then

	LogMessage "Found a proper Java version"
        info "Found a proper Java version"

        grep "dsrepl.java-args=-Xms8m -client" $OPENDJ_ROOT/config/java.properties
        if [ $? != 0 ] ; then
            echo "dsrepl.java-args=-Xms8m -client" >> $OPENDJ_ROOT/config/java.properties
        fi

        grep "status.java-args=-Xms8m -client" $OPENDJ_ROOT/config/java.properties
        if [ $? != 0 ] ; then
            echo "status.java-args=-Xms8m -client" >> $OPENDJ_ROOT/config/java.properties
        fi

        sed -e "s|start-ds.java-args=-server|start-ds.java-args=-Xms2048m -Xmx2048m -Duser.timezone=${TIME_ZONE} -Dcom.sun.management.jmxremote -Ds=opendj -server -XX:+UseCompressedOops -XX:+UseConcMarkSweepGC -XX:MaxTenuringThreshold=1 -XX:+DisableExplicitGC -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=$HPROF_LOG -Xlog:gc=debug:file=$OPENDJ_ROOT/logs/opendj-gc.log:time,uptime,level,tags:filecount=5,filesize=10m |" \
            -e "s/^dsrepl.java-args=-Xms8m -client/dsrepl.java-args=-Xms8m -client -Dcom.sun.jndi.ldap.object.disableEndpointIdentification=true/" \
            -e "s/^status.java-args=-Xms8m -client/status.java-args=-Xms8m -client -Dcom.sun.jndi.ldap.object.disableEndpointIdentification=true/" \
            -e "s:^default.java-home=.*:default.java-home=${OPENDJ_JAVA_HOME}:" \
            -e "s/import-ldif.offline.java-args=-server/import-ldif.offline.java-args=-server -XX:+UseCompressedOops/" \
            -e "s/rebuild-index.offline.java-args=-server/rebuild-index.offline.java-args=-server -XX:+UseCompressedOops/" \
            $OPENDJ_ROOT/config/java.properties > $OPENDJ_ROOT/config/java.properties_new
    else
        sed -e "s|start-ds.java-args=-Xms[0-9]*m -Xmx[0-9]*m -server|start-ds.java-args=-Xms2048m -Xmx2048m -Duser.timezone=${TIME_ZONE} -Dcom.sun.management.jmxremote -Ds=opendj -server -XX:+UseCompressedOops -XX:+UseConcMarkSweepGC -XX:MaxTenuringThreshold=1 -XX:+DisableExplicitGC -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=$HPROF_LOG -Xlog:gc=debug:file=$OPENDJ_ROOT/logs/opendj-gc.log:time,uptime,level,tags:filecount=5,filesize=10m |" \
            -e "s:^default.java-home=.*:default.java-home=${OPENDJ_JAVA_HOME}:" \
            -e "s/import-ldif.offline.java-args=-server/import-ldif.offline.java-args=-server -XX:+UseCompressedOops/" \
            -e "s/rebuild-index.offline.java-args=-server/rebuild-index.offline.java-args=-server -XX:+UseCompressedOops/" \
            $OPENDJ_ROOT/config/java.properties > $OPENDJ_ROOT/config/java.properties_new
    fi

    if [ $? != 0 ] ; then
        LogMessage "WARNING: Failed to change JVM arguments"
        info "WARNING: Failed to change JVM arguments"
        return 1
    fi

    mv -f $OPENDJ_ROOT/config/java.properties_new $OPENDJ_ROOT/config/java.properties
    if [ $? != 0 ] ; then
        LogMessage "WARNING: Failed to move java.properties file"
        info "WARNING: Failed to move java.properties file"
        return 1
    fi

    $CHMOD 644 $OPENDJ_ROOT/config/java.properties
    if [ $? != 0 ] ; then
        LogMessage "WARNING: Failed to chmod java.properties template"
        info "WARNING: Failed to chmod java.properties"
        return 1
    fi

    $CHOWN opendj:opendj $OPENDJ_ROOT/config/java.properties
    if [ $? != 0 ] ; then
        LogMessage "WARNING: Failed to chown java.properties template"
        info "WARNING: Failed to chown java.properties"
        return 1
    fi

    LogMessage "Set of JVM memory for upgrade completed successfully."
    info "Set of JVM memory for upgrade completed successfully."
    return 0
}

###########################################################################################
# Function: SetupOpenDJLogging
# Description: This function tells OpenDJ where to put logs, i.e. /var/ericsson/log/opendj
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################
SetupOpenDJLogging()
{
  LogMessage "INFO: SetupOpenDJLogging request has been received...... Processing request"

  # OpenDJ still puts server.out and server.pid here so redirect via symlink
  #
  mkdir -p /var/ericsson/log/opendj/server
  if [ $? != 0 ] ; then
    LogMessage "ERROR: Failed to create directory /var/ericsson/log/opendj/server"
    error "Failed to create directory /var/ericsson/log/opendj/server"
    return 1
  fi

  # don't fail the install if we can't copy these logs
  cp $OPENDJ_ROOT/logs/* /var/ericsson/log/opendj/server
  if [ $? != 0 ] ; then
    LogMessage "WARNING: Failed to copy logs to /var/ericsson/log/opendj/server"
    info "WARNING: Failed to copy logs to /var/ericsson/log/opendj/server"
  fi

  $CHOWN -R opendj:opendj /var/ericsson/log/opendj/server
  if [ $? != 0 ] ; then
    LogMessage "ERROR: Failed to chown directory /var/ericsson/log/opendj/server"
    error "Failed to chown directory /var/ericsson/log/opendj/server"
    return 1
  fi

  ${RM_RF} $OPENDJ_ROOT/logs
  if [ $? != 0 ] ; then
    LogMessage "ERROR: Failed to remove directory $OPENDJ_ROOT/logs"
    error "Failed to remove directory $OPENDJ_ROOT/logs"
    return 1
  fi

  ln -s /var/ericsson/log/opendj/server $OPENDJ_ROOT/logs
  if [ $? != 0 ] ; then
    LogMessage "ERROR: Failed to create symlink $OPENDJ_ROOT/logs"
    error "Failed to create symlink $OPENDJ_ROOT/logs"
    return 1
  fi

  $CHOWN -h opendj:opendj $OPENDJ_ROOT/logs
  if [ $? != 0 ] ; then
    LogMessage "ERROR: Failed to chown symlink $OPENDJ_ROOT/logs"
    error "Failed to chown symlink $OPENDJ_ROOT/logs"
    return 1
  fi

  LogMessage "INFO: SetupOpenDJLogging completed successfully"
  info "SetupOpenDJLogging completed successfully"
  return 0
}

###########################################################################################
# Function: SetupOpenDJDBPartition
# Description: This function move Opendj DB to a new partition $DBPATH
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################
SetupOpenDJDBPartition()
{
  LogMessage "INFO: SetupOpenDJDBPartition request has been received...... Processing request"

  if [ -d $DBPATH ] ; then
    LogMessage "INFO: SetupOpenDJDBPartition partition $DBPATH already present"
    info "SetupOpenDJDBPartition partition $DBPATH already present"
    return 0
  fi

  mkdir -p $DBPATH
  if [ $? != 0 ] ; then
    LogMessage "ERROR: Failed to create directory $DBPATH"
    error "Failed to create directory $DBPATH"
    return 1
  fi

  # don't fail the install if we can't copy these logs
  cp -R $OPENDJ_ROOT/db/* $DBPATH
  if [ $? != 0 ] ; then
    LogMessage "WARNING: Failed to copy db to $DBPATH"
    info "WARNING: Failed to copy db to $DBPATH"
  fi

  $CHOWN -R opendj:opendj $DBPATH
  if [ $? != 0 ] ; then
    LogMessage "ERROR: Failed to chown directory $DBPATH"
    error "Failed to chown directory $DBPATH"
    return 1
  fi

  ${RM_RF} $OPENDJ_ROOT/db
  if [ $? != 0 ] ; then
    LogMessage "ERROR: Failed to remove directory $OPENDJ_ROOT/db"
    error "Failed to remove directory $OPENDJ_ROOT/db"
    return 1
  fi

  ln -s $DBPATH $OPENDJ_ROOT/db
  if [ $? != 0 ] ; then
    LogMessage "ERROR: Failed to create symlink $OPENDJ_ROOT/db"
    error "Failed to create symlink $OPENDJ_ROOT/db"
    return 1
  fi

  $CHOWN -h opendj:opendj $OPENDJ_ROOT/db
  if [ $? != 0 ] ; then
    LogMessage "ERROR: Failed to chown symlink $OPENDJ_ROOT/db"
    error "Failed to chown symlink $OPENDJ_ROOT/db"
    return 1
  fi

  LogMessage "INFO: SetupOpenDJDBPartition completed successfully"
  info "SetupOpenDJDBPartition completed successfully"
  return 0
}

###########################################################################################
# Function: SetupOpenDJChangeLogDbPartition
# Description: This function move Opendj changelogDb to a new partition $CHANGELOGDBPATH
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################
SetupOpenDJChangeLogDbPartition()
{
  LogMessage "INFO: SetupOpenDJChangeLogDbPartition request has been received...... Processing request"

  if [ -d $CHANGELOGDBPATH ] ; then
    LogMessage "INFO: SetupOpenDJChangeLogDbPartition partition $CHANGELOGDBPATH already present"
    info "SetupOpenDJChangeLogDbPartition partition $CHANGELOGDBPATH already present"
    return 0
  fi

  mkdir -p $CHANGELOGDBPATH
  if [ $? != 0 ] ; then
    LogMessage "ERROR: Failed to create directory $CHANGELOGDBPATH"
    error "Failed to create directory $CHANGELOGDBPATH"
    return 1
  fi

  # don't fail the install if we can't copy these logs
  cp -R $OPENDJ_ROOT/changelogDb/* $CHANGELOGDBPATH
  if [ $? != 0 ] ; then
    LogMessage "WARNING: Failed to copy changelogDb to $CHANGELOGDBPATH"
    info "WARNING: Failed to copy changelogDb to $CHANGELOGDBPATH"
  fi

  $CHOWN -R opendj:opendj $CHANGELOGDBPATH
  if [ $? != 0 ] ; then
    LogMessage "ERROR: Failed to chown directory $CHANGELOGDBPATH"
    error "Failed to chown directory $CHANGELOGDBPATH"
    return 1
  fi

  ${RM_RF} $OPENDJ_ROOT/changelogDb
  if [ $? != 0 ] ; then
    LogMessage "ERROR: Failed to remove directory $OPENDJ_ROOT/changelogDb"
    error "Failed to remove directory $OPENDJ_ROOT/changelogDb"
    return 1
  fi

  ln -s $CHANGELOGDBPATH $OPENDJ_ROOT/changelogDb
  if [ $? != 0 ] ; then
    LogMessage "ERROR: Failed to create symlink $OPENDJ_ROOT/changelogDb"
    error "Failed to create symlink $OPENDJ_ROOT/changelogDb"
    return 1
  fi

  $CHOWN -h opendj:opendj $OPENDJ_ROOT/changelogDb
  if [ $? != 0 ] ; then
    LogMessage "ERROR: Failed to chown symlink $OPENDJ_ROOT/changelogDb"
    error "Failed to chown symlink $OPENDJ_ROOT/changelogDb"
    return 1
  fi

  LogMessage "INFO: SetupOpenDJChangeLogDbPartition completed successfully"
  info "SetupOpenDJChangeLogDbPartition completed successfully"
  return 0
}



###########################################################################################
# Function: RestoreOpendjLogsUpgrade
# Description: This function restores in upgrade opendj logs location
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################

RestoreOpendjLogsUpgrade()
{
  LogMessage "INFO: RestoreOpendjLogsUpgrade request has been received...... Processing request"

  if [ ! -L $OPENDJ_ROOT/logs ] ; then
    LogMessage "INFO: $OPENDJ_ROOT/logs already a directory, skipping"
    info "$OPENDJ_ROOT/logs already a directory, skipping"
    return 0
  fi

  ${RM_RF} -rf $OPENDJ_ROOT/logs
  if [ $? != 0 ] ; then
    LogMessage "ERROR: Failed to remove symlink $OPENDJ_ROOT/logs"
    error "Failed to remove symlink $OPENDJ_ROOT/logs"
    return 1
  fi

  mkdir $OPENDJ_ROOT/logs
  if [ $? != 0 ] ; then
    LogMessage "ERROR: Failed to recreate directory /ericsson/opendj/opendj/logs"
    error "Failed to recreate directory /ericsson/opendj/opendj/logs"
    return 1
  fi

  $CHOWN -h opendj:opendj $OPENDJ_ROOT/logs
  if [ $? != 0 ] ; then
    LogMessage "ERROR: Failed to chown directory $OPENDJ_ROOT/logs"
    error "Failed to chown directory $OPENDJ_ROOT/logs"
    return 1
  fi

  LogMessage "INFO: RestoreOpendjLogsUpgrade completed successfully"
  info "RestoreOpendjLogsUpgrade completed successfully"
  return 0
}



###########################################################################################
# Function: StopOpenDJ
# Description: This function stops the opendj service using service or systemctl
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################
StopOpenDJ()
{
  if [ $(/sbin/pidof systemd) ] ; then
    /bin/systemctl stop opendj
    return $?
  elif [ $(/sbin/pidof init) ] ; then
    /sbin/service opendj stop
    return $?
  else
    echo "Error: Failed to find any services system."
    return $1
  fi
}



###########################################################################################
# Function: ConfigOpendjCertificate
# Description: This function exports Opendj's self signed certificate
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################
ConfigOpendjCertificate()
{
  LogMessage "ConfigOpendjCertificate request has been received. Processing request....."
  KEYSTORE_PWD=`$CAT $OPENDJ_ROOT/config/keystore.pin`

  # create a random password for the keystores
  NEW_KEYSTORE_PWD=`$OPENSSL rand -base64 12`

  # remove the rootCA created by DS from the keystore
  $JAVA_KEYTOOL -delete -alias ca-cert -keystore $KEYSTORE_NAME -storepass $KEYSTORE_PWD 2>&1 | tee -a "${LOG_FILE}"
  if [ $? != 0 ] ; then
    LogMessage "ERROR: Failed to delete the rootCA created by DS from the keystore"
    error "ERROR: Failed to delete the rootCA created by DS from the keystore"
    return 1
  fi

  # delete the DS certificates (signed by the rootCA created by DS) from opendj keystore
  $JAVA_KEYTOOL -delete -alias ssl-key-pair -keystore $KEYSTORE_NAME -storepass $KEYSTORE_PWD 2>&1 | tee -a "${LOG_FILE}"
  if [ $? != 0 ] ; then
    LogMessage "ERROR: Failed to delete the DS certificates (signed by the rootCA created by DS) from opendj keystore"
    error "Failed to delete the DS certificates (signed by the rootCA created by DS) from opendj keystore"
    return 1
  fi

  # import "Ericsson" rootCA into opendj's keystore 
  # (use the alias rootCA already used in version 6.5.5, to be compliant)
  $JAVA_KEYTOOL -import -no-prompt -trustcacerts -alias rootCA -keystore $KEYSTORE_NAME -storetype PKCS12 -storepass $KEYSTORE_PWD -file $ROOTCA_FILE 2>&1 | tee -a "${LOG_FILE}"
  if [ $? != 0 ] ; then
    LogMessage "ERROR: Failed to import Ericsson Root CA into Opendj's keystore"
    error "Failed to import Ericsson Root CA into Opendj's keystore"
    return 1
  fi

  # Create, sign and export Opendj certificates
  # Generate a key
  # The alias was server-cert (version 6.5.5) but now is ssl-key-pair (version 7.3)
  $JAVA_KEYTOOL -genkey -alias ssl-key-pair -validity $KEY_VALIDITY_PERIOD -keyalg "RSA" -keysize 2048 -dname "CN=${LDAP_HOST}" -keystore $KEYSTORE_NAME -keypass "$KEYSTORE_PWD" -storepass "$KEYSTORE_PWD" -storetype PKCS12 2>&1 | tee -a "${LOG_FILE}"
  if [ $? != 0 ] ; then
     LogMessage "ERROR: Failed to generate Opendj keypair "
     error "Failed to generate Opendj keypair "
     return 1
  fi

  # Create a CSR with the key
  # The alias was server-cert (version 6.5.5) but now is ssl-key-pair (version 7.3)
  $JAVA_KEYTOOL -certreq -v -alias ssl-key-pair -keystore $KEYSTORE_NAME -storetype PKCS12 -storepass "$KEYSTORE_PWD" -file "${IDENMGMT_ROOT}/opendj/config/${LDAP_HOST}-ldap-cer.csr" 2>&1 | tee -a "${LOG_FILE}"
  if [ $? != 0 ] ; then
    LogMessage "ERROR: Failed to create a CSR for Opendj's certificate "
    error "Failed to create a CSR for Opendj's certificate "
    return 1
  fi

  # Sign the CSR using the Ericsson Root CA
  $OPENSSL x509 -req -in ${IDENMGMT_ROOT}/opendj/config/${LDAP_HOST}-ldap-cer.csr -CA ${ROOTCA_FILE} -CAkey ${ROOTCA_KEY_FILE} -CAcreateserial -out ${IDENMGMT_ROOT}/opendj/config/${LDAP_HOST}-ldap-cer.pem -days $KEY_VALIDITY_PERIOD -extfile ${IDENMGMT_ROOT}/opendj/config/opendj-ssl-ext-ca.cnf -extensions usr_cert 2>&1 | tee -a "${LOG_FILE}"
  if [ $? != 0 ] ; then
    LogMessage "ERROR: Failed to sign a CSR for Opendj"
    error "Failed to sign a CSR for Opendj"
    return 1
  fi

  # import opendj's certificate into the keystore
  $JAVA_KEYTOOL -import -no-prompt -trustcacerts -alias ssl-key-pair -keystore $KEYSTORE_NAME -storetype PKCS12 -storepass $KEYSTORE_PWD -file ${IDENMGMT_ROOT}/opendj/config/${LDAP_HOST}-ldap-cer.pem 2>&1 | tee -a "${LOG_FILE}"
  if [ $? != 0 ] ; then
    LogMessage "ERROR: Failed to import Opendj's certificate into the keystore"
    error "Failed to import Opendj's certificate into the keystore"
    return 1
  fi

  # remove csr
  ${RM_RF} ${IDENMGMT_ROOT}/opendj/config/${LDAP_HOST}-ldap-cer.csr

  StopDS
  if [ $? != 0 ] ; then
    LogMessage "ERROR: Failed to stop Opendj"
    error "Failed to stop Opendj"
    return 1
  fi

  LogMessage "INFO : change the keystore password"
  info "INFO : change the keystore password"

  $JAVA_KEYTOOL -storepasswd -keystore $KEYSTORE_NAME -new $NEW_KEYSTORE_PWD -storepass $KEYSTORE_PWD 2>&1 | tee -a "${LOG_FILE}"
  if [ $? != 0 ] ; then
    LogMessage "ERROR: Failed to change the store password of a keystore: ${KEYSTORE_NAME}"
    error "Failed to change the store password of a keystore: ${KEYSTORE_NAME}"
    return 1
  fi

    $JAVA_KEYTOOL -keypasswd -keystore $KEYSTORE_NAME -storepass $NEW_KEYSTORE_PWD -alias master-key -new $NEW_KEYSTORE_PWD -keypass $KEYSTORE_PWD 2>&1 | tee -a "${LOG_FILE}"
  if [ $? != 0 ] ; then
    LogMessage "ERROR: Failed to change the key password of  master-key entry: ${KEYSTORE_NAME}"
    error "Failed to change the key password of an entry: ${KEYSTORE_NAME}"
    return 1
  fi

  $JAVA_KEYTOOL -keypasswd -keystore $KEYSTORE_NAME -storepass $NEW_KEYSTORE_PWD -alias ssl-key-pair -new $NEW_KEYSTORE_PWD -keypass $KEYSTORE_PWD 2>&1 | tee -a "${LOG_FILE}"
  if [ $? != 0 ] ; then
    LogMessage "ERROR: Failed to change the key password of ssl-key-pair entry: ${KEYSTORE_NAME}"
    error "Failed to change the key password of an entry: ${KEYSTORE_NAME}"
    return 1
  fi

  echo $NEW_KEYSTORE_PWD > $OPENDJ_ROOT/config/keystore.pin

  StartDS
  if [ $? != 0 ] ; then
    LogMessage "ERROR: Failed to start Opendj"
    error "Failed to start Opendj after certificates configuration"
    return 1
  fi

  $CHOWN -R opendj:opendj $OPENDJ_ROOT
  if [ $? != 0 ] ; then
    LogMessage "ERROR: Failed to chown directory $OPENDJ_ROOT"
    error "Failed to chown directory $OPENDJ_ROOT"
    return 1
  fi

  LogMessage "ConfigOpendjCertificate completed successfully!"
  info "ConfigOpendjCertificate completed successfully!"
  return 0
}

###########################################################################################
# Function: EnableJMX
# Description: This function enables JMX protocol
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################
EnableJMX()
{
   LogMessage "INFO: Checking JMX connection handler presence"
rtMess="$($DSCONFIG get-connection-handler-prop --port $ADMIN_CONNECTOR_PORT \
 --hostname localhost \
 --bindDN "$DM_DN" \
 --bindPassword "$DM_PWD" \
 --handler-name JMX \
 --trustAll --no-prompt )"

if [[ $rtMess != *"Property"* ]]
then
    #install 
    LogMessage "INFO: Creating JMX connection manager"

    rtMess="$($DSCONFIG create-connection-handler \
 --hostname localhost  \
 --port $ADMIN_CONNECTOR_PORT \
 --bindDN "$DM_DN" \
 --bindPassword "$DM_PWD" \
 --handler-name JMX \
 --type jmx \
 --set key-manager-provider:"PKCS12" \
 --set ssl-cert-nickname:ssl-key-pair \
 --set use-ssl:true \
 --set listen-port:1689 \
 --set enabled:true  --trustAll --no-prompt)"

    if [ "$?" == "0" ]
        then
            LogMessage "INFO: JMX connection handler created successfully"
    else 
        LogMessage "ERROR: JMX connector creation failed"
        error "JMX connector creation failed"
        return 1
    fi

fi

  $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt <<EOT | tee -a $LOG_FILE
dn: $DM_DN
changetype: modify
add: ds-privilege-name
ds-privilege-name: jmx-notify
ds-privilege-name: jmx-read
ds-privilege-name: jmx-write
EOT

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ] && [ $rr -ne 20 ] ; then
        LogMessage "ERROR: $rr"
        LogMessage "ERROR: Fail to set read, write and notify privileges "
        error "$rr"
        error "Fail to set read, write and notify privileges "
        return 2
  else
        LogMessage "INFO: Privileges, jmx-notify, jmx-read, and jmx-write assigned as necessary to the user "
        info "Privileges, jmx-notify, jmx-read, and jmx-write assigned as necessary to the user "
  fi

return 0
}

###########################################################################################
# Function: SetupKeyManagerProvider
# Description: This function enable the default key manager provider in upgrade
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################
# key manager provider-name : Default Key Manager --> PKCS12
# trust manager provider-name : Default Trust Manager --> PKCS12
# for both providers : key-store-type:JKS --> key-store-type:PKCS12
SetupKeyManagerProvider()
{

LogMessage "INFO: Check PKCS12 key manager provider if present"

rtMess="$($DSCONFIG get-key-manager-provider-prop --port $ADMIN_CONNECTOR_PORT \
 --hostname localhost \
 --bindDN "$DM_DN" \
 --bindPassword "$DM_PWD" \
 --provider-name "PKCS12" \
 --trustAll --no-prompt )"

if [[ $rtMess != *"Property"* ]]
then

    LogMessage "INFO: Creating and checking PKCS12 key manager provider"

    rtMex="$($DSCONFIG create-key-manager-provider \
 --hostname localhost  \
 --port $ADMIN_CONNECTOR_PORT \
 --bindDN "$DM_DN" \
 --bindPassword "$DM_PWD" \
 --provider-name "PKCS12" \
 --type file-based \
 --set enabled:true --set key-store-file:config/keystore --set key-store-pin:"&{file:config/keystore.pin}" --set key-store-type:PKCS12 \
 --trustAll --no-prompt)"


    rtMex="$($DSCONFIG get-key-manager-provider-prop --port $ADMIN_CONNECTOR_PORT \
 --hostname localhost \
 --bindDN "$DM_DN" \
 --bindPassword "$DM_PWD" \
 --provider-name "PKCS12" \
 --trustAll --no-prompt )"

    if [[ $rtMex == *"Property"* ]]
    then
        LogMessage "INFO: Created PKCS12 key manager provider"
        info "Created PKCS12 key manager provider"
    else
        LogMessage "ERROR: Fail to set PKCS12 key manager provider, error message $rtMess "
        error "Fail to set PKCS12 key manager provider, error message $rtMess "
        return 1
    fi
fi

LogMessage "INFO: PKCS12 Key Manager exists "
info "PKCS12 Key Manager exists, no further actions required "

LogMessage "INFO: Check PKCS12 trust manager provider if present"

rtMess="$($DSCONFIG get-trust-manager-provider-prop --port $ADMIN_CONNECTOR_PORT \
 --hostname localhost \
 --bindDN "$DM_DN" \
 --bindPassword "$DM_PWD" \
 --provider-name "PKCS12" \
 --trustAll --no-prompt )"

if [[ $rtMess == *"Property"* ]]
then
    LogMessage "INFO: PKCS12 Trust Manager already exists, no further actions required "
    info "PKCS12 Trust Manager already exists, no further actions required "
    return 0
fi

LogMessage "INFO: Creating and checking PKCS12 trust manager provider"

rtMess="$($DSCONFIG create-trust-manager-provider \
 --hostname localhost  \
 --port $ADMIN_CONNECTOR_PORT \
 --bindDN "$DM_DN" \
 --bindPassword "$DM_PWD" \
 --provider-name "PKCS12" \
 --type file-based \
 --set enabled:true --set trust-store-file:config/keystore --set trust-store-pin:"&{file:config/keystore.pin}" --set trust-store-type:PKCS12 \
 --trustAll --no-prompt)"


rtMess="$($DSCONFIG get-trust-manager-provider-prop --port $ADMIN_CONNECTOR_PORT \
 --hostname localhost \
 --bindDN "$DM_DN" \
 --bindPassword "$DM_PWD" \
 --provider-name "PKCS12" \
 --trustAll --no-prompt )"

if [[ $rtMess == *"Property"* ]]
then
    LogMessage "INFO: Created PKCS12 trust manager provider"
    info "Created PKCS12 trust manager provider"
    return 0
else
    LogMessage "ERROR: Fail to set PKCS12 trust manager provider, error message $rtMess "
    error "Fail to set PKCS12 trust manager provider, error message $rtMess "
    return 1
fi


LogMessage "INFO: PKCS12 Trust Manager exists "
info "PKCS12 Trust Manager exists, no further actions required "
}

###########################################################################################
# Function: SortDiffLdif
# Description: This function sort diff.ldif entries
# Parameters: None
###########################################################################################
SortDiffLdif(){
LINE_SEP=-
LDIF_FILE=$TMP_FOLDER/diff.ldif
DEBUG_SORT=true

LogMessage "INFO: sorting entries of diff.ldif file"

if [ ! -e $LDIF_FILE ]; then
    exit 1
fi

if [ "$DEBUG_SORT" ]; then
    cp $LDIF_FILE $TMP_FOLDER/diff.ldif.orig
fi

TMP_LDIF=$TMP_FOLDER/diff.tmp
SORT_LDIF=$TMP_FOLDER/diff.sort

# Copy source removing empty lines
grep -v '^$' $LDIF_FILE > $TMP_LDIF

if [[ `tail -1 $TMP_LDIF` != $LINE_SEP ]]; then
    echo $LINE_SEP >> $TMP_LDIF
fi

# Copy first 2 lines if ldif does not begin with add or delete
HEADER=`head -1 $TMP_LDIF`
if [[ ( $HEADER != add* ) && ( $HEADER != delete* ) ]]; then
    head -2 $TMP_LDIF > $SORT_LDIF
fi

grep -E -A 2 "delete: +ldapSyntaxes" $TMP_LDIF | grep -v "\-\-" >> $SORT_LDIF
grep -E -A 2 "delete: +attributeTypes" $TMP_LDIF | grep -v "\-\-" >> $SORT_LDIF
grep -E -A 2 "delete: +objectClasses" $TMP_LDIF | grep -v "\-\-" >> $SORT_LDIF
grep -E -A 2 "add: +ldapSyntaxes" $TMP_LDIF | grep -v "\-\-" >> $SORT_LDIF
grep -E -A 2 "add: +attributeTypes" $TMP_LDIF | grep -v "\-\-" >> $SORT_LDIF
if [[ `tail -1 $SORT_LDIF` != $LINE_SEP* ]]; then
    echo $LINE_SEP >> $SORT_LDIF
fi
grep -E -A 2 "add: +objectClasses" $TMP_LDIF | grep -v "\-\-" >> $SORT_LDIF

# Remove last separator
if [[ `tail -1 $SORT_LDIF` == $LINE_SEP* ]]; then
    sed -i '$ d' $SORT_LDIF
fi

if [ -s $SORT_LDIF ]; then
    diff -E $SORT_LDIF $LDIF_FILE > /dev/null
    if [ "$?" == 0 ]; then
        # No difference in sorted LDIF file
        LogMessage "INFO: diff.ldif does not need sorting"
        ${RM_RF} $SORT_LDIF
    else
        mv $SORT_LDIF $LDIF_FILE
        if [ "$DEBUG_SORT" ]; then
            cp $LDIF_FILE $TMP_FOLDER/diff.ldif.sort
        fi
        LogMessage "INFO: diff.ldif has been sorted"
    fi
else
    ${RM_RF} $SORT_LDIF
fi
${RM_RF}  $TMP_LDIF
}
###########################################################################################
# Function: UpdateSchema
# Description: This function checks and updates customized schema (99-user.ldif) if needed
#              Only adding of new attributes/objectClasses is supported
#              Make sure to add entries to 99-user.ldif ONLY in normalized format
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################
UpdateSchema(){

 LogMessage "INFO: UpdateSchema invoked, processing request .........."
 LogMessage "INFO: Checking the new schema"

$LDIFDIFF -o $TMP_FOLDER/diff.ldif -e modifyTimestamp -e modifiersName -e ds-sync-generation-id -e etag -e ds-sync-state $OPENDJ_SCHEMA_DIR/99-user.ldif $OPENDJ_NEW_SCHEMA_DIR/99-user.ldif | tee -a $LOG_FILE
 rr=${PIPESTATUS[0]}

 if [ $rr = 1 ] ; then
        LogMessage "INFO: New schema differs from current one"
        SortDiffLdif
 elif [ $rr = 0 ] ; then

        ${RM_RF} $TMP_FOLDER/diff.ldif

        LogMessage "INFO: Schema is up-to-date already"
        LogMessage "INFO: UpdateSchema completed successfully"
        info "Schema is up-to-date already"
        info "UpdateSchema completed successfully"
        return 0
 else
        LogMessage "ERROR: Failed to read Opendj custom schema"
        error "Failed to read Opendj custom schema"
        return 1
 fi

 LogMessage "INFO: Update schema with new attributes"


 $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt -f $TMP_FOLDER/diff.ldif | tee -a $LOG_FILE
 rr=${PIPESTATUS[0]}


 if [ $rr = 0 ] ; then
        LogMessage "INFO: Schema is up-to-date now"
 else
        LogMessage "ERROR: Failed to update Opendj custom schema"
        error "Failed to update Opendj custom schema"
        return 1
 fi

 ${RM_RF} $TMP_FOLDER/diff.ldif

 LogMessage "INFO: UpdateSchema completed successfully"
 info "UpdateSchema completed successfully"
 return 0
}

###########################################################################################
# Function: RestartDS
# Description: This function restart DS
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################
RestartDS(){

 LogMessage "INFO: Restarting OpenDJ DS"

 su -c "${STOP_DS} --restart" - opendj
 if [ $? != 0 ] ; then
        LogMessage "ERROR: Failed to restart OpenDJ DS"
        error "Failed to restart OpenDJ DS"
        return 1
 fi

 LogMessage "INFO: OpenDJ DS Restarted"
 info "OpenDJ DS Restarted"
 return 0;
}

###########################################################################################
# Function: StartDS
# Description: This function starts DS
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################
StartDS(){
 LogMessage "INFO: Starting OpenDJ DS"

 su -c "${START_DS}" - opendj
 if [ $? != 0 ] ; then
        LogMessage "ERROR: Failed to start OpenDJ DS"
        error "Failed to start OpenDJ DS"
        return 1
 fi

 # Start code for checking start-ds
 
 opendj_pid_file_path=${INSTALL_ROOT}/logs/server.pid

 OPENDJ_REAL_PID=`ps aux|grep 'start-ds'|grep 'org.opends.server.core.DirectoryServer'|tr -s ' '|cut -d ' ' -f 2`
 if [ -n "$OPENDJ_REAL_PID" ]; then
    # OpenDJ process is running
    OPENDJ_FILE_PID=`cat $opendj_pid_file_path 2> /dev/null`
    if [ -z "$OPENDJ_FILE_PID" ]; then
         #server.pid file is empty
         info "INFO: start-ds exit with 0 but file server.pid is empty. No PID in server.pid file. Process OpenDJ PID = ($OPENDJ_REAL_PID)."
         echo $OPENDJ_REAL_PID > $opendj_pid_file_path && chown opendj:opendj $opendj_pid_file_path
    else
         info "INFO: checked opendjStart finished with SUCCESS"
    fi
 else
    # OpenDJ process is not running
    info "INFO: OpenDJ process ID is not yet present..."
    #return 1
 fi
                                                                                                                                     
 # Stop code for checking start-ds


 LogMessage "INFO: OpenDJ DS Started"
 info "OpenDJ DS Started"
 return 0;
}

###########################################################################################
# Function: StopDS
# Description: This function stops DS
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################
StopDS(){
 LogMessage "INFO: Stopping OpenDJ DS"

 su -c "${STOP_DS}" - opendj
 if [ $? != 0 ] ; then
        OPENDJ_REAL_PID=`ps aux|grep 'start-ds'|grep 'org.opends.server.core.DirectoryServer'|tr -s ' '|cut -d ' ' -f 2`
        if [ -z "$OPENDJ_REAL_PID" ] ; then
            LogMessage "INFO : Already stopped  OpenDJ DS - stop-ds returns 0"
              if [ -f "${OPENDJ_ROOT}/logs/server.pid" ] ; then
                        $RM "${OPENDJ_ROOT}/logs/server.pid"
                        LogMessage "INFO : Removed server.pid"
              fi
            return 0
        fi

        LogMessage "ERROR: Failed to stop OpenDJ DS"
        error "Failed to stop OpenDJ DS"
        return 1
 fi

 LogMessage "INFO: OpenDJ DS Stopped"
 info "OpenDJ DS Stopped"
 return 0
}

###########################################################################################
# Function: StopDS_with_retry
# Description: This function stops DS and wait if the command has not been executed correctly
#              (used only in upgrade)
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################
StopDsWithRetry(){

  retryCounter=1
  
  while [ $retryCounter -le $UPGRADE_MAX_COUNTER ] ; do
	LogMessage "Try OpenDJ stop n $retryCounter"
	StopDS
	if [ ${?} -ne 0 ] ; then
          retryCounter=$((retryCounter+1))
          # failed: wait and retry
	  if [ $retryCounter -le $UPGRADE_MAX_COUNTER ] ; then
          	LogMessage "INFO: Wait and retry"
	  	sleep $UPGRADE_TIMEOUT
	  fi
	else
	  # executed
          retryCounter=100
	fi
  done
	
  if [ $retryCounter -ne 100 ] ; then
    LogMessage "ERROR: max retry OpenDJ stop reached"
    error "max retry OpenDJ stop reached"
    return 1
  fi
  return 0
}

###########################################################################################
# Function: RemovePasswordExpirationFromProxyUsers
# Description: This function allows Proxy User password to never expire
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################
RemovePasswordExpirationFromProxyUsers(){

  LogMessage "INFO: RemovePasswordExpirationFromProxyUsers request has been received. Processing request..."

  $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt <<EOT | tee -a $LOG_FILE
dn: cn=Proxy Agent Password Never Expire Subentry Policy,$BASE_DN
changetype: add
objectClass: top
objectClass: subentry
objectClass: pwdPolicy
cn: Proxy Agent Password Never Expire Subentry Policy
pwdMaxAge: 0
pwdAttribute: userPassword
subtreeSpecification: {base "ou=proxyagent,ou=com"}
EOT

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ] && [ $rr -ne 68 ] ; then
     LogMessage "ERROR: Failed to remove password expiration for ou=proxyagent,ou=com and the error code from DS is [$rr]"
     error "Failed to remove password expiration for ou=proxyagent,ou=com and the error code from DS is [$rr]"
     return 1
  fi

  if [ $rr -eq 68 ]; then
      LogMessage "INFO: Policy for ou=proxyagent,ou=com already configured"
  else
      LogMessage "INFO: Remove password expiration for ou=proxyagent,ou=com completed successfully"
  fi

  $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt <<EOT | tee -a $LOG_FILE
dn: cn=Proxy Account Password Never Expire Subentry Policy,$BASE_DN
changetype: add
objectClass: top
objectClass: subentry
objectClass: pwdPolicy
cn: Proxy Account Password Never Expire Subentry Policy
pwdMaxAge: 0
pwdAttribute: userPassword
subtreeSpecification: {base "ou=Profiles"}
EOT

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ] && [ $rr -ne 68 ] ; then
     LogMessage "ERROR: Failed to remove password expiration for ou=Profiles and the error code from DS is [$rr]"
     error "Failed to remove password expiration for ou=Profiles and the error code from DS is [$rr]"
     return 1
  fi

  if [ $rr -eq 68 ]; then
      LogMessage "INFO: Policy for ou=Profiles already configured"
      info "Policy for ou=Profiles already configured"
  else
      LogMessage "INFO: Remove password expiration for ou=Profiles completed successfully"
      info "Remove password expiration for ou=Profiles completed successfully"
  fi
  return 0
}

###########################################################################################
# Function: RemovePasswordExpirationFromM2MUsers
# Description: This function allows M2MUsers password to never expire
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################
RemovePasswordExpirationFromM2MUsers(){

  LogMessage "INFO: RemovePasswordExpirationFromM2MUsers request has been received. Processing request..."

  $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt <<EOT | tee -a $LOG_FILE
dn: cn=M2MUsers Account Password Never Expire Subentry Policy,$BASE_DN
changetype: add
objectClass: top
objectClass: subentry
objectClass: pwdPolicy
cn: M2MUsers Account Password Never Expire Subentry Policy
pwdMaxAge: 0
pwdAttribute: userPassword
subtreeSpecification: {base "ou=M2MUsers"}
EOT

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ] && [ $rr -ne 68 ] ; then
     LogMessage "ERROR: Failed to RemovePasswordExpirationFromM2MUsers and the error code from DS is [$rr]"
     error "Failed to RemovePasswordExpirationFromM2MUsers and the error code from DS is [$rr]"
     return 1
  fi

  if [ $rr -eq 68 ]; then
      LogMessage "INFO: Policy already configured"
      info "Policy already configured"
  else
      LogMessage "INFO: RemovePasswordExpirationFromM2MUsers completed successfully"
      info "RemovePasswordExpirationFromM2MUsers completed successfully"
  fi
  return 0
}

###########################################################################################################
# Function: ModifyPwdMaxFailureForM2MUsers
# Description: This function modifies pwdMaxFailure attribute for M2MUsers so that password is never locked 
# Parameters: None
# Return:  0 everything ok, 1 fail
###########################################################################################################
ModifyPwdMaxFailureForM2MUsers(){

  LogMessage "INFO: ModifyPwdMaxFailureForM2MUsers request has been received. Processing request..."

  $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt <<EOT | tee -a $LOG_FILE
dn: cn=M2MUsers Account Password Never Expire Subentry Policy,$BASE_DN
changetype: modify
add: pwdMaxFailure
pwdMaxFailure: 0
EOT

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ] && [ $rr -ne 20 ] ; then
     LogMessage "ERROR: Failed to ModifyPwdMaxFailureForM2MUsers and the error code from DS is [$rr]"
     error "Failed to ModifyPwdMaxFailureForM2MUsers and the error code from DS is [$rr]"
     return 1
  fi

  if [ $rr -eq 20 ]; then
      LogMessage "INFO: pwdMaxFailure attribute already configured for M2M Users"
      info "pwdMaxFailure attribute already configured for M2M Users"
  else
      LogMessage "INFO: ModifyPwdMaxFailureForM2MUsers completed successfully"
      info "ModifyPwdMaxFailureForM2MUsers completed successfully"
  fi
  return 0
}

#############################################################################################################
# Function: ModifyPwdMaxFailureForProxyUsers
# Description: This function modifies pwdMaxFailure attribute for ProxyUsers so that password is never locked 
# Parameters: None
# Return:  0 everything ok, 1 fail
#############################################################################################################
ModifyPwdMaxFailureForProxyUsers(){

  LogMessage "INFO: ModifyPwdMaxFailureForProxyUsers request has been received. Processing request..."

  $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt <<EOT | tee -a $LOG_FILE
dn: cn=Proxy Agent Password Never Expire Subentry Policy,$BASE_DN
changetype: modify
add: pwdMaxFailure
pwdMaxFailure: 0
EOT

  rr=${PIPESTATUS[0]}
  if [ $rr -ne 0 ] && [ $rr -ne 20 ] ; then
     LogMessage "ERROR: Failed to ModifyPwdMaxFailureForProxyUsers and the error code from DS is [$rr]"
     error "Failed to ModifyPwdMaxFailureForProxyUsers and the error code from DS is [$rr]"
     return 1
  fi

  if [ $rr -eq 20 ]; then
      LogMessage "INFO: pwdMaxFailure attribute already configured for ProxyUsers"
      info "pwdMaxFailure attribute already configured for ProxyUsers"
  else
      LogMessage "INFO: ModifyPwdMaxFailureForProxyUsers completed successfully"
      info "ModifyPwdMaxFailureForProxyUsers completed successfully"
  fi
  return 0
}

###########################################################################################
# Function: ModifyPwdChangedTimeAttributeType
# Description: This function makes pwdChangedTime attribute type user modifiable
# Parameters: None
# Return:  0 everything ok, 1 fail, 3 for vENM in case of rollback. See TORF-726754
###########################################################################################
ModifyPwdChangedTimeAttributeType(){

 LogMessage "INFO: Modify pwdChangedTime attribute type"

 $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt << EOT | tee -a $LOG_FILE
dn: cn=schema
changetype: modify
delete: attributeTypes
attributeTypes: ( 1.3.6.1.4.1.42.2.27.8.1.16 NAME 'pwdChangedTime' DESC 'The time the password was last changed' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation X-ORIGIN 'draft-behera-ldap-password-policy' )
-
add: attributeTypes
attributeTypes: ( 1.3.6.1.4.1.42.2.27.8.1.16 NAME 'pwdChangedTime' DESC 'The time the password was last changed' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE USAGE directoryOperation X-ORIGIN 'draft-behera-ldap-password-policy' )
EOT

 rr=${PIPESTATUS[0]}
 if [ "${DDC_ON_CLOUD}" == TRUE ] && [ $rr -eq 53 ] ; then
      LogMessage "WARNING: ModifyPwdChangedTimeAttributeType. The response is [$rr]"
      info "WARNING: .ModifyPwdChangedTimeAttributeType The response is [$rr]"
      return 3
 fi        
 if [ $rr = 0 ] || [ $rr = 20 ]; then
    LogMessage "INFO: pwdChangedTime attribute type modified successfully"
 elif [ $rr = 16 ]; then
    LogMessage "INFO: pwdChangedTime attribute has been already modified"
 else
    LogMessage "ERROR: Failed to modify pwdChangedTime attribute type"
    error "Failed to modify pwdChangedTime attribute type"
    return 1
 fi

 LogMessage "INFO: ModifyPwdChangedTimeAttributeType completed successfully"
 info "ModifyPwdChangedTimeAttributeType completed successfully"
 return 0
}

################################################################################
# Function:    AdjustThreadsParametersForSynchronization
# Description: Adjust threads parameters to avoid overfill heap space
# Parameters:  None
#
# Returns:
#             0      Succeed
#             1      Failed
################################################################################
AdjustThreadsParametersForSynchronization() {
    LogMessage "INFO: AdjustThreadsParametersForSynchronization request has been received. Processing request ......"

    rtMessage="$($DSCONFIG set-work-queue-prop --port $ADMIN_CONNECTOR_PORT \
                                         --hostname localhost \
                                         --bindDN "$DM_DN" \
                                         --bindPassword "$DM_PWD" \
                                         --set num-worker-threads:8 \
                                         -X -n 2>&1 > /dev/null)"
    if [ $? != 0 ]
    then
        LogMessage "ERROR: $rtMessage"
        LogMessage "ERROR: Failed to Adjust Threads Parameters For Synchronization (worker-threads)"
        error "$rtMessage"
        error "Failed to Adjust Threads Parameters For Synchronization (worker-threads)"
        return 1
    else
        LogMessage "INFO: Succeed to Adjust Threads Parameters For Synchronization (worker-threads)"
    fi

    rtMessage="$($DSCONFIG set-synchronization-provider-prop --port $ADMIN_CONNECTOR_PORT \
                                         --hostname localhost \
                                         --bindDN "$DM_DN" \
                                         --bindPassword "$DM_PWD" \
                                         --provider-name Multimaster\ Synchronization \
                                         --set num-update-replay-threads:8 \
                                         -X -n 2>&1 > /dev/null)"
    if [ $? != 0 ]
    then
        LogMessage "ERROR: $rtMessage"
        LogMessage "ERROR: Failed to Adjust Threads Parameters For Synchronization (update-reply-threads)"
        error "$rtMessage"
        error "Failed to Adjust Threads Parameters For Synchronization (update-reply-threads)"
        return 1
    else
        LogMessage "INFO: Succeed to Adjust Threads Parameters For Synchronization (update-reply-threads)"
    fi
    LogMessage "INFO: AdjustThreadsParametersForSynchronization completed successfully "
    info "AdjustThreadsParametersForSynchronization completed successfully "
    return 0
}

################################################################################
# Function:    RemovePasswordExpirationForEnmUser
# Description: This function creates subentry password policy for specified user
#              with disabled password ageing
# Parameters:  $1 - uid of enmuser for whom password policy is created and applied
#
# Returns:
#             0      Succeed
#             1      Failed
################################################################################
RemovePasswordExpirationForEnmUser() {
    LogMessage "INFO: RemovePasswordExpirationForEnmUser with parameter $1 request has been received. Processing request..."

    $LDAPMODIFY -h localhost -p $COM_INF_LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w "$DM_PWD" --no-prompt <<EOT | tee -a $LOG_FILE
dn: cn=$1 Account Password Never Expire Subentry Policy,$BASE_DN
changetype: add
objectClass: top
objectClass: subentry
objectClass: pwdPolicy
cn: $1 Account Password Never Expire Subentry Policy
pwdMaxAge: 0
pwdAttribute: userPassword
subtreeSpecification: {base "uid=$1,ou=People"}
EOT

    rr=${PIPESTATUS[0]}
    if [ $rr -ne 0 ] && [ $rr -ne 68 ] ; then
        LogMessage "ERROR: Failed to RemovePasswordExpirationForEnmUser and the error code from DS is [$rr]"
        error "Failed to RemovePasswordExpirationForEnmUser and the error code from DS is [$rr]"
        return 1
    fi

    if [ $rr -eq 68 ]; then
        LogMessage "INFO: Policy for user $1 already configured"
        info "Policy for user $1 already configured"
    else
        LogMessage "INFO: RemovePasswordExpirationForEnmUser completed successfully"
        info "RemovePasswordExpirationForEnmUser completed successfully"
    fi
    return 0
}

#######################################################################################
# Function:   UpdateToJeExport 
# Description: This function exports backend before upgrade to change type from pdb to je if necessary 
# Parameters:  no parameter 
#
# Returns:
#             0      Succeed
#             1      Failed            
######################################################################################
#
#UpdateToJeExport() {
#
#    LogMessage "INFO: backend update to je EXPORT procedure, checking if version is different"
#
#    if [ "$OLD_OPENDJ_VERSION" == $NEW_OPENDJ_VERSION ]; then
#        LogMessage "INFO: opendj version is the same, $OLD_OPENDJ_VERSION , returning"
#        info "opendj version is the same, $OLD_OPENDJ_VERSION , returning"
#        return 0
#    fi
#
#    LogMessage "INFO: checking if opendj is already to version 6.5.0 where pdb is not supported"
#
#    if [ "$OLD_OPENDJ_VERSION" == "6.5.0" ]; then
#        LogMessage "INFO: opendj version is already $OLD_OPENDJ_VERSION , returning"
#        info "opendj version is already $OLD_OPENDJ_VERSION , returning"
#        return 0
#   fi
#
#    if [ "$OLD_OPENDJ_VERSION" == "6.5.5" ]; then
#        LogMessage "INFO: opendj version is already $OLD_OPENDJ_VERSION , returning"
#        info "opendj version is already $OLD_OPENDJ_VERSION , returning"
#        return 0
#    fi
#
#    if [ "$OLD_OPENDJ_VERSION" == "7.3.3" ]; then
#        LogMessage "INFO: opendj version is already $OLD_OPENDJ_VERSION , returning"
#        info "opendj version is already $OLD_OPENDJ_VERSION , returning"
#        return 0
#    fi
#
#    LogMessage "INFO: exporting backend ldif file"
#    su opendj -c "$EXPORT_LDIF --backendID userRoot --ldifFile $TMP_FOLDER/userTmpRoot.ldif --includeBranch '$BASE_DN' " 2>&1
#
#    rr=${PIPESTATUS[0]}
#    if [ $rr -ne 0 ] ; then
#        LogMessage "ERROR: exporting backend failed"
#        error "exporting backend failed"
#        return 1
#    fi
#
#    LogMessage "INFO: Export successfull"
#}

###################################################################################################
# Function:   UpdateToJeImport
# Description: This function import backend after upgrade to automatically change type from pdb to je if necessary 
# Parameters:  no parameter 
#
# Returns:
#             0      Succeed
#             1      Failed            
###################################################################################################
#
#UpdateToJeImport() {
#
#    LogMessage "INFO: backend update to je IMPORT, checking if opendj is already to version 6.5.0 where pdb is not supported"
#
#    if [ "$OLD_OPENDJ_VERSION" == "6.5.0" ]; then
#        LogMessage "INFO: opendj version is already $OLD_OPENDJ_VERSION , returning"
#        info "opendj version is already $OLD_OPENDJ_VERSION , returning"
#        return 0
#    fi
#
#    if [ "$OLD_OPENDJ_VERSION" == "6.5.5" ]; then
#        LogMessage "INFO: opendj version is already $OLD_OPENDJ_VERSION , returning"
#        info "opendj version is already $OLD_OPENDJ_VERSION , returning"
#        return 0
#    fi
#
#    if [ "$OLD_OPENDJ_VERSION" == "7.3.3" ]; then
#        LogMessage "INFO: opendj version is already $OLD_OPENDJ_VERSION , returning"
#        info "opendj version is already $OLD_OPENDJ_VERSION , returning"
#        return 0
#    fi
#
#    LogMessage "INFO: importing backend ldif file"
#    su opendj -c "$IMPORT_LDIF --offline --backendId userRoot --ldifFile $TMP_FOLDER/userTmpRoot.ldif --includeBranch '$BASE_DN' --no-prompt " 2>&1
#    rr=${PIPESTATUS[0]}
#    if [ $rr -ne 0 ] ; then
#        LogMessage "ERROR: Import LDIF during backend update failed"
#        error "Import LDIF during backend update failed"
#        return 1
#    fi
#    ${RM_RF} $TMP_FOLDER/userTmpRoot.ldif
#
#    LogMessage "INFO: Import successfull"
#
#}

################################################################################
# Function:   CleanInstall 
# Description: This function remove (only for Cloud) opendj installation if one of the steps fails 
# Parameters:  no parameter 
#
# Returns:
#             0      Succeed
# I expect that this method will never fail. The run command is an rm -rf            
################################################################################
CleanInstall() {

SAVELOGSDIR=/ericsson/enm/dumps/opendjsavelogs

#RM_RF /ericsson/opendj/opendj
#RM_RF lock for installing openDJ
#RM_RF lock for running replication
if [[ "${DDC_ON_CLOUD}" == TRUE ]]; then
          StopOpenDJ
             if [ $? != 0 ] ; then
                 LogMessage "ERROR: Failed to stop Opendj"
                 error "Failed to stop Opendj for Cloud removal"
                 return 1
             else
                 if [ -d "$SAVELOGSDIR" ]; then
                    # remove all files except server.out
                    ${RM_RF} $SAVELOGSDIR/*.*
                 else
                    ${MKDIR} $SAVELOGSDIR
                 fi
                 LogMessage "ERROR: Save openDJ log directory on Cloud before removing installation directory"
                 ${CP} -rf /ericsson/opendj/opendj/logs  ${SAVELOGSDIR}/.

                 LogMessage "ERROR: Remove openDJ installation directory on Cloud"
                 error "Remove openDJ installation directory on Cloud"
                 ${RM_RF} ${OPENDJ_ROOT}/
                 LogMessage "ERROR: Remove openDJ replication lock on Cloud"
                 error "Remove openDJ replication lock on Cloud"
                 ${RM_RF} ${SHARE_ROOT}/replock.lock
             fi
fi


return 0

}




###############################################################################
# Main Program
# Parameters: None
###############################################################################

if [[ "${DDC_ON_CLOUD}" == TRUE ]]; then 
	sleep 10
fi

source $IDENMGMT_ROOT/opendj/bin/common.sh
if [ $? -ne 0 ]; then
   echo "ERROR: Failed to source $IDENMGMT_ROOT/opendj/bin/common.sh"
   exit 1
fi

SetLogFile $LOG_DIR $LOG_FILE
if [ $? != 0 ]; then
   echo "ERROR: SetLogFile failed"
   error "SetLogFile failed"
   exit 1
fi

SetENMSettings $1
if [ $? != 0 ]; then
    LogMessage "ERROR: cannot set ENM variables"
    error "Cannot set ENM varables"
    exit 1
fi


AddOpendjUserToJbossGroup
if [ $? != 0 ]; then
    LogMessage "ERROR: cannot add opendj user to jboss group"
    error "Cannot add opendj user to jboss group"
    exit 1
fi

ExtractAndConfigureCerts
if [ $? != 0 ]; then
    LogMessage "ERROR: cannot configure certs"
    error "Cannot configure certs"
    exit 1
fi

HardenPasskeys
if [ $? != 0 ]; then
    LogMessage "ERROR: mode could not be changed to 644"
    error "Mode could not be changed to 644"
    exit 1
fi

HardenCerts
if [ $? != 0 ]; then
    LogMessage "ERROR: mode for certs could not be changed to 644"
    error "Mode for certs could not be changed to 644"
    exit 1
fi

LogMessage "INFO: Opendj installation/upgrade started..."
if [ $# -ne 1 ]; then
   LogMessage "ERROR: Wrong number of arguments"
   error "Wrong number of arguments"
   exit 1
fi

#Assure root ownership for /ericsson/tor/data after any changes connected to passkey extraction
USR=$(stat -c "%u" $SHARE_ROOT)
GRP=$(stat -c "%g" $SHARE_ROOT)
if [ $USR -eq 502 ] && [ $GRP -eq 502 ]; then
   LogMessage "INFO: Ownership of ${SHARE_ROOT} changed to root"
   $CHOWN root:root $SHARE_ROOT
   if [ $? -ne 0 ]; then
      LogMessage "WARNING: failed to change ownership for ${SHARE_ROOT}"
      info "WARNING: failed to change ownership for ${SHARE_ROOT}"
   fi
fi

#Force 755 rights to /ericsson/tor/data directory. TORF-213271
#This is to sanitize ENM installation made before 17.03
$CHMOD 755 $SHARE_ROOT
if [ $? -ne 0 ]; then
      LogMessage "WARNING: failed to set rights for ${SHARE_ROOT}"
      info "WARNING: failed to set rights for ${SHARE_ROOT}"
fi


# record installation settings
LogMessage "INFO: LDAP_HOST $LDAP_HOST"
LogMessage "INFO: DM_DN $DM_DN"
LogMessage "INFO: BASE_DN $BASE_DN"
LogMessage "INFO: ADMIN_CONNECTOR_PORT $ADMIN_CONNECTOR_PORT"
LogMessage "INFO: COM_INF_LDAP_PORT $COM_INF_LDAP_PORT"
LogMessage "INFO: SSO_USER_DN $SSO_USER_DN"

# Parse argument to determine if this is an install or an upgrade
if [ $1 -ne 1 -a $1 -ne 2 ]; then
   LogMessage "ERROR: Install type is missing or is wrong"
   error "Install type is missing or is wrong"
   exit 1
elif [ $1 -eq 1 ]; then
   LogMessage "INFO: This is an install"
   info "This is an install"

  #If opendj first installation is on going (something wrong), clean and start first installation again
  if [[ "${DDC_ON_CLOUD}" == TRUE ]]; then
         if [ -d ${OPENDJ_ROOT}/opendj_first_installation_on_going ]; then
              CleanInstall 
         fi
  fi

   # (first step) Create file to save the status that opendj first installation is on going
   if [[ "${DDC_ON_CLOUD}" == TRUE ]]; then
       mkdir -p ${OPENDJ_ROOT}/opendj_first_installation_on_going
   fi
   
   UpdatePasswords
   if [ $? != 0 ] ; then
      LogMessage "ERROR: UpdatePasswords failed"
      error "UpdatePasswords failed"
      CleanInstall
      exit 1
   fi
   UnzipSource
   if [ $? != 0 ] ; then
      LogMessage "ERROR: Unzip source failed."
      error "Unzip source failed."
      CleanInstall
      exit 1
   fi

   # (second step) Create file to save the status that opendj first installation is on going
   # DA CONTROLLARE PERCHE? VIENE FATTO DUE VOLTE QUESTO SETTAGGIO IN PARTENZA E ANCHE QUI PER vENM e cENM
   if [ "${DDC_ON_CLOUD}" == TRUE ] || [ "${cENM_DEPLOYMENT}" == TRUE ] ; then
       mkdir -p ${OPENDJ_ROOT}/template/config/schema/
       ${CP} /opt/opendj/template/config/schema/99-user.ldif ${OPENDJ_ROOT}/template/config/schema/
   fi

   javaCheck
   if [ "$?" != "0" ] ; then
      LogMessage "ERROR: javaCheck failed "
      error "javaCheck failed "
      CleanInstall
      exit 1
   fi

   InstallOpendj
   if [ "$?" != "0" ] ; then
      LogMessage "ERROR: InstallOpendj failed "
      error "InstallOpendj failed "
      CleanInstall
      exit 1
   fi

   # setAllow-zero-length-values to true to permit empty mail
   setAllow-zero-length-values
   if [ $? != 0 ] ; then
     LogMessage "ERROR: setAllow-zero-length-values failed "
     error "setAllow-zero-length-values failed"
     exit 1
   fi

   ReconfigureCache
   if [ $? != 0 ] ; then
      LogMessage "ERROR: ReconfigureCache failed"
      error "ReconfigureCache failed"
      CleanInstall
      return 1
   fi

   ReconfigureDiskThresholdsBackend
   if [ $? != 0 ] ; then
      LogMessage "ERROR: ReconfigureDiskThresholdsBackend failed"
      error "ReconfigureDiskThresholdsBackend failed"
      CleanInstall
      return 1
   fi

   ReconfigureDiskThresholdsReplication
   if [ $? != 0 ] ; then
      LogMessage "ERROR: ReconfigureDiskThresholdsReplication failed"
      error "ReconfigureDiskThresholdsReplication failed"
      CleanInstall
      return 1
   fi

   DisableChangelog-enabled
   if [ $? != 0 ] ; then
      LogMessage "ERROR: DisableChangelog-enabled failed"
      error "DisableChangelog-enabled failed"
      CleanInstall
      return 1
   fi

## Apply Patches start #######################################
#  To Apply Patches please modify ApplyPatches and uncomment #
#  also the stop and start ds below                          #

#   StopDS
#   if [ $? != 0 ] ; then
#      LogMessage "ERROR: RestartDS failed"
#      error "RestartDS failed"
#      CleanInstall
#      exit 1
#   fi

#   ApplyPatches
#   if [ $? -ne 0 ]; then
#       LogMessage "ERROR: failed to apply OpenDJ patches"
#       error "Failed to apply OpenDJ patches"
#       exit 1
#   fi

#   StartDS
#   if [ $? != 0 ] ; then
#      LogMessage "ERROR: StartDS failed"
#      error "StartDS failed"
#      CleanInstall
#      exit 1
#   fi

## Apply Patches end #######################################

   SetJVMArgsOpendj
   if [ "$?" != "0" ] ; then
      LogMessage "ERROR: Set JVM memory failed "
      error "Set JVM memory failed "
      CleanInstall
      exit 1
   fi

   ConfigOpendjCertificate
   if [ "$?" != "0" ] ; then
     LogMessage "ERROR: ConfigOpendjCertificate failed"
     error "ConfigOpendjCertificate failed"
     CleanInstall
     exit 1
   fi

   # no more used for initial install of DS 7.3.0
   # SetupKeyManagerProvider
   # if [ "$?" != "0" ] ; then
   #  LogMessage "ERROR: SetupKeyManagerProvider failed"
   #  error "SetupKeyManagerProvider failed"
   #  CleanInstall
   #  exit 1
   # fi

   if [ "${DDC_ON_CLOUD}" != TRUE  ] && [ "${cENM_DEPLOYMENT}" != TRUE ] ; then
      SetupOpenDJLogging
      if [ "$?" != "0" ] ; then
         LogMessage "ERROR: SetupOpenDJLogging failed"
         error "SetupOpenDJLogging failed"
         CleanInstall
         exit 1
      fi
   fi

   if [ "${DDC_ON_CLOUD}" != TRUE ] && [ "${cENM_DEPLOYMENT}" != TRUE ] ; then
       chown -R opendj:opendj /ericsson/opendj
       ln -s /var/ericsson/log/opendj/server /ericsson/opendj/opendj/logs
       chown -R opendj:opendj /ericsson/opendj/opendj/logs
   fi

   CreateContainers
   if [ "$?" != "0" ] ; then
      LogMessage "ERROR: CreateContainers failed"
      error "CreateContainers failed"
      CleanInstall
      exit 1
   fi

   CreateProxyagentContainer
   if [ $? != 0 ] ; then
      LogMessage "ERROR: CreateProxyagentContainer failed"
      error "CreateProxyagentContainer failed"
      CleanInstall
      exit 1
   fi

   CreateProxyagentContainerLockable
   if [ $? != 0 ] ; then
      LogMessage "ERROR: CreateProxyagentContainerLockable failed"
      error "CreateProxyagentContainerLockable failed"
      CleanInstall
      exit 1
   fi

   EnableReferentialIntegrity
   if [ "$?" != "0" ] ; then
      LogMessage "ERROR: EnableReferentialIntegrity failed"
      error "EnableReferentialIntegrity failed"
      CleanInstall
      exit 1
   fi

   DefineLogRetentionPolicies
   if [ "$?" != "0" ] ; then
       LogMessage "ERROR: DefineLogRetentionPolicies failed"
       error "DefineLogRetentionPolicies failed"
      CleanInstall
       exit 1
   fi

   DefineLogRotationPolicies
   if [ "$?" != "0" ] ; then
       LogMessage "ERROR: DefineLogRotationPolicies failed"
       error "DefineLogRotationPolicies failed"
      CleanInstall
       exit 1
   fi

   AssignLogPoliciesToLogPublisher
   if [ "$?" != "0" ] ; then
      LogMessage "ERROR: AssignLogPoliciesToLogPublisher failed"
      error "AssignLogPoliciesToLogPublisher failed"
      CleanInstall
      exit 1
   fi

#Change purge delay for replication
   ChangePurgeDelay

   EnableAuditLogPublisher
   if [ "$?" != "0" ] ; then
      LogMessage "ERROR: EnableAuditLogPublisher failed"
      error "EnableAuditLogPublisher failed"
      CleanInstall
      exit 1
   fi

   EnableSHA256PasswordStorageScheme
   if [ "$?" != "0" ] ; then
      LogMessage "ERROR: EnableSHA256PasswordStorageScheme failed"
      error "EnableSHA256PasswordStorageScheme failed"
      CleanInstall
      exit 1
   fi

   ConfigDefaultPasswordPolicy
   if [ "$?" != "0" ] ; then
      LogMessage "ERROR: ConfigDefaultPasswordPolicy failed"
      error "ConfigDefaultPasswordPolicy failed"
      CleanInstall
      exit 1
   fi

   ConfigSuperuserPasswdPolicy
   if [ "$?" != "0" ] ; then
      LogMessage "ERROR: ConfigSuperuserPasswdPolicy failed"
      error "ConfigSuperuserPasswdPolicy failed"
      CleanInstall
      exit 1
   fi

   SetENM_UserSubentryPasswordPolicy
   if [ "$?" != "0" ] ; then
      LogMessage "ERROR: SetENM_UserSubentryPasswordPolicy failed"
      error "SetENM_UserSubentryPasswordPolicy failed"
      CleanInstall
      exit 1
   fi

   SetPasswordPolicyForProxyUsersLockable
   if [ "$?" != "0" ] ; then
      LogMessage "ERROR: SetPasswordPolicyForProxyUsersLockable failed"
      error "SetPasswordPolicyForProxyUsersLockable failed"
      CleanInstall
      exit 1
   fi

   UpdateRandomPasswordGenerator
   if [ "$?" != "0" ] ; then
      LogMessage "ERROR: UpdateRandomPasswordGenerator failed"
      error "UpdateRandomPasswordGenerator failed"
      CleanInstall
      exit 1
   fi

   ConfigHttpConnectionHandler
   if [ "$?" != "0" ] ; then
      LogMessage "ERROR: ConfigHttpConnectionHandler failed"
      error "ConfigHttpConnectionHandler failed"
      CleanInstall
      exit 1
   fi

   CreateReadOnlyUser
   if [ "$?" != "0" ] ; then
      LogMessage "ERROR: CreateReadOnlyUser failed"
      error "CreateReadOnlyUser failed"
      CleanInstall
      exit 1
   fi

   PrimeSecData
   if [ "$?" != "0" ] ; then
      LogMessage "ERROR: PrimeSecData failed"
      error "PrimeSecData failed"
      CleanInstall
      exit 1
   fi

   EnableTls
   if [ "$?" != "0" ] ; then
      LogMessage "ERROR: EnableTls failed"
      error "EnableTls failed"
      CleanInstall
      exit 1
   fi

   HardenOpendj
   if [ "$?" != "0" ] ; then
      LogMessage "ERROR: HardenOpendj failed"
      error "HardenOpendj failed"
      CleanInstall
      exit 1
   fi

   AdjustThreadsParametersForSynchronization
   if [ "$?" != "0" ] ; then
      LogMessage "ERROR: AdjustThreadsParametersForSynchronization failed"
      error "AdjustThreadsParametersForSynchronization failed"
      CleanInstall
      exit 1
   fi

   EnableJMX
   if [ "$?" != "0" ] ; then
      LogMessage "ERROR: EnableJMX failed"
      error "EnableJMX failed"
      CleanInstall
      exit 1
   fi

   RemovePasswordExpirationFromProxyUsers
   if [ $? -ne 0 ]; then
      LogMessage "ERROR: RemovePasswordExpirationFromProxyUsers failed"
      error "RemovePasswordExpirationFromProxyUsers failed"
      CleanInstall
      exit 1
   fi

   RemovePasswordExpirationFromM2MUsers
   if [ $? -ne 0 ]; then
      LogMessage "ERROR: RemovePasswordExpirationFromM2MUsers failed"
      error "RemovePasswordExpirationFromM2MUsers failed"
      CleanInstall
      exit 1
   fi

   ModifyPwdMaxFailureForProxyUsers
   if [ $? -ne 0 ]; then
      LogMessage "ERROR: ModifyPwdMaxFailureForProxyUsers failed"
      error "ModifyPwdMaxFailureForProxyUsers failed"
      CleanInstall
      exit 1
   fi

   ModifyPwdMaxFailureForM2MUsers
   if [ $? -ne 0 ]; then
      LogMessage "ERROR: ModifyPwdMaxFailureForM2MUsers failed"
      error "ModifyPwdMaxFailureForM2MUsers failed"
      CleanInstall
      exit 1
   fi

   UpdateSsoUserPriv
   if [ $? -ne 0 ]; then
      LogMessage "ERROR: UpdateSsoUserPriv failed"
      error "UpdateSsoUserPriv failed"
      CleanInstall
      exit 1
   fi

   for i in "${USERS_WITH_DISABLED_PASSWORD_AGEING[@]}"
   do
      RemovePasswordExpirationForEnmUser $i
      if [ $? -ne 0 ]; then
         LogMessage "ERROR: RemovePasswordExpirationForEnmUser $i failed"
         error "RemovePasswordExpirationForEnmUser $i failed"
         CleanInstall
         exit 1
      fi
   done

   ModifyPwdChangedTimeAttributeType
   if [ $? -ne 0 ]; then
      LogMessage "ERROR: ModifyPwdChangedTimeAttributeType failed"
      error "ModifyPwdChangedTimeAttributeType failed"
      CleanInstall
      exit 1
   fi

   ImproveConfigParametersHeapMemory 
   if [ $? -ne 0 ]; then
      LogMessage "ERROR: ImproveConfigParametersHeapMemory failed"
      error "ImproveConfigParametersHeapMemory failed"
      CleanInstall
      exit 1
   fi

   SetUidNumberAsIndex
   if [ $? -ne 0 ]; then
      LogMessage "ERROR: SetUidNumberAsIndex failed"
      error "SetUidNumberAsIndex failed"
      CleanInstall
      exit 1
   fi
   SetUnauthenticatedRequestsPolicy
   if [ $? -ne 0 ]; then
      LogMessage "ERROR: SetUnauthenticatedRequestsPolicy failed"
     error "SetUnauthenticatedRequestsPolicy failed"
      CleanInstall
      exit 1
   fi


   ScheduleExportLdif
   if [ $? -ne 0 ]; then
      LogMessage "ERROR: ScheduleExportLdif failed"
      error "ScheduleExportLdif failed"
      CleanInstall
      exit 1
   fi

   StopDS
   if [ "$?" != "0" ] ; then
      LogMessage "ERROR: ShutdownOpendj failed"
      error "ShutdownOpendj failed"
      CleanInstall
      exit 1
   fi



#$DSCONFIG  set-synchronization-provider-prop \
#          --provider-name Multimaster\ Synchronization \
#          --set enabled:true \
#          --offline \
#          --configFile ${OPENDJ_ROOT}/config/config.ldif \
#          --no-prompt
#  if [ $? != 0 ] ; then
#     LogMessage "ERROR: enabling replication failure"
#     error "replication enabling failure  "
#     CleanInstall
#     exit 1
#  fi

   HardenBinFiles
   if [ "$?" != "0" ]; then
      LogMessage "ERROR: HardenBinFiles failed"
      error "HardenBinFiles failed"
      CleanInstall
      exit 1
   fi

  #If opendj first installation is finished with success, remove first installation file
  if [[ "${DDC_ON_CLOUD}" == TRUE ]]; then
               ${RM_RF} ${OPENDJ_ROOT}/opendj_first_installation_on_going            
                    if [ "$?" != "0" ] ; then
                        LogMessage "ERROR: Removed opendj_first_installation_on_going  failed"
                        error "Removed opendj_first_installation_on_going  failed"
                        CleanInstall
                        exit 1
                    fi
  fi

else
   LogMessage "INFO: This is an upgrade"
   info "This is an upgrade"

###############################################################################
# Code to copy of DB and changelogDB to their mounting points                 #
  if [ "${DDC_ON_CLOUD}" != TRUE  ] && [ "${cENM_DEPLOYMENT}" != TRUE ] ; then

     SetupOpenDJDBPartition
     if [ $? != 0 ] ; then
        LogMessage "ERROR: SetupOpenDJDBPartition failed"
        error "SetupOpenDJDBPartition failed"
        return 1
     fi

     SetupOpenDJChangeLogDbPartition
     if [ $? != 0 ] ; then
        LogMessage "ERROR: SetupOpenDJChangeLogDbPartition failed"
        error "SetupOpenDJChangeLogDbPartition failed"
        return 1
     fi

  fi
#                                                                              #
################################################################################

   NEW_OPENDJ_VERSION=`cat $IDENMGMT_ROOT/opendj/config/version`
   if [ $? -ne 0  -o -z "$NEW_OPENDJ_VERSION" ]; then
      LogMessage "ERROR: Failed to determine version of Opendj being installed"
      error "Failed to determine version of Opendj being installed"
      exit 1
   fi
   
   ## Retrieve OLD_OPENDJ_VERSION
   VERSION=$(grep "ds-cfg-version:" $OPENDJ_ROOT/config/config.ldif| sed -e 's/[^0-9\.]/ /g'|sed 's/^[ ]*//' | cut -d " " -f 1 | sed 's/.$//')
   if [[ -z "$VERSION" ]]; then
      if [ -f $OPENDJ_ROOT/config/config.version ]; then
         # If config.version file exists then old version is 6.5.x
         VERSION="6.5.5"
      else
         LogMessage "ERROR: old version of opendj not found"
         error "old version of opendj not found"
         exit 1
      fi
   fi
   OLD_OPENDJ_VERSION="$VERSION"

   LogMessage "INFO: Removing filtered-ldap-access.audit.json"
   ${RM_RF} $OPENDJ_ROOT/logs/filtered-ldap-access.audit.jso* 

   LogMessage "INFO: Version of old Opendj: $OLD_OPENDJ_VERSION"
   LogMessage "INFO: Version of Opendj being installed: $NEW_OPENDJ_VERSION"

   if [[ "${DDC_ON_CLOUD}" == TRUE ]]; then
      if [ ! -s $OPENDJ_ROOT/db/adminRoot/admin-backend.ldif ]; then
          LogMessage "INFO: Replication setup failed in the previous run: copy admin-backend.ldif_saved file"
          info "Replication setup failed in the previous run: copy admin-backend.ldif_saved file"
          ${CP}  $OPENDJ_ROOT/admin-backend.ldif_saved $OPENDJ_ROOT/db/adminRoot/admin-backend.ldif
         #no more used from rel. 7.3.0
         #${RM_RF}  $OPENDJ_ROOT/replication_in_progress        
      fi 
   fi

   ExportLDIF
   if [ $? -ne 0 ]; then
      LogMessage "ERROR: ExportLDIF Failed"
      error "ExportLDIF Failed"
      exit 1
   fi

#   UpdateToJeExport
#   if [ $? != 0 ] ; then
#      LogMessage "ERROR: UpdateToJeExport failed"
#      error "UpdateToJeExport failed"
#      exit 1
#   fi

   UnzipSource
   if [ $? != 0 ] ; then
      LogMessage "ERROR: Unzip source failed."
      error "Unzip source failed."
      exit 1
   fi

   if [[ "${DDC_ON_CLOUD}" != TRUE ]]; then
       chown -R opendj:opendj /ericsson/opendj
       ln -s /var/ericsson/log/opendj/server /ericsson/opendj/opendj/logs
       chown -R opendj:opendj /ericsson/opendj/opendj/logs
   fi

   UpdatePasswords
   if [ $? != 0 ] ; then
      LogMessage "ERROR: UpdatePasswords failed"
      error "UpdatePasswords failed"
      exit 1
   fi

   javaCheck
   if [ "$?" != "0" ] ; then
      LogMessage "ERROR: javaCheck failed "
      error "javaCheck failed "
      exit 1
   fi

   SetJVMArgsOpendj
   if [ "$?" != "0" ] ; then
      LogMessage "ERROR: SetJVMArgsOpendj failed "
      error " SetJVMArgsOpendj failed "
      exit 1
   fi

   if [ "$OLD_OPENDJ_VERSION" != "$NEW_OPENDJ_VERSION" ]; then

      LogMessage "UPLIFT: OLD_OPENDJ_VERSION=$OLD_OPENDJ_VERSION and NEW_OPENDJ_VERSION=$NEW_OPENDJ_VERSION"

      UpgradeOpendj
      if [ $? != 0 ] ; then
         LogMessage "ERROR: UpgradeOpendj failed."
         error "UpgradeOpendj failed."
         exit 1
      fi
      export DSCONFIG ADMIN_CONNECTOR_PORT DM_DN DM_PWD OPENDJ_ROOT
      LogMessage "INFO: Calling $IDENMGMT_ROOT/opendj/bin/DeleteOldDBDirs65.sh."
      info " Calling $IDENMGMT_ROOT/opendj/bin/DeleteOldDBDirs65.sh."
      nohup $IDENMGMT_ROOT/opendj/bin/DeleteOldDBDirs65.sh > $LOG_DIR/DeleteOldDBDirs65.log 2>&1 &

   else
      LogMessage "INFO: This is an in-release upgrade"

      # if there are any patches
      # insert here ApplyPatches function

      RemoveOldAdminDataDB
      if [ $? != 0 ] ; then
         LogMessage "ERROR: RemoveOldAdminDataDB failed."
         error "RemoveOldAdminDataDB failed."
         exit 1
      fi
   fi

   #TODO just workaround
   # do we need logs on permanent storage or maybe it's not necessary and DDC will collect them anyway
   if [ "${DDC_ON_CLOUD}" != TRUE  ] && [ "${cENM_DEPLOYMENT}" != TRUE ] ; then
      SetupOpenDJLogging ||  exit 1
   else
      RestoreOpendjLogsUpgrade || exit 1
   fi

   if [[ "${DDC_ON_CLOUD}" == TRUE ]]; then
      LogMessage "Info: Restart procedure for Cloud"
      info "Restart procedure for Cloud"
      # Stop OpenDJ
      StopDS
      if [ $? != 0 ] ; then
         LogMessage "ERROR: StopDS failed"
         error "StopDS failed during restart procedure for cloud"
         return 1
      fi
      # Waiting for deleting lock file
      #while [ -f "$OPENDJ_INTERNAL_LOCK_FILE" ]
      #do
      #    LogMessage "INFO: waiting for deleting OpenDJ lock file"
      #    sleep 5
      #done    
      #Start OpenDJ
     
      sleep 10 
      StartDS
      if [ $? != 0 ] ; then
         LogMessage "ERROR: StartDS failed"
         error "StartDS failed during restart procedure for cloud"
         return 1
      fi

      #SetJVMArgsOpendj

   else
      LogMessage "Info: Restart procedure for Physical"
      info "Restart procedure for Physical"

      # SetJVMArgsOpendj
      $CHOWN -R opendj:opendj $OPENDJ_ROOT/locks
      RestartDS
      if [ $? != 0 ] ; then
         LogMessage "ERROR: RestartDS failed"
         error "RestartDS failed during restart procedure for physical"
         exit 1
      fi
   fi

   # setAllow-zero-length-values to true to permit empty mail
   setAllow-zero-length-values
   if [ $? != 0 ] ; then
     LogMessage "ERROR: setAllow-zero-length-values failed "
     error "setAllow-zero-length-values failed"
     exit 1
   fi

   #Change purge delay for replication
   ChangePurgeDelay
   if [ $? != 0 ] ; then
     LogMessage "ERROR: ChangePurgeDelay failed "
     error "ChangePurgeDelay failed"
     exit 1
   fi

   EnableAuditLogPublisher
   if [ "$?" != "0" ] ; then
      LogMessage "ERROR: EnableAuditLogPublisher failed"
      error "EnableAuditLogPublisher failed"
      exit 1
   fi

   EnableCustomLogPolicies
   if [ "$?" != "0" ] ; then
      LogMessage "ERROR: EnableCustomLogPolicies failed"
      error "EnableCustomLogPolicies failed"
      exit 1
   fi

   ConfigDefaultPasswordPolicy
   if [ "$?" != "0" ] ; then
      LogMessage "ERROR: ConfigDefaultPasswordPolicy failed"
      error "ConfigDefaultPasswordPolicy failed"
      exit 1
   fi

   SetSuperUserPasswordPolicy
   if [ "$?" != "0" ] ; then
      LogMessage "ERROR: SetSuperUserPasswordPolicy failed"
      error "SetSuperUserPasswordPolicy failed"
      exit 1
   fi

   AdjustThreadsParametersForSynchronization
   if [ "$?" != "0" ] ; then
      LogMessage "ERROR: AdjustThreadsParametersForSynchronization failed"
      error "AdjustThreadsParametersForSynchronization failed"
      exit 1
   fi

   SetENM_UserSubentryPasswordPolicy
   ret=$?
   if [ "$ret" != "0" ] ; then
      if [ "$ret" == "3" ] ; then
       LogMessage "WARNING: SetENM_UserSubentryPasswordPolicy - Restore/Rollback exit with success"
       info "WARNING: SetENM_UserSubentryPasswordPolicy - Restore/Rollback exit with success"
       StopDsWithRetry
          if [ $? != 0 ] ; then
               LogMessage "ERROR: StopDsWithRetry failed"
               error "StopDsWithRetry failed"
               exit 1
          fi

       ${OPENDJ_ROOT}/bin/dsrepl clear-changelog 
          if [ $? != 0 ] ; then
               LogMessage  "ERROR: Clear changelogdb failed"
               error "Clear changelogdb failed"
               exit 1
          fi
       LogMessage "INFO: clear changelogdb exit with success"
       info "Clear changelogdb  exit with success"

       exit 0
      fi
      LogMessage "ERROR: SetENM_UserSubentryPasswordPolicy failed"
      error "SetENM_UserSubentryPasswordPolicy failed"
      exit 1
   fi

   UpdateSchema
   if [ $? != 0 ] ; then
      LogMessage "ERROR: UpdateSchema failed."
      error "UpdateSchema failed."
      exit 1
   fi

   CreateProxyagentContainer
   if [ $? != 0 ] ; then
      LogMessage "ERROR: CreateProxyagentContainer failed"
      error "CreateProxyagentContainer failed"
      exit 1
   fi

   CreateProxyagentContainerLockable
   if [ $? != 0 ] ; then
      LogMessage "ERROR: CreateProxyagentContainerLockable failed"
      error "CreateProxyagentContainerLockable failed"
      exit 1
   fi

   SetPasswordPolicyForProxyUsersLockable
   if [ "$?" != "0" ] ; then
      LogMessage "ERROR: SetPasswordPolicyForProxyUsersLockable failed"
      error "SetPasswordPolicyForProxyUsersLockable failed"
      exit 1
   fi

   UpdateRandomPasswordGenerator
   if [ $? != 0 ] ; then
      LogMessage "ERROR: UpdateRandomPasswordGenerator failed"
      error "UpdateRandomPasswordGenerator failed"
      exit 1
   fi

   RemovePasswordExpirationFromProxyUsers
   if [ $? -ne 0 ]; then
      LogMessage "ERROR: RemovePasswordExpirationFromProxyUsers failed"
      error "RemovePasswordExpirationFromProxyUsers failed"
      exit 1
   fi

   RemovePasswordExpirationFromM2MUsers
   if [ $? -ne 0 ]; then
      LogMessage "ERROR: RemovePasswordExpirationFromM2MUsers failed"
      error "RemovePasswordExpirationFromM2MUsers failed"
      exit 1
   fi

   ModifyPwdMaxFailureForProxyUsers
   if [ $? -ne 0 ]; then
      LogMessage "ERROR: ModifyPwdMaxFailureForProxyUsers failed"
      error "ModifyPwdMaxFailureForProxyUsers failed"
      exit 1
   fi

   ModifyPwdMaxFailureForM2MUsers
   if [ $? -ne 0 ]; then
      LogMessage "ERROR: ModifyPwdMaxFailureForM2MUsers failed"
      error "ModifyPwdMaxFailureForM2MUsers failed"
      exit 1
   fi

   UpdateSsoUserPriv
   if [ $? -ne 0 ]; then
      LogMessage "ERROR: UpdateSsoUserPriv failed"
      error "UpdateSsoUserPriv failed"
      exit 1
   fi

   for i in "${USERS_WITH_DISABLED_PASSWORD_AGEING[@]}"
   do
      RemovePasswordExpirationForEnmUser $i
      if [ $? -ne 0 ]; then
         LogMessage "ERROR: RemovePasswordExpirationForEnmUser $i failed"
         error "RemovePasswordExpirationForEnmUser $i failed"
         exit 1
      fi
   done

   ModifyPwdChangedTimeAttributeType
   ret=$?
   if [ "$ret" != "0" ] ; then
      if [ "$ret" == "3" ] ; then
       LogMessage "WARNING: ModifyPwdChangedTimeAttributeType - Restore/Rollback exit with success"
       info "WARNING: ModifyPwdChangedTimeAttributeType - Restore/Rollback exit with success"
       StopDsWithRetry
          if [ $? != 0 ] ; then
               LogMessage "ERROR: StopDsWithRetry failed"
               error "StopDsWithRetry failed"
               exit 1
          fi

       ${OPENDJ_ROOT}/bin/dsrepl clear-changelog 
          if [ $? != 0 ] ; then
               LogMessage  "ERROR: Clear changelogdb failed"
               error "Clear changelogdb failed"
               exit 1
          fi
       LogMessage "INFO: clear changelogdb exit with success"
       info "Clear changelogdb  exit with success"

       exit 0
      fi
      LogMessage "ERROR: ModifyPwdChangedTimeAttributeType failed"
      error "ModifyPwdChangedTimeAttributeType failed"
      exit 1
   fi

   # It is no more necessary for DS 7.3 
   # if [ "$OLD_OPENDJ_VERSION" != "$NEW_OPENDJ_VERSION" ]; then
   #   # only if not in single opendj configuration (trasport and extra small)
   #   IsSingleOpendj
   #   if [ $? != 0 ] ; then
   #     if [[ "${DDC_ON_CLOUD}" != TRUE ]]; then
   #       ReconfigureOpendj
   #       if [ $? != 0 ] ; then
   #          LogMessage "ERROR: ReconfigureOpendj failed."
   #          error "ReconfigureOpendj failed."
   #          exit 1
   #       fi
   #      fi
   #   fi
   # else
   #   LogMessage "INFO: Not a 3PP uplift, no reconfiguration necessary"
   # fi

   # It is no more necessary for DS 7.3
   # You would create a Key Manager Provider "PKCS12" that is not used:
   # In case of upg you use Key Manager Provider "Default Key Manager" (from DS 6.5.5)
   # Trust Manager Provider used: "PKCS12" (created with "SecurityModel")
   # SetupKeyManagerProvider
   # if [ "$?" != "0" ] ; then
   #    LogMessage "ERROR: SetupKeyManagerProvider failed"
   #   error "SetupKeyManagerProvider failed"
   #   exit 1
   # fi

   if [ "$OLD_OPENDJ_VERSION" == "3.0.0" ]; then
       DeleteOldConnectors
       if [ "$?" != "0" ] ; then
         LogMessage "ERROR: DisableOldConnectors failed"
         error "DisableOldConnectors failed"
         exit 1
       fi
   fi

   # It is no more necessary for DS 7.3
   # In case of upg you use Key Manager Provider "Default Key Manager" (from DS 6.5.5)
   # Trust Manager Provider used: "PKCS12" (created with "SecurityModel")
   # ConfigHttpConnectionHandler
   # if [ "$?" != "0" ] ; then
   #   LogMessage "ERROR: ConfigHttpConnectionHandler failed"
   #   error "ConfigHttpConnectionHandler failed"
   #   exit 1
   # fi

   # LDAPS, HTTP and ADMIN connectors linked to Key Manager Provider "Default Key Manager" (from DS 6.5.5)
   # and Trust Manager Provider "PKCS12" (created with "SecurityModel")
   # Set Up of new allowed suites already done in SecurityModel
   # EnableTls
   # if [ "$?" != "0" ] ; then
   #   LogMessage "ERROR: EnableTls failed"
   #   error "EnableTls failed"
   #   exit 1
   # fi

   setGdprAcis
   if [ "$?" != "0" ] ; then
      LogMessage "ERROR: setGdprAcis failed"
      error "setGdprAcis failed"
      exit 1
   fi

   # this function is invoked to give
   # Directory Manager some rights on JMX
   EnableJMX
   if [ "$?" != "0" ] ; then
     LogMessage "ERROR: EnableJMX failed"
     error "EnableJMX failed"
     exit 1
   fi

   ImproveConfigParametersHeapMemory 
   if [ $? -ne 0 ]; then
      LogMessage "ERROR: ImproveConfigParametersHeapMemory failed"
      error "ImproveConfigParametersHeapMemory failed"
      exit 1
   fi

   SetUidNumberAsIndex
   if [ $? -ne 0 ]; then
      LogMessage "ERROR: SetUidNumberAsIndex failed"
      error "SetUidNumberAsIndex failed"
      exit 1
   fi

   SetUnauthenticatedRequestsPolicy
   if [ $? -ne 0 ]; then
      LogMessage "ERROR: SetUnauthenticatedRequestsPolicy failed"
      error "SetUnauthenticatedRequestsPolicy failed"
      exit 1
   fi

   ScheduleExportLdif
   if [ $? -ne 0 ]; then
      LogMessage "ERROR: ScheduleExportLdif failed"
      error "ScheduleExportLdif failed"
      CleanInstall
      exit 1
   fi

   StopDsWithRetry
   if [ $? != 0 ] ; then
      error "StopDsWithRetry failed"
      exit 1
   fi

   HardenBinFiles
   if [ "$?" != "0" ] ; then
      LogMessage "ERROR: HardenBinFiles failed"
      error "HardenBinFiles failed"
      exit 1
   fi

fi

#Modify Crontab for running check replication script only once in an hour
#Modify the default 33 value with a random value between 1 and 60

if [ "$cENM_DEPLOYMENT" != TRUE ] ; then
    echo "33  * * * * root sh /opt/ericsson/com.ericsson.oss.security/idenmgmt/opendj/bin/monitor_replication.sh CRON_MODE  > /dev/null 2>&1" > /etc/cron.d/monitor_cron
    chmod 644 /etc/cron.d/monitor_cron
    RANGE=59
    number=$RANDOM+1
    let "number %= $RANGE"
    sed -i "s/33/$number/" /etc/cron.d/monitor_cron
fi

# delete the possibly old ldapnoresponse.cnt
    LogMessage "INFO: remove old ldapnoresponse.cnt."
    if [ -f ${OPENDJ_ROOT}/$UNWILLINGCNTFILE ]; then
       rm -f ${OPENDJ_ROOT}/$UNWILLINGCNTFILE
    fi

# delete the possibly old monitorreplication.cnt
    LogMessage "INFO: remove old monitorreplication.cnt."
    if [ -f $LOG_DIR/$MON_REPL_CNTFILE ]; then
       rm -f $LOG_DIR/$MON_REPL_CNTFILE
    fi

# delete the deployment info
    LogMessage "INFO: remove deploymentId.cnf"
    if [ -f $DEPLOY_PATH ]; then
       rm -f $DEPLOY_PATH
    fi

LogMessage "INFO: install_opendj.sh completed successfully."
info "install_opendj.sh completed successfully."

exit 0

