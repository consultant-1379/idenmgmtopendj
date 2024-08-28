#!/bin/bash
###########################################################################################
# COPYRIGHT Ericsson 2016
#
# The copyright to the computer program(s) herein is the property of
# Ericsson Inc. The programs may be used and/or copied only with written
# permission from Ericsson Inc. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
###########################################################################################

# This script gathers all the OpenDJ,MySQL and VCS engine logs from the DB node, creates a tgz archive file and moves
# it to the /ericsson/tor/data/idam_logs/ folder, accessible from the Management Server. Temporary
# files are removed afterwards.

GREP='/bin/grep -w'
CUT=/bin/cut
OPENSSL=/usr/bin/openssl
LDAPSEARCH=/opt/opendj/bin/ldapsearch

varTimestamp=`date +%Y-%m-%d:%H:%M:%S`
db_host=`hostname`
varArchiveName="openDJ-logs-$db_host-${varTimestamp}.tgz"
varArchive="/tmp/${varArchiveName}"
LOG_DIR="/ericsson/tor/data/idam_logs"
IDAM_TMP_LOG_DIR="/tmp/idamlogsdump"
OPENDJ_MESSAGES="/var/log/messages"
OPENDJ_TMP="/tmp/opendj-"
OPENDJ_VARLOG="/var/log/opendj/"
MYSQL_VARLOG="/var/log/mysql/"
VCS_ENGINE_LOG="/var/VRTSvcs/log/engine_A.log"
SHARE_ROOT=/ericsson/tor/data
OPENDJ_PASSKEY=$SHARE_ROOT/idenmgmt/opendj_passkey
CONSUL_GET_GP="consul kv get global_properties"
ENM_ON_CLOUD_ENV=`$CONSUL_GET_GP/DDC_ON_CLOUD`

if [ "${ENM_ON_CLOUD_ENV,,}" == "true" ]; then
   COM_INF_LDAP_PORT=`$CONSUL_GET_GP/COM_INF_LDAP_PORT`
   LDAP_ADMIN_PASSWORD=`$CONSUL_GET_GP/LDAP_ADMIN_PASSWORD`
   LDAP_ADMIN_CN=`$CONSUL_GET_GP/LDAP_ADMIN_CN`
else
   GLOBAL_PROPERTY_FILE=${SHARE_ROOT}/global.properties
   eval $(${GREP} "COM_INF_LDAP_PORT" ${GLOBAL_PROPERTY_FILE})
   eval $(${GREP} "LDAP_ADMIN_PASSWORD" ${GLOBAL_PROPERTY_FILE})
   eval $(${GREP} "LDAP_ADMIN_CN" ${GLOBAL_PROPERTY_FILE})
fi

DM_DN=$LDAP_ADMIN_CN
LDAP_PORT=$COM_INF_LDAP_PORT
DM_PWD=""

checkResult()
{
   RESULT=$1
   if [ $RESULT -ne 0 ] ; then
      echo "ERROR! $2 failed"
   else
      echo "SUCCESS! $2 - done!"
   fi
}

decryptOpendjPasswd()
{
   echo "INFO: decryptOpendjPasswd request is received ...... Processing request"

   if [ -e ${OPENDJ_PASSKEY} ]; then
      DM_PWD=`sg jboss -c "echo ${LDAP_ADMIN_PASSWORD} | ${OPENSSL} enc -a -d -md md5 -aes-128-cbc -salt -kfile ${OPENDJ_PASSKEY}"`
      if [ -z "${DM_PWD}" ]; then
         echo "ERROR: Failed to decrypt LDAP_ADMIN_PASSWORD from global properties"
         return 1
      fi
   else
      echo "INFO: ${OPENDJ_PASSKEY} does not exist"
      return 1
   fi

   echo "INFO: decryptOpendjPasswd completed successfully"
   return 0
}

checkOpenDJStatus()
{
   echo "INFO: checking OpenDJ status..."
   $LDAPSEARCH -p $LDAP_PORT --useSSL --bindDN "$DM_DN" -w $DM_PWD --trustAll -b "" objectclass=domain  > /dev/null
}

CollectLdapsearchLogs()
{
   #List the contents of the OpenDJ changelog
   $LDAPSEARCH -p $LDAP_PORT --useSSL --trustAll -D "$DM_DN" -w $DM_PWD -b "cn=changelog" objectclass=* > $IDAM_TMP_LOG_DIR/`hostname`-$varTimestamp-LDAP_changelog.out
   checkResult $? "List the contents of the changelog"

   #List the LDAP monitor entries
 #  $LDAPSEARCH --dontWrap --useSSL --port $LDAP_PORT --bindDN "$DM_DN" -w $DM_PWD --trustAll --baseDN "cn=monitor" --searchScope sub "(objectClass=*)" \* > $IDAM_TMP_LOG_DIR/`hostname`-$varTimestamp--LDAP_monitor.out
# dontWrap not more used in DS 6.5
   $LDAPSEARCH --useSSL --port $LDAP_PORT --bindDN "$DM_DN" -w $DM_PWD --trustAll --baseDN "cn=monitor" --searchScope sub "(objectClass=*)" \* > $IDAM_TMP_LOG_DIR/`hostname`-$varTimestamp--LDAP_monitor.out
   checkResult $? "List the LDAP monitor entries"
}

###############################################################################
# Main Program
# Description: Collect OpenDJ logs
###############################################################################

#Create the main Identity and Access Management log directory if it doesn't exist
echo "Creating the log folder, if not present: $LOG_DIR"
mkdir -p $LOG_DIR
if [ $? != 0 ] ; then
  echo "Failed to create $LOG_DIR, terminating script"
  exit 1
fi

#Create a temporary directory for OpenDJ,MySQL and VCS DB logs
echo "Creating temporary OpenDJ log folder"
mkdir -p $IDAM_TMP_LOG_DIR
if [ $? != 0 ] ; then
   echo "Failed to create $IDAM_TMP_LOG_DIR, terminating script"
   exit 1
fi

#Copy log files to a temporary folder
echo "Copying log files to a temporary folder"
cp $OPENDJ_MESSAGES* $IDAM_TMP_LOG_DIR/
checkResult $? "Copying $OPENDJ_MESSAGES"
cp $OPENDJ_TMP* $IDAM_TMP_LOG_DIR/
checkResult $? "Copying $OPENDJ_TMP"
cp -r $OPENDJ_VARLOG. $IDAM_TMP_LOG_DIR/
checkResult $? "Copying  $OPENDJ_VARLOG"
cp -r $MYSQL_VARLOG. $IDAM_TMP_LOG_DIR/
checkResult $? "Copying  $MYSQL_VARLOG"

if [ "${ENM_ON_CLOUD_ENV,,}" != "true" ]; then
   cp $VCS_ENGINE_LOG $IDAM_TMP_LOG_DIR/
   checkResult $? "Copying $VCS_ENGINE_LOG"
fi

#Collect network configuration and system properties
netstat -an | grep 8989 > $IDAM_TMP_LOG_DIR/`hostname`-$varTimestamp--netstat
ifconfig -a > $IDAM_TMP_LOG_DIR/`hostname`-$varTimestamp--ifconfig
echo "System-release:" >> $IDAM_TMP_LOG_DIR/`hostname`-$varTimestamp--systemproperties.out
cat /etc/system-release >> $IDAM_TMP_LOG_DIR/`hostname`-$varTimestamp--systemproperties.out
echo "Redhat-release:" >> $IDAM_TMP_LOG_DIR/`hostname`-$varTimestamp--systemproperties.out
cat /etc/redhat-release >> $IDAM_TMP_LOG_DIR/`hostname`-$varTimestamp--systemproperties.out
echo "etc/hosts:" >> $IDAM_TMP_LOG_DIR/`hostname`-$varTimestamp--systemproperties.out
cat /etc/hosts >> $IDAM_TMP_LOG_DIR/`hostname`-$varTimestamp--systemproperties.out
echo "resolv.conf:" >> $IDAM_TMP_LOG_DIR/`hostname`-$varTimestamp--systemproperties.out
cat /etc/resolv.conf >> $IDAM_TMP_LOG_DIR/`hostname`-$varTimestamp--systemproperties.out
echo "nsswitch.conf:" >> $IDAM_TMP_LOG_DIR/`hostname`-$varTimestamp--systemproperties.out
cat /etc/nsswitch.conf >> $IDAM_TMP_LOG_DIR/`hostname`-$varTimestamp--systemproperties.out

decryptOpendjPasswd
if [ $? != 0 ]; then
   echo "ERROR: decrypt password failed."
fi

checkOpenDJStatus
status=$?
if [ $status != 0 ]; then
   echo "INFO: OpenDJ is OFFLINE or w/o connectivity, LDAP exit code is $status"
else
   echo "INFO: OpenDJ is ONLINE, collecting LDAP logs"
   CollectLdapsearchLogs
   if [ $? != 0 ]; then
      echo "ERROR: CollectLdapsearchLogs failed"
   fi
fi

#Create the archive, remove temporary folder and move the archive to /ericsson/tor/data/idam_logs/
echo "Creating the archive with OpenDJ logs from $db_host"
tar czf ${varArchive} --directory="${IDAM_TMP_LOG_DIR}" .
checkResult $? "Archive compression"

echo "Removing temporary folder"
rm -rf $IDAM_TMP_LOG_DIR
checkResult $? "Removing temporary folder"

echo "Begin moving files to the $LOG_DIR folder, accessible from the MS, the name of the archive: $varArchiveName"
mv $varArchive $LOG_DIR
checkResult $? "Moving log archive to $LOG_DIR"

echo "Check if the archive exists and verify the if final contents of the log archive file matches the contents of the log folders."
echo "If errors are present during copying, missing or nonexistent log files might be the reason"
exit 0

