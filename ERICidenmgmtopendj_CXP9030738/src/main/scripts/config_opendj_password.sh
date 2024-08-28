#!/bin/bash
###############################################################################
# COPYRIGHT Ericsson 2015 
# The copyright to the computer program(s) herein is the property of
# Ericsson Inc. The programs may be used and/or copied only with written
# permission from Ericsson Inc. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
#
###############################################################################
# This script is used to change the LDAP_ADMIN_PASSWORD password
# Author: Team ENMeshed
#
###############################################################################

IDENMGMT_ROOT=/opt/ericsson/com.ericsson.oss.security/idenmgmt
PROPS_FILE=$IDENMGMT_ROOT/config/datastore.properties
OPENDJ_PASSKEY=/ericsson/tor/data/idenmgmt/opendj_passkey

# set logs file
LOG_FILE="/var/log/opendj/opendj-password-change-`/bin/date "+%F:%H:%M:%S%:z"`.log"

# database DN
DM_DN=""
DM_PWD=""

# old password is provided by first parameter of the script in encrypted form
PREVIOUS_PASS_ENC="$1"
PREVIOUS_PASS=""

# old passkey is provided by second parameter of the script as string
PREVIOUS_PASSKEY="$2"
CURRENT_PASSKEY=""

# this script is performed after password change in global.properties, so new password is
# taken from global.propertiws file
NEW_PASS=""

# load common methods 
source ${IDENMGMT_ROOT}/opendj/bin/config_common.sh


##################################################
# MAIN
##################################################

echo "Script to change LDAP_ADMIN_PASSWORD"

#Create log file
SetLogFile $LOG_FILE
if [ $? != 0 ] ; then
   echo "ERROR: SetLogFile failed."
   exit 1
fi

# do nothing if the passkey is being updated
read -r CURRENT_PASSKEY < $OPENDJ_PASSKEY

if [ "$CURRENT_PASSKEY" != "$PREVIOUS_PASSKEY" ]; then
    LogMessage "This is a passkey update not a password change so nothing to do"
    exit 0
fi

# Verify old password
CheckPassword "LDAP_ADMIN_PASSWORD" $OPENDJ_PASSKEY
if [ $? != 0 ] ; then
    LogMessage "ERROR: CheckPassword failed"
    exit 1
fi

# do nothing if the password has not been changed
if [ "$PREVIOUS_PASS" == "$NEW_PASS" ]; then
    LogMessage "The password does not require updating."
    exit 0
fi

# Modify OpenDJ admin password
StorePasswordinOpenDJ "$DM_DN" "$NEW_PASS"
if [ $? != 0 ] ; then
    LogMessage "ERROR: StorePasswordinOpenDJ failed"
    exit 1
fi

LogMessage "Password changed successfully"
