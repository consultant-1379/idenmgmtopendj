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
# This utility script used to change the OpenDJ server passwords
# Author: Team ENMeshed
#
###############################################################################

IDENMGMT_ROOT=/opt/ericsson/com.ericsson.oss.security/idenmgmt
OPENDJ_ROOT=/opt/opendj
PROPS_FILE=${IDENMGMT_ROOT}/config/datastore.properties
OPENDJ_DM_PASSKEY=/ericsson/tor/data/idenmgmt/opendj_passkey
GREP="/bin/grep"
CUT="/bin/cut"
OPENSSL=/usr/bin/openssl

GLOBAL_PROPERTY_FILE=/ericsson/tor/data/global.properties
source $GLOBAL_PROPERTY_FILE >/dev/null 2>&1

# database DN
DM_DN=""
DM_PWD=""

# old password is provided by first parameter of the script in encrypted form
PREVIOUS_PASS_ENC="$1"
PREVIOUS_PASS=""

# this script is performed after password change in global.properties, so new password is
# taken from global.properties file
NEW_PASS=""


###########################################################################################
# Function: LogMessage
# Description: This function creates the log file
# Parameters: String to save in log file
# Return:  none
###########################################################################################
LogMessage()
{
    local msg="$(/bin/date "+%F:%H:%M:%S%:z"): $1"
    echo $msg >> $LOG_FILE
    echo $msg
}


###########################################################################################
# Function: SetLogFile
# Description: This function creates the log file
# Parameters: LOG_FILE
# Return:  0 everything ok, 1 fail
###########################################################################################
SetLogFile()
{
    local log_file="$1"
    local log_dir="$(dirname ${log_file})"

    echo  "Log file: $log_file"

    # Create the log directory if it does not already exist
    if [ ! -d $log_dir ] ; then
        mkdir -p $log_dir
        if [ $? != 0 ] ; then
            echo "Failed to create $log_dir"
            return 1
        fi
    fi
    chown opendj:opendj $log_dir
    if [ $? != 0 ] ; then
        echo "Failed to set ownership on $log_dir"
        return 1
    fi

    # Construct the LOG_FILE name and create it and validate it can be written
    touch $log_file
    if [ $? != 0 ] ; then
        echo "Failed to create $log_file"
        return 1
    fi

    # Change permission on log file to rw to all
    chmod 666 $log_file
    if [ $? != 0 ] ; then
        echo "Failed to set permissions on $log_file"
        return 1
    fi

    # Change owner to OpenDJ
    chown opendj:opendj $log_file
    if [ $? != 0 ] ; then
        echo "Failed to change ownership of $log_file"
        return 1
    fi

    return 0
}


###########################################################################################
# Function: CheckDN
# Description: check if the Directory Manager DN is set in PROPS_FILE
# Parameters: none
# Return:  0 everything ok, 1 fail
###########################################################################################
CheckDN()
{
    # get datastore.properties settings
    DM_DN=$( ${GREP} rootUserDN ${PROPS_FILE} | ${CUT} -d= -f2- )
    if [ -z "${DM_DN}" ]; then
        LogMessage "ERROR: DM_DN is not set in ${PROPS_FILE}"
        return 1
    fi
    return 0
}


###########################################################################################
# Function: CheckPassword
# Description: Checks, if the password is defined in global.properties and it is possible
#   to encrypt it
# Parameters: a password key, a path to the passkey
# Return:  0 everything ok, 1 fail
###########################################################################################
CheckPassword()
{
    local password_key="$1"
    local passkey="$2"

    LogMessage "CheckPassword(type=${password_key}, passkey=${passkey}) request has been received. Processing request..."

    # Check if DM_DN is defined
    CheckDN
    if [ $? != 0 ] ; then
        LogMessage "ERROR: CheckDN failed"
        return 1
    fi

    # if we change password not for DM, we use the password for DM from LITP model
    local dm_pwd_enc=""

    if [ "$password_key" != "LDAP_ADMIN_PASSWORD" ]; then
        dm_pwd_enc=$LDAP_ADMIN_PASSWORD
    else
        dm_pwd_enc=$PREVIOUS_PASS_ENC
    fi

    # decrypt DM password
    DM_PWD=`echo ${dm_pwd_enc} | ${OPENSSL} enc -a -d -md md5 -aes-128-cbc -salt -kfile ${OPENDJ_DM_PASSKEY}`
    if [  ${PIPESTATUS[0]} -ne 0 ]; then
       LogMessage "ERROR: Old password encryption failed"
       return 1
    fi
    if [ -z "${DM_PWD}" ]; then
        LogMessage "ERROR: Failed to decrypt old password provided in script parameter"
        return 1
    fi

    # Check if password is stored in global.properties and the key is available
    if [ -z "${!password_key}" ]; then
        LogMessage "ERROR: ${password_key} is not set in ${GLOBAL_PROPERTY_FILE}"
        return 1
    fi
    if [ ! -r ${passkey} ]; then
        LogMessage "INFO: ${passkey} does not exist or is not readable"
        return 1
    fi

    # Decrypt the password to change
    NEW_PASS=`echo ${!password_key} | ${OPENSSL} enc -a -d -md md5 -aes-128-cbc -salt -kfile ${passkey}`
        if [ ${PIPESTATUS[0]} -ne 0 ]; then
           LogMessage "ERROR: New password encryption failed"
           return 1
        fi
        if [ -z "${NEW_PASS}" ]; then
            LogMessage "ERROR: Failed to decrypt ${password_key} from ${GLOBAL_PROPERTY_FILE}"
            return 1
        fi

    # decrypt the previous password
    PREVIOUS_PASS=`echo ${PREVIOUS_PASS_ENC} | ${OPENSSL} enc -a -d -md md5 -aes-128-cbc -salt -kfile ${passkey}`
    if [  ${PIPESTATUS[0]} -ne 0 ]; then
       LogMessage "ERROR: Old password encryption failed"
       return 1
    fi
    if [ -z "${PREVIOUS_PASS}" ]; then
        LogMessage "ERROR: Failed to decrypt old password provided in script parameter"
        return 1
    fi
    return 0
}


###########################################################################################
# Function: StorePasswordinOpenDJ
# Description: Save password for the user in the db
# Parameters: a password name, a path to the passkey
# Return:  0 everything ok, 1 fail
###########################################################################################
StorePasswordinOpenDJ()
{
    local authz_id="$1"
    local new_pass="$2"

    LogMessage "StorePasswordinOpenDJ(authz_id=${authz_id}) request has been received. Processing request..."

    if [ -z "$authz_id" ]; then
        LogMessage "ERROR: authz_id cannot be empty."
        return 1
    fi


    LogMessage "Updating password in OpenDJ"

    # Modify password in OpenDJ
    local additional_param=""
    if [ "${authz_id}" == "$DM_DN" ]; then
        additional_param="--currentPassword $DM_PWD"
    fi
    output=`${OPENDJ_ROOT}/bin/ldappasswordmodify --useSSL  --trustAll --no-prompt -h localhost -p $COM_INF_LDAP_PORT -D "$DM_DN" -w "$DM_PWD" --authzID "$authz_id" ${additional_param} --newPassword ${new_pass} 2>&1`
    rr=${PIPESTATUS[0]}

    if [ $rr -ne 0 ]; then
        LogMessage "ERROR: Failed to change password, the error is [$rr] - ${output}."
        return 1
    fi

    LogMessage "StorePasswordinOpenDJ completed successfully"
    return 0
}
