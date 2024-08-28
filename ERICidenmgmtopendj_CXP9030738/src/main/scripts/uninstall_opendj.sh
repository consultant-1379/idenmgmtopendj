#/bin/ksh
################################################################################
# Copyright (c) 2014 Ericsson, Inc. All Rights Reserved.
# This script installs the OpenDJ directory server
# Author: Simohamed Elmajdoubi
# ESN 38708
#
###############################################################################

GREP=/bin/grep
CUT=/bin/cut
CAT=/bin/cat
DATENOW=$(/bin/date +"%Y-%m-%d-%H:%M")
LOG_DIR="/var/log/opendj"
LOG_FILE="$LOG_DIR/uninstall-opendj-${DATENOW}.log"

BACKUP_DIR="/ericsson/tor/data"
BACKUP_FILE="/ericsson/tor/data/opendj-backup.tar"
# deployment paths
IDENMGMT_ROOT=/opt/ericsson/com.ericsson.oss.security/idenmgmt

####################################################################
##                             Main program                       ##
####################################################################
source $IDENMGMT_ROOT/opendj/bin/common.sh
if [ $? -ne 0 ]; then
   echo "ERROR: Failed to source $IDENMGMT_ROOT/opendj/bin/common.sh"
   exit 1
fi


SetLogFile $LOG_DIR $LOG_FILE
if [ $? -ne 0 ]; then
   echo "ERROR: SetLogFile failed"
   exit 1
fi
LogMessage "Opendj uninstallation started..."

ShutdownOpendj
if [ $? -ne  0 ] ; then
   LogMessage "ERROR: ShutdownOpendj failed."
   exit 1
fi

exit 0
