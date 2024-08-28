#!/bin/bash

#
# Script to ensure an opendj POSIX user exists before OpenDJ is installed
#

OPENDJ_USER=opendj

# Create a variables file to hold opendj SERVICE_INSTANCE_NAME instead of using /etc/init.d/functions
if [ "$cENM_DEPLOYMENT" != TRUE ] ; then
touch /opt/ericsson/com.ericsson.oss.security/idenmgmt/opendj/variables
fi

id -g ${OPENDJ_USER} 2>/dev/null >/dev/null
if [ $? -ne 0 ]; then
    echo "Adding group '${OPENDJ_USER}'"
    groupadd -g 502 ${OPENDJ_USER}
fi

if ! getent shadow ${OPENDJ_USER} > /dev/null 2>&1; then
    echo "Adding user '${OPENDJ_USER}'"
    useradd -u 502 -g 502 ${OPENDJ_USER}
fi

exit 0
