#!/bin/bash

# Check in cloud the presence of end_installation file
# if it is not present then opendj directory is removed and then
# VM is restarted killing the consul process
if [ -f /ericsson/opendj/opendj/setup ]; then
    # installation was started
    if [ -d /ericsson/opendj/opendj/end_installation ]; then
        exit 0
    else
        # NOTE. fault condition. An upgrade or installation did not finish correctly:
        # - config.ldif.startok has size 0
        # - admin-backend.ldif and/or admin-backend.ldif.old have size 0
        # - end_installation file not present
        # - changelogDb file may have size 0
        rm -rf /ericsson/opendj/opendj
        pkill consul
        exit 1
    fi
else
    exit 0
fi