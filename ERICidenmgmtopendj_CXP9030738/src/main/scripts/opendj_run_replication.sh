#/bin/bash

consul lock -try 1ns lock_replication /ericsson/opendj/opendj/bin/opendj_check_up.sh
