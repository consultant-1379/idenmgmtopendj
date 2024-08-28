#!/bin/bash

# Asumption: If opendj installation fails, it fails opendj package. 
#            If replication configuration fails, it does not fail opendj package
# Only configure replication during an install ($1 = 1)  and not during an upgrade ($1 = 2)

INSTALL_STAGE_OPTION_FILE=/opt/ericsson/com.ericsson.oss.security/idenmgmt/opendj/config/opendj-install-info.txt
prg=`basename $0`

info()
{
	logger -s -t IDENMGMT_OPENDJ -p user.notice "INFORMATION ( $prg ): $@"
}

error()
{
	logger -s -t IDENMGMT_OPENDJ -p user.err "ERROR ( ${SCRIPT_NAME} ): $@"
}

##########################################################################################
#### checkSizeForLogPolicies
####
#### This method retrieve opendj cloud partition size and modify accordingly log policies
##########################################################################################

checkSizeForLogPolicies()
{
    DEFAULT_PART_SIZE=15360
    PART_SIZE=$(df -ahP | grep "/ericsson/opendj" | awk '{ print $2 }')
    LOG_POLICY_CONF=/opt/ericsson/com.ericsson.oss.security/idenmgmt/opendj/config/opendj_log_policy.cnf
    LOG_RETENTION_TOTAL_SIZE=$(grep Log_Retention_Total_File_Size_Limit $LOG_POLICY_CONF | cut -d= -f2- )
    LOG_RETENTION_FILE_NUMBER=$(grep Log_Retention_File_Number_Limit $LOG_POLICY_CONF | cut -d= -f2 )
    LOG_ROTATION_FILE_SIZE=$(grep Log_Rotation_File_Size_Limit $LOG_POLICY_CONF | cut -d= -f2-)

    #Extract Partition size in MB
    if [[ $PART_SIZE == *"G" ]]; then
       PART_SIZE_INT=$(echo "${PART_SIZE%G*} * 1024" | bc -l)
    fi
    if [[ $PART_SIZE == *"M" ]]; then
       PART_SIZE_INT=${PART_SIZE%M*}
    fi
    #Extract Log retention total size in MB
    if [[ $LOG_RETENTION_TOTAL_SIZE == *" gb" ]]; then
       LOG_RETENTION_TOTAL_INT=$(echo "${LOG_RETENTION_TOTAL_SIZE% gb*} * 1024" | bc -l)
    fi
    if [[ $LOG_RETENTION_TOTAL_SIZE == *" mb" ]]; then
        LOG_RETENTION_TOTAL_INT=${LOG_RETENTION_TOTAL_SIZE% mb*}
    fi
    #Extract Log rotation file size in MB
    if [[ $LOG_ROTATION_FILE_SIZE == *" mb" ]]; then
        LOG_ROTATION_FILE_SIZE_INT=${LOG_ROTATION_FILE_SIZE% mb*}
    fi
    
    #Basic dimensioning
    NEW_LOG_RETENTION_TOT=$(echo "$PART_SIZE_INT * $LOG_RETENTION_TOTAL_INT / $DEFAULT_PART_SIZE" | bc -l | awk '{printf("%d\n",$1 + 0.5)}')
    NEW_LOG_RETENTION_FILE_NUM=$(echo "$PART_SIZE_INT * $LOG_RETENTION_FILE_NUMBER * 3 / $DEFAULT_PART_SIZE" | bc -l | awk '{printf("%d\n",$1 + 0.5)}')
    NEW_LOG_ROTATION_FILE_SIZE=$(echo "$PART_SIZE_INT * $LOG_ROTATION_FILE_SIZE_INT / $DEFAULT_PART_SIZE" | bc -l | awk '{printf("%d\n",$1 + 0.5)}')

    echo $NEW_LOG_RETENTION_TOT
    echo $NEW_LOG_RETENTION_FILE_NUM
    echo $NEW_LOG_ROTATION_FILE_SIZE
    whereis bc


    #Substituting values in cnf file
    sed -i "s/Log_Retention_Total_File_Size_Limit=$LOG_RETENTION_TOTAL_SIZE/Log_Retention_Total_File_Size_Limit=$NEW_LOG_RETENTION_TOT mb/g" $LOG_POLICY_CONF
    sed -i "s/Log_Retention_File_Number_Limit=$LOG_RETENTION_FILE_NUMBER/Log_Retention_File_Number_Limit=$NEW_LOG_RETENTION_FILE_NUM/g" $LOG_POLICY_CONF
    sed -i "s/Log_Rotation_File_Size_Limit=$LOG_ROTATION_FILE_SIZE/Log_Rotation_File_Size_Limit=$NEW_LOG_ROTATION_FILE_SIZE mb/g" $LOG_POLICY_CONF

}

##############################################################################################
#### configInotifyMaxFileWatches
####
#### This method config through sysctl the max number of files to be monitored by inotify tool
##############################################################################################
configInotifyMaxFileWatches() {

    if [ $(cat /proc/sys/fs/inotify/max_user_watches) -lt 524288 ] ; then
            sysctl -q -w fs.inotify.max_user_watches=524288
    fi

}

#main

ENVIRONMENT=kvm
LMS_HOSTNAME="ms-1"
RHEL7_UPGRADE_PATH_EXPECTED_VALUE="rh7_uplift_opendj"
RH7_UPLIFT_OPENDJ=`/usr/bin/curl -s http://$LMS_HOSTNAME:8500/v1/kv/rh7_uplift_opendj --connect-timeout 5 | grep -om1 "rh7_uplift_opendj"`

info "Post Install script beginning"
GLOBAL_PROPERTIES=/ericsson/tor/data/global.properties

if [ -f "$GLOBAL_PROPERTIES" ] && [ "$cENM_DEPLOYMENT" != TRUE ] ; then
      # we need DDC_ON_CLOUD
      source ${GLOBAL_PROPERTIES}  2>/dev/null
fi

if [ "${DDC_ON_CLOUD}" == TRUE ] || [ "${cENM_DEPLOYMENT}" == TRUE ] ; then
  # on CLOUD
  if [ -f /ericsson/opendj/opendj/config/keystore ]; then
      #insert 2=upgrade on INSTALL_STAGE_OPTION_FILE
      echo 2 > $INSTALL_STAGE_OPTION_FILE
  else
      #insert 1=install on INSTALL_STAGE_OPTION_FILE
      echo 1 > $INSTALL_STAGE_OPTION_FILE
  fi
  if [ "${DDC_ON_CLOUD}" == TRUE ]; then
     #in cENM usecase default pENM size for log is mantained
     checkSizeForLogPolicies
  fi
else
    if [ "${RH7_UPLIFT_OPENDJ}" == "${RHEL7_UPGRADE_PATH_EXPECTED_VALUE}" ]; then
        echo 1 > $INSTALL_STAGE_OPTION_FILE
    else
     # on PHYSICAL or VAPP
     # check if we're installing or upgrading
     # write the value of the argument passed by RPM to the scriptlets
        echo "${1}" > $INSTALL_STAGE_OPTION_FILE
    fi
fi

if [ "$cENM_DEPLOYMENT" != TRUE ] ; then
configInotifyMaxFileWatches
fi

info "Post Install script end"

exit 0;
