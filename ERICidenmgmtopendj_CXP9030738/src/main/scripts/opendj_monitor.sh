#!/bin/bash

#######################################
#
#  Simple monitor script called by VCS to monitor service health
#  This script emulates the  status function but allows us the scope to make it more
#  extensive in the future
#
#######################################

# global properties that are either required by SSO or defined in the SED.
LOGGER_TAG="OPENDJ_MONITOR"
IDENMGMT_ROOT=/opt/ericsson/com.ericsson.oss.security/idenmgmt
GREP='/bin/grep -w'
EGREP=/bin/egrep
ECHO=/bin/echo
AWK=/bin/awk
TAIL=/usr/bin/tail
CUT=/bin/cut
CAT=/bin/cat
MV=/bin/mv
WC='/usr/bin/wc'
ROOTCA_CERT=/ericsson/tor/data/certificates/rootCA.pem
CURL=/usr/bin/curl
DB_HOSTNAME=`hostname -i`

UNWILLINGCNTFILE="ldapnoresponse.cnt"
UNWILLINGMAXRETRY=3
UNAVAILABLERETCODE=52
UNWILLINGRETCODE=53
OTHERRETCODE=80
UNWILLINGTIMEOUT=5
UNWILLINGTIMEOUTCODE=124

MON_REPL_THRESHOLD=90
MON_REPL_RETRY=3
MON_REPL_LOGDIR="/var/log/opendj"
#MON_REPL_LOGFILE="opendj-check*.log"
MON_REPL_CNTFILE="monitorreplication.cnt"
#MON_REPL_TEST="grep 'monitor_replication' /var/log/messages | grep 'OK' | tail -n 1 | awk '{print $15}'"


# optional parameter to mute the output (when its called by service status)
MUTE=false
if [ ! -z "$1" ] ; then
   if [ "$1" == "mute" ] ; then
      MUTE=true
   fi
fi


info()
{
    #echo "$@"
    logger -s -t IDENMGMT_OPENDJ -p user.notice "INFORMATION ( ${LOGGER_TAG} ): $@"
}

error()
{
    #echo "$@"
    logger -s -t IDENMGMT_OPENDJ -p user.err "ERROR ( ${LOGGER_TAG} ): $@"
}



#######################################
# Action :
#   opendjStatus
# Arguments:
#   None
# Returns:
#   Return code of service status function
#######################################
opendjStatus()
{
  #statusCommand="status"
  statusCommand="check"
  if [ $(/sbin/pidof systemd) ] ; then
    /bin/systemctl $statusCommand opendj
    return $?
  elif [ $(/sbin/pidof init) ] ; then
    /sbin/service opendj $statusCommand 
    return $?
  elif [ -f /etc/init.d/opendj ]; then
    /etc/init.d/opendj $statusCommand
  else
    echo "Error: Failed to find any services system."
    return $1
  fi
}


#######################################
# Action :
#   opendjUnwillingStatus
# Arguments:
#   None
# Returns:
#   Return code of service status function
#       1:  unwilling status after UNWILLINGMAXRETRY 
#           (actually error codes 52, 53, 80 are checked)
#       0:  status ok (even for TIMEOUT)
#######################################
opendjUnwillingStatus()
{

   if [ $MUTE == false ]; then
       info "Running opendjUnwillingStatus procedure ....."
   fi
   iniTime=`date +%s%3N`
   timeout $UNWILLINGTIMEOUT $LDAPSEARCH -p 1636 --useSSL --trustAll -b "" "(uid=ssouser)" > /dev/null
   respCode=${?}
   endTime=`date +%s%3N`
   if [ $MUTE == false ]; then
       info "opendjUnwillingStatus LDAPSEARCH time: $((endTime - iniTime)) msec - code: $respCode"
   fi
   if [ $respCode -eq $UNWILLINGRETCODE ] || [ $respCode -eq $UNAVAILABLERETCODE ] || [ $respCode -eq $OTHERRETCODE ]; then
      no=0
      if [ -f ${OPENDJ_ROOT}/$UNWILLINGCNTFILE ]; then
         no=$($CAT ${OPENDJ_ROOT}/$UNWILLINGCNTFILE )
      fi
      no=$(($no + 1))
      $ECHO $no > ${OPENDJ_ROOT}/$UNWILLINGCNTFILE
      if [ $MUTE == false ]; then
          info "opendjUnwillingStatus procedure NOT OK: $no , retCode: $respCode"
      fi
      if [ $no -gt $UNWILLINGMAXRETRY ]; then 
         #rm -f ${OPENDJ_ROOT}/ldapnoresponse.cnt
         return 1    #opendj is not working properly on port 1636 expected code error 53 unwilling 
                            #UNWILLINGMAXRETRY done
      else
         return 0    #opendj is not working properly on port 1636 expected code error 53 unwilling 
                            #UNWILLINGMAXRETRY NOT done
                                             
      fi
   else  
      if [ -f ${OPENDJ_ROOT}/$UNWILLINGCNTFILE ]; then
         rm -f ${OPENDJ_ROOT}/$UNWILLINGCNTFILE
      fi
      if [ $MUTE == false ]; then
          info "opendjUnwillingStatus procedure OK"
      fi
      return 0   #opendj is working properly
  fi

}




#######################################
# Action :
#   opendjReplicationTime
# Arguments:
#   None
# Returns:
#   Return code of service status function
#       1:  monitor replication exceed timeout
#       0:  status ok
#######################################
opendjReplicationTime()
{
   if [ $MUTE == false ]; then
       info "Running opendjReplicationTime procedure ....."
   fi

   if [ -f $MON_REPL_LOGDIR/$MON_REPL_CNTFILE ]; then

      # look last elapsed time if they exceed threshold
      elapsedTimes=$($CAT $MON_REPL_LOGDIR/$MON_REPL_CNTFILE | $TAIL -n $MON_REPL_RETRY | $AWK '{print $3}')

      declare -a elapsedTimes_array
      local IFS=' ' elapsedTimes_array=($elapsedTimes)

      no=0
      for element in "${elapsedTimes_array[@]}"
        do 
           if [ "$element" -gt "$MON_REPL_THRESHOLD" ]; then
                no=$(($no + 1))
                if [ $MUTE == false ]; then
                   info "Monitor Replication exceed time : $element sec."
               fi
           fi
        done 

      if [ $MUTE == false ]; then
         info "Last Monitor Replication elapsed time : ${elapsedTimes_array[@]:(-1)} sec."
      fi

      if [ "$no" -eq "$MON_REPL_RETRY" ]; then
         return 1
      fi

   else
      if [ $MUTE == false ]; then
          info "no replication log present"
      fi   
   fi

   if [ $MUTE == false ]; then
      info "opendjReplicationTime procedure OK"
   fi
   return 0
}


#######################################
# Action :
#   monitor
# Arguments:
#   None
# Returns:
#   0 Resource is running
#   1 Resource is in failed state
#   7 Resource is stopped
#######################################
monitor()
{
#Setting INSTALL_ROOT for service opendj status without using global.properties
if [ -f /ericsson/opendj/opendj/setup ]; then
      OPENDJ_ROOT=/ericsson/opendj/opendj
else
    if [ -f /opt/opendj/setup ]; then
      OPENDJ_ROOT=/opt/opendj
    else
      error "setup file not found."
      return 1
    fi
fi  
export OPENDJ_ROOT
LDAPSEARCH=$OPENDJ_ROOT/bin/ldapsearch


#During backup the monitor exit with success (return 0)BACKUP_DIR/backup.lock

if [ -f ${OPENDJ_ROOT}/bklock.lock ]; then
     return 0 
fi


opendjStatus
RETCODE=$?
if [ ${RETCODE} -eq 3 ] ; then
  error "Resource is stopped."
  return 7
elif [ ${RETCODE} -eq 5 ] ; then
 info "Disk space is full"
 return 0
elif [ ${RETCODE} -ne 0 ] ; then
 error "Resource is in failed state."
 return 1
fi

opendjUnwillingStatus
RETCODE=$?
if [ ${RETCODE} -eq 1 ] ; then
      error "Opendj unwilling status"
      return 1
fi

#TORF-2236368: removed because the search is too big.
#$LDAPSEARCH -p 1636 --useSSL --trustAll -b "" "(objectclass=*)" > /dev/null
#if [ ${?} -ne 0 ] ; then
 #return 1
#fi


# check elapsed time for replication
opendjReplicationTime
RETCODE=$?
if [ ${RETCODE} -eq 1 ] ; then
      error "Monitor Replication exceed time"
      return 1
fi
     

#For Cloud check the presence of end_installation file
if [ -f /ericsson/opendj/opendj/setup ]; then
   if [ -d /ericsson/opendj/opendj/end_installation ]; then
       return 0
   else
       error "end_installation file not present."
       return 1
   fi
else
       return 0
fi

}


#######################################
#
#  main
#
#######################################
monitor

exit $?


