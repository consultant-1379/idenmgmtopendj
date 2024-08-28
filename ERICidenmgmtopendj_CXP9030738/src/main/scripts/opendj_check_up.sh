#/bin/bash

REPLICATION_SCRIPT=/opt/ericsson/com.ericsson.oss.security/idenmgmt/opendj/bin/config_opendj_replication.sh

#######################################
# Action :
#   check_n_opendj_is_running
# Arguments:
#   None
# Returns:
#   Service description
#       n  opendj is running
#######################################
check_n_opendj_is_running()
{


  FINDOPENDJ=`/usr/bin/curl localhost:8500/v1/catalog/services |sed 's/],/\n/g'|grep opendj-completed|sed 's/"opendj-completed"://'|sed 's/\[//'|sed 's/]//'|sed 's/"/''/g'|sed 's/,/ /g'`

  IN=`echo ${FINDOPENDJ}`

  IFS=' ' read -r -a instances <<< "$IN"

  for j in "${instances[@]}"
     do
        echo "$j"
        echo "elemento2"
     done



  num=${#instances[@]}
  echo $num

  return $num

}


echo "main"


while true
   do
      check_n_opendj_is_running
      if [ ${?} -eq 2 ]; then
           ${REPLICATION_SCRIPT}
           exit 0
      fi
      sleep 10
   done
