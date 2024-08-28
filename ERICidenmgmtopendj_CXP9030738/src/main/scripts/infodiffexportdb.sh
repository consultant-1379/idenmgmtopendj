#!/bin/bash

if [[ ( "$#" -ne 2 ) ]] ; then
    echo "Script $0 requires two ldif files produced via export-ldif."
else
    echo "Script $0 is running on $1."
    DN1=($(grep -i "^dn: " $1 | sed "s|dn: ||" | sed "s| |+|g"))
    DN2=($(grep -i "^dn: " $2 | sed "s|dn: ||" | sed "s| |+|g"))
    TMP1=$1".csv"
    TMP2=$2".csv"
    export found=0
    echo "DN Objects present only in $2;createTimestamp;modifyTimestamp" > $TMP1
    for ((i = 0; i < ${#DN1[@]}; i++)); do
       found=0
       for ((k = 0; k < ${#DN2[@]}; k++)); do
          if [ "${DN1[$i]}" = "${DN2[$k]}" ]; then
             found=1
             break
          fi
       done
       if [[ ( "$found" == 0 ) ]]; then
          out=$(echo "${DN1[$i]}" | sed "s|+| |g")
          grep '^dn:\|^createTimestamp\|^modifyTimestamp' $1 | grep -A2 "${out}" | sed "s|dn: ||" | awk -F: -v OFS=";" '{if (NR%3==1) printf "%s%s",$1,$2 OFS;
                   else printf "%s", $2 (NR%3?OFS:ORS)}' >> $TMP1
       fi
    done
    echo "End of parsing of $1: see results in $TMP1 ."
    echo "Script $0 is running on $2."
    echo
    echo "DN Objects present only in $2;createTimestamp;modifyTimestamp" > $TMP2
    for ((i = 0; i < ${#DN2[@]}; i++)); do
       found=0
       for ((k = 0; k < ${#DN1[@]}; k++)); do
          if [ "${DN2[$i]}" = "${DN1[$k]}" ]; then
             found=1
             break
          fi
       done
       if [[ ( "$found" == 0 ) ]]; then
          out=$(echo "${DN2[$i]}" | sed "s|+| |g")
          grep '^dn:\|^createTimestamp\|^modifyTimestamp' $2 | grep -A2 "${out}" | sed "s|dn: ||" | awk -F: -v OFS=";" '{if (NR%3==1) printf "%s%s",$1,$2 OFS;
                   else printf "%s", $2 (NR%3?OFS:ORS)}' >> $TMP2
       fi
    done
    echo "End of parsing of $1 : see results in $TMP2 ."
    echo "Script $0 has finished."
    echo
fi
