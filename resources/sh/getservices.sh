#!/bin/bash

function usage {
	echo 'Usage: bash getsvc.sh <outfile>'
	exit 1
}

test -z "$1" && usage
outfile="$1"
TAB=$(printf '\t')

SIFS="$IFS"
IFS='
'

SERVICE_UID=0
for SERVICE_name in `sc query state= all | egrep '^SERVICE_NAME' | cut -d' ' -f2- `; do 
	sc query "$SERVICE_name" > svc_query.tmp
	sc qc "$SERVICE_name" 4096 > svc_qc.tmp
	
	SERVICE_descriptiveName=$(cat svc_qc.tmp | egrep 'DISPLAY_NAME' | cut -d':' -f2- | bash trim.sh)
	SERVICE_mode=$(cat svc_qc.tmp | egrep 'START_TYPE' | cut -d':' -f2 | bash trim.sh | cut -d' ' -f1)
	SERVICE_path=$(cat svc_qc.tmp | egrep 'BINARY_PATH' | cut -d':' -f2- | bash trim.sh)
	SERVICE_binary_name=$(echo $SERVICE_path | cut -d'"' -f2)
	SERVICE_pathmd5sum=$(md5sum -N -L $SERVICE_binary_name 2> /dev/null)
	

	# Multiple attempts to get the md5 checksum
	if test -z "$SERVICE_pathmd5sum"; then
		SERVICE_pathmd5sum=$(md5sum -N -L "$SERVICE_binary_name" 2> /dev/null)
	fi
	
	if test -z "$SERVICE_pathmd5sum"; then
		tmp=$(echo SERVICE_binary_name | sed -r 's/^(.+) -.+$/\1/g')
		SERVICE_pathmd5sum=$(md5sum -N -L "$tmp" 2> /dev/null)
	fi
	
	if test -z "$SERVICE_pathmd5sum"; then
		SERVICE_pathmd5sum='00000000000000000000000000000000'
	fi
	
	SERVICE_status=$(cat svc_query.tmp | egrep 'STATE' | cut -d':' -f2 | bash trim.sh | cut -d' ' -f1)

	echo "$SERVICE_UID"X"$TAB$SERVICE_descriptiveName$TAB$SERVICE_mode$TAB$SERVICE_path$TAB$SERVICE_pathmd5sum$TAB$SERVICE_status$TAB$SERVICE_name" >> $outfile

	SERVICE_UID=$(($SERVICE_UID+1))
done

IFS="$SIFS"

rm svc_query.tmp svc_qc.tmp