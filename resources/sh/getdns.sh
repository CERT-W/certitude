function usage {
	echo 'Usage: bash getdns.sh <outfile>'
	exit 1
}

test -z "$1" && usage
outfile="$1"

rm "$outfile" 2>/dev/null

SIFS=$IFS
IFS='
'

previous=""
domain=""
c=0
uid=1

for line in $( ipconfig /displaydns | ./tail -n +3 | bash trim.sh); do

	if test "$line" "=" "----------------------------------------"; then
		domain="$previous"
		c=0
	else
	
		if test $c -eq 6; then
			#echo -e "$uid\t$domain\t$RecordName\t$RecordType\t$TimeToLive\t$DataLength\t$RecordData_Host\t$RecordData_IPv4Address" >> "$outfile"
			echo -e "$uid\t$RecordName\t$RecordType\t$TimeToLive\t$DataLength\t$RecordData_Host\t$RecordData_IPv4Address" >> "$outfile"
			c=0
			uid=$(($uid+1))
		fi
	
		if test $c -eq 0; then
			RecordName=$(echo $line | cut -d':' -f2 | bash trim.sh)
		fi
		
		if test $c -eq 1; then
			RecordType=$(echo $line | cut -d':' -f2 | bash trim.sh)
		fi
		
		if test $c -eq 2; then
			TimeToLive=$(echo $line | cut -d':' -f2 | bash trim.sh)
		fi
		
		if test $c -eq 3; then
			DataLength=$(echo $line | cut -d':' -f2 | bash trim.sh)
		fi
		
		if test $c -eq 5; then
			tmp=$(echo $line | cut -d':' -f2 | bash trim.sh)
			tmp_test=$(echo $tmp | egrep '^(25[0-5]|2[0-4][0-9]|[1-9][0-9]{2}|[1-9][0-9]|[0-9]\.){3}25[0-5]|2[0-4][0-9]|[1-9][0-9]{2}|[1-9][0-9]|[0-9]$')
			if test -z "$tmp_test"; then
				RecordData_Host="$tmp";
				RecordData_IPv4Address="-"
			else
				RecordData_Host="-";
				RecordData_IPv4Address="$tmp"
			fi
		fi
		
		
		
		c=$(($c+1))
	fi
	
	
	
	previous="$line"
	
done
