function usage {
	echo 'Usage: bash getdns.sh <outfile>'
	exit 1
}

test -z "$1" && usage
outfile="$1"

rm "$outfile" 2>/dev/null

SIFS="$IFS"
IFS='
'
TAB=$(echo -en '\t')

for line in $(./PsList.exe); do
	st=$(echo $line | cut -d"$TAB" -f1-7)
	
	en=$(echo $line | cut -d"$TAB" -f8)
	newen=$(echo $en | tr '|' '\n' | sort | uniq | egrep -v '^$' | tr "\\n" "|")
	echo $st$TAB$newen>>"$outfile"
done

IFS="$SIFS"