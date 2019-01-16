#!/bin/sh

SERVER=192.5.5.241

OUTFILE=/usr/local/etc/root.zone
TMPFILE=${OUTFILE}.$$

if [ -f ${OUTFILE} ]; then
	FILE_SOA=$(/usr/bin/awk '/^.\s/ { if ($4 == "SOA") { print $7; exit } }' ${OUTFILE} )
	ROOT_SOA=$(/usr/bin/dig +short @${SERVER} . SOA | awk '{ print $3 }' )
	
	if [ x${FILE_SOA} == x${ROOT_SOA} ]; then
		exit
	fi
fi

/usr/bin/dig +nocmd +nostats +nocomments @${SERVER} . axfr > ${TMPFILE}
/bin/mv ${TMPFILE} ${OUTFILE}
