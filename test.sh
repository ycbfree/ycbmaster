#!/bin/bash
configfile='./config.cfg'
configfile_secured='./secure-config.cfg'

if egrep -q -v '^#|^[^ ]*=[^;]*' "$configfile"; then
	egrep '^#|^[^ ]*=[^;&]*'  "$configfile" > "$configfile_secured"
	configfile="$configfile_secured"
fi

source "$configfile"
echo "config: $TITLE"
