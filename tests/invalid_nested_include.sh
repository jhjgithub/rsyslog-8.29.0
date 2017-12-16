#!/bin/bash
# Note: this test tests if we die when recursively include the same
# file ever again. This is a user error, but we should detect it.
# This file is part of the rsyslog project, released  under ASL 2.0
. $srcdir/diag.sh init
. $srcdir/diag.sh generate-conf
echo '$IncludeConfig work-nested.conf
' > work-nested.conf
. $srcdir/diag.sh add-conf '
$IncludeConfig work-nested.conf
template(name="outfmt" type="string" string="%msg%\n")
if $msg contains "error" then
	action(type="omfile" template="outfmt" file="rsyslog.out.log")
'
. $srcdir/diag.sh startup
. $srcdir/diag.sh shutdown-when-empty
grep work-nested.conf rsyslog.out.log
if [ $? -ne 0 ]; then
	echo "FAIL: rsyslog.out.log does not contain expected error message on"
	echo "recursive include file work-nested.conf."
	echo "content is:"
	echo "......................................................................"
	cat rsyslog.out.log
	echo "......................................................................"
	. $srcdir/diag.sh error-exit
fi
. $srcdir/diag.sh exit
