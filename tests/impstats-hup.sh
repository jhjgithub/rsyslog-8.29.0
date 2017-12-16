#!/bin/bash
# test if HUP works for impstats
# This file is part of the rsyslog project, released under ASL 2.0
. $srcdir/diag.sh init
. $srcdir/diag.sh generate-conf
. $srcdir/diag.sh add-conf '
module(load="../plugins/impstats/.libs/impstats"
	log.file="./rsyslog.out.log"
	interval="1" ruleset="stats")

ruleset(name="stats") {
	stop # nothing to do here
}
'
. $srcdir/diag.sh startup
./msleep 2000
mv rsyslog.out.log rsyslog2.out.log
. $srcdir/diag.sh issue-HUP
./msleep 2000
. $srcdir/diag.sh shutdown-when-empty
. $srcdir/diag.sh wait-shutdown
echo checking pre-HUP file
. $srcdir/diag.sh content-check 'global: origin=dynstats' rsyslog2.out.log
echo checking post-HUP file
. $srcdir/diag.sh content-check 'global: origin=dynstats' rsyslog.out.log
. $srcdir/diag.sh exit
