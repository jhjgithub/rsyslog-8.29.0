#!/bin/bash
# addd 2016-07-11 by RGerhards, released under ASL 2.0

. $srcdir/diag.sh init
. $srcdir/diag.sh generate-conf
. $srcdir/diag.sh add-conf '
module(load="../plugins/imtcp/.libs/imtcp")
input(type="imtcp" port="13514")
template(name="outfmt" type="string" string="%hostname%\n")

parser(name="pmrfc3164.hostname_with_slashes" type="pmrfc3164" permit.slashesinhostname="on")
$rulesetparser pmrfc3164.hostname_with_slashes
local4.debug action(type="omfile" template="outfmt" file="rsyslog.out.log")
'
. $srcdir/diag.sh startup
echo '<167>Mar  6 16:57:54 hostname1/hostname2 test: msgnum:0' > rsyslog.input
. $srcdir/diag.sh tcpflood -B -I rsyslog.input
. $srcdir/diag.sh shutdown-when-empty
. $srcdir/diag.sh wait-shutdown
echo "hostname1/hostname2" | cmp rsyslog.out.log
if [ ! $? -eq 0 ]; then
  echo "invalid hostname generated, rsyslog.out.log is:"
  cat rsyslog.out.log
  . $srcdir/diag.sh error-exit 1
fi;
. $srcdir/diag.sh exit
