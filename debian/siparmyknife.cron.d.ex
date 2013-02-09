#
# Regular cron jobs for the siparmyknife package
#
0 4	* * *	root	[ -x /usr/bin/siparmyknife_maintenance ] && /usr/bin/siparmyknife_maintenance
