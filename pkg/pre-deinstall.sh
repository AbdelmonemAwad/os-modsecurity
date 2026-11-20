#!/bin/sh
# Copyright (C) 2026 Abdelmonem Awad <eg2@live.com>. BSD 2-Clause License.
#
# Run by pkg(8) before the files of os-modsecurity are removed. The rc script that stops the plugin's
# Apache is a packaged file: by post-deinstall it is gone. So Apache is stopped here.
#
# pkg runs the old package's pre-deinstall in an upgrade too, where nothing is to go: Apache goes on, and
# the new package's post-install applies again with the new code. PKG_UPGRADE is set in that case and no
# other.
if [ -n "${PKG_UPGRADE}" ]; then
	exit 0
fi

if [ -x /usr/local/etc/rc.d/modsecurity ]; then
	/usr/local/etc/rc.d/modsecurity onestop > /dev/null 2>&1 || true
fi
# an Apache of this plugin the rc script did not find; the brackets keep the pattern from matching the
# shell that runs this text, and the package's own apache24 runs another configuration
/bin/pkill -f 'httpd -f /usr/local/etc/[o]s-modsecurity/' 2> /dev/null || true
