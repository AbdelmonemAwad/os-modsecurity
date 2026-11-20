#!/bin/sh
# Copyright (C) 2026 Abdelmonem Awad <eg2@live.com>. BSD 2-Clause License.
#
# Run by pkg(8) after the files of os-modsecurity are in place, on install and on upgrade alike, with
# apache24 and ap24-mod_security installed before it (PLUGIN_DEPENDS). tools/make-package.sh inlines it
# into the package manifest. The first blocks and the registration are what every OPNsense plugin runs;
# the chmod lines and syntax checks of install/install.sh are not repeated, for the reasons os-netreport's
# post-install gives.

if [ -f /usr/local/etc/rc.d/configd ]; then
	/usr/local/etc/rc.d/configd restart
fi

install -d -o root -g wheel -m 0755 /usr/local/etc/os-modsecurity /usr/local/etc/os-modsecurity/crs
install -d -o root -g wheel -m 0700 /usr/local/etc/os-modsecurity/certs
install -d -o root -g wheel -m 0750 /var/db/os-modsecurity /var/log/modsecurity

if [ -f /usr/local/opnsense/mvc/script/run_migrations.php ]; then
	/usr/local/opnsense/mvc/script/run_migrations.php OPNsense/ModSecurity
fi

if [ -x /usr/local/opnsense/scripts/firmware/register.php ]; then
	/usr/local/opnsense/scripts/firmware/register.php install os-modsecurity > /dev/null 2>&1 || true
fi

if [ -f /usr/local/etc/rc.configure_plugins ]; then
	echo "Reloading plugin configuration"
	/usr/local/etc/rc.configure_plugins POST_INSTALL
fi

# The page's place in the menu: the XGS section where os-xgs-npu is installed, Services where it is not.
# The menu file is not one of the package's files; place-menu.sh writes it and says which it chose.
WHERE=
if [ -x /usr/local/opnsense/scripts/modsecurity/place-menu.sh ]; then
	WHERE=$(/usr/local/opnsense/scripts/modsecurity/place-menu.sh) || WHERE=
fi

# The page as PHP compiled it, so an upgrade is shown at once.
find /var/lib/php/cache -maxdepth 1 -iname '*_views_opnsense_modsecurity_*' -delete 2> /dev/null || true

# As install/install.sh does it: off by default, so on a first install Apache is only asked to stop; on an
# upgrade with the plugin on, an Apply writes the configuration again with the new code and reloads Apache.
STATE=
if [ -f /usr/local/sbin/configctl ]; then
	if /usr/local/bin/python3 /usr/local/opnsense/scripts/modsecurity/setup.py enabled 2> /dev/null | grep -q '"enabled": true'; then
		/usr/local/sbin/configctl modsecurity apply > /dev/null 2>&1 || true
		STATE=" (on: Apply ran)"
	else
		/usr/local/sbin/configctl modsecurity stop > /dev/null 2>&1 || true
		STATE=" (off until it is turned on in Settings)"
	fi
fi

case "${WHERE}" in
xgs)	echo "Web Application Firewall installed: the page is at XGS > Web Application Firewall${STATE}" ;;
own)	echo "Web Application Firewall installed: the page is at Services > Web Application Firewall${STATE}" ;;
*)	echo "Web Application Firewall installed${STATE}; its menu file was not written: run /usr/local/opnsense/scripts/modsecurity/place-menu.sh" ;;
esac
