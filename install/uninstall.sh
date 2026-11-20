#!/bin/sh
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
# Remove the Web Application Firewall plugin: its Apache stopped, its files, its place in the menu and
# among the services, the page as PHP compiled it, and everything it wrote - Apache's configuration and
# the sites' certificates exported for it, the Core Rule Set installed, its logs, what it last did. It
# changes nothing on the firewall but what it laid down: no rule, no table, no interface, the web GUI as
# it was. Kept: the settings in config.xml, and OPNsense's packages apache24 and ap24-mod_security unless
# install/install.sh installed them and no other package needs them - then they go too, as os-appcontrol's
# ndpi does; the packages they brought with them stay (pkg autoremove takes away those nothing needs).

# which of the two packages install/install.sh installed, read before its folder goes
OURS=
[ -f /usr/local/share/os-modsecurity/packages-installed ] && OURS=$(cat /usr/local/share/os-modsecurity/packages-installed)

# Apache first, while the rc script that stops it is there
/usr/local/etc/rc.d/modsecurity onestop > /dev/null 2>&1 || true
# an Apache of this plugin the rc script did not find; the brackets keep the pattern from matching a
# shell that carries this text, and the package's own apache24 runs another configuration
/bin/pkill -f 'httpd -f /usr/local/etc/[o]s-modsecurity/' 2> /dev/null || true

# the hook, the rc script, the cron entry and the actions, then everything else src/ lays down
rm -f /usr/local/etc/inc/plugins.inc.d/modsecurity.inc
rm -f /usr/local/etc/rc.d/modsecurity
rm -f /usr/local/etc/cron.d/modsecurity
rm -f /usr/local/opnsense/service/conf/actions.d/actions_modsecurity.conf
rm -rf /usr/local/opnsense/service/templates/OPNsense/ModSecurity
rm -rf /usr/local/opnsense/scripts/modsecurity
# the menu file place-menu.sh wrote, which is not one of src/'s files
rm -f /usr/local/opnsense/mvc/app/models/OPNsense/ModSecurity/Menu/Menu.xml
rmdir /usr/local/opnsense/mvc/app/models/OPNsense/ModSecurity/Menu 2>/dev/null || true
rm -rf /usr/local/opnsense/mvc/app/models/OPNsense/ModSecurity
rm -rf /usr/local/opnsense/mvc/app/controllers/OPNsense/ModSecurity
rm -rf /usr/local/opnsense/mvc/app/views/OPNsense/ModSecurity
rm -rf /usr/local/opnsense/mvc/app/library/OPNsense/ModSecurity
rm -rf /usr/local/share/os-modsecurity
# what it wrote: Apache's configuration, the certificates, the Core Rule Set; its logs; ModSecurity's work
# files; what it last did; Apache's runtime files and pid file
rm -rf /usr/local/etc/os-modsecurity
rm -rf /var/log/modsecurity
rm -rf /var/tmp/os-modsecurity
rm -rf /var/db/os-modsecurity
rm -rf /var/run/modsecurity
rm -f /var/run/modsecurity.pid
service configd restart > /dev/null
# PHP keeps them in its own temporary directory on 26.7 (/var/lib/php/tmp); /tmp is where they were.
# And the page as PHP compiled it.
rm -f /var/lib/php/tmp/opnsense_menu_cache.xml /var/lib/php/tmp/opnsense_acl_cache.json \
    /tmp/opnsense_menu_cache.xml /tmp/opnsense_acl_cache.json
find /var/lib/php/cache -maxdepth 1 -iname '*_views_opnsense_modsecurity_*' -delete 2> /dev/null || true

# the packages install/install.sh installed, ModSecurity's module before the Apache it needs, each only
# when no other package needs it
KEPT=
# (a package already gone is neither; a query pkg could not answer keeps it, as pkg delete would take
# every package needing it along)
for p in ap24-mod_security apache24; do
    pkg info -e "$p" > /dev/null 2>&1 || continue
    case " ${OURS} " in
    *" $p "*)
        if NEEDS=$(pkg query '%rn' "$p" 2> /dev/null) && [ -z "${NEEDS}" ] && pkg delete -y "$p" > /dev/null 2>&1; then
            echo "The package $p, which install/install.sh installed, removed."
        else
            KEPT="${KEPT} $p"
        fi
        ;;
    *) KEPT="${KEPT} $p" ;;
    esac
done
if [ -n "${KEPT}" ]; then
    echo "Web Application Firewall removed; its settings stay in config.xml, and these packages stay installed:${KEPT}"
else
    echo "Web Application Firewall removed; its settings stay in config.xml"
fi
