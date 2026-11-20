<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * The Web Application Firewall as one of the firewall's services, its start at boot, and its addresses
 * followed. Its logs are kept no longer than OPNsense keeps its own by its cron.d entry (setup.py prune).
 *
 * OPNsense starts a plugin's daemons from rc.bootup through plugins_configure('bootup'), which calls the
 * 'bootup' tasks a plugin returns from its _configure() - an rc.conf.d switch alone is read by nothing at
 * boot (os-fanctl, measured on two appliances). So the start is here, guarded by the one setting that
 * decides it: enabled, off by default. It is an Apply (setup.py), which writes Apache's configuration with
 * the interfaces' addresses of the moment before it starts Apache. Where Listen interfaces are chosen, a
 * new address on one of them is an Apply too ('newwanip'), as the web GUI follows its own (webgui.inc).
 * Settings are read out of $config, not through the model, as the family's other hooks read their own.
 *
 * No firewall rule is added: a site reached from another network needs a rule there that passes its port
 * to this firewall, which the owner makes. Apache's own replies leave by OPNsense's rule "let out anything
 * from firewall host itself" (filter.lib.inc).
 */

function modsecurity_general()
{
    global $config;

    $general = $config['OPNsense']['ModSecurity']['general'] ?? [];
    return is_array($general) ? $general : [];
}

function modsecurity_enabled()
{
    return (string)(modsecurity_general()['enabled'] ?? '0') === '1';
}

function modsecurity_services()
{
    if (!modsecurity_enabled()) {
        return [];
    }

    return [[
        'description' => gettext('Web Application Firewall'),
        'configd' => [
            'restart' => ['modsecurity restart'],
            'start' => ['modsecurity start'],
            'stop' => ['modsecurity stop'],
        ],
        'name' => 'modsecurity',
        'pidfile' => '/var/run/modsecurity.pid',
    ]];
}

function modsecurity_configure()
{
    return [
        'bootup' => ['modsecurity_configure_do'],
        'newwanip' => ['modsecurity_configure_do:2'],
    ];
}

function modsecurity_configure_do($verbose = false, $interface_map = null)
{
    if (!modsecurity_enabled()) {
        return;
    }

    if (func_num_args() > 1) {
        /*
         * A new address: nothing where Apache listens on every address, which takes it already; else an
         * Apply where it is on one of the interfaces chosen - or where none is named, as the web GUI reloads
         * then (webgui.inc).
         */
        if (!plugins_argument_map($interface_map)) {
            return;
        }
        $chosen = array_filter(explode(',', (string)(modsecurity_general()['interfaces'] ?? '')));
        if (!count($chosen)) {
            return;
        }
        if (is_array($interface_map) && !count(array_intersect($interface_map, $chosen))) {
            return;
        }
    }

    if ($verbose) {
        echo 'Starting the Web Application Firewall...';
        flush();
    }

    configd_run('modsecurity apply');

    if ($verbose) {
        echo "done.\n";
    }
}
