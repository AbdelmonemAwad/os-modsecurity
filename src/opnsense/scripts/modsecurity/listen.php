<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * The addresses the Web Application Firewall listens on when its Listen interfaces are chosen: each
 * interface's addresses as OPNsense's own web GUI takes its own (plugins.inc.d/webgui.inc), through
 * interfaces_addresses() - an address a virtual IP marks not to be bound left out, and a tentative
 * IPv6 one - and a link-local one too, which no site is published on. setup.py asks it at each Apply;
 * the plugin's hook asks for an Apply again when one of these interfaces gets a new address.
 *
 *   php listen.php lan,wan     {"addresses": [{"address": ..., "family": "inet" or "inet6",
 *                               "interface": ...}]}
 */

require_once 'config.inc';
require_once 'util.inc';
require_once 'interfaces.inc';

$keys = array_values(array_filter(array_map('trim', explode(',', $argv[1] ?? '')), 'strlen'));
$found = [];

if (count($keys)) {
    foreach (interfaces_addresses($keys) as $info) {
        if (empty($info['bind']) || !empty($info['scope'])) {
            continue;
        }
        if ($info['family'] == 'inet6' && (!empty($info['tentative']) || !empty($info['detached']))) {
            continue;
        }
        $found[] = ['address' => $info['address'], 'family' => $info['family'], 'interface' => $info['interface']];
    }
}

echo json_encode(['addresses' => $found]) . PHP_EOL;
