<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 */

namespace OPNsense\ModSecurity;

/**
 * Where the web GUI listens, as plugins.inc.d/webgui.inc binds it, and where that meets the ports the
 * Web Application Firewall would take (settled point 8a: refused, and how to move the GUI said; the plugin
 * never moves it). The same reading as scripts/modsecurity/common.py (webgui, gui_conflicts).
 */
class WebGui
{
    /**
     * ['ports' => [...], 'interfaces' => [...]] of system/webgui: its port - 443 for HTTPS and 80 for
     * HTTP where none is set - and 80 for its redirect to HTTPS unless that is turned off; its Listen
     * interfaces, none for every address.
     * @param array $webgui system/webgui as an array of its elements' texts, an element absent not there
     */
    public static function listeners(array $webgui)
    {
        $protocol = trim((string)($webgui['protocol'] ?? 'https'));
        if ($protocol === '') {
            $protocol = 'https';
        }
        $given = trim((string)($webgui['port'] ?? ''));
        $ports = [];
        if (ctype_digit($given) && (int)$given >= 1 && (int)$given <= 65535) {
            $ports[] = (int)$given;
        } else {
            $ports[] = $protocol === 'https' ? 443 : 80;
        }
        if ($protocol === 'https' && !array_key_exists('disablehttpredirect', $webgui)) {
            $ports[] = 80;
        }
        $ports = array_values(array_unique($ports));
        sort($ports);
        $interfaces = array_values(array_filter(array_map('trim', explode(',', (string)($webgui['interfaces'] ?? ''))), 'strlen'));
        return ['ports' => $ports, 'interfaces' => $interfaces];
    }

    /**
     * The ports of $ports the GUI holds where Apache would listen on $interfaces (none: every address):
     * [['port' => ..., 'interfaces' => the GUI's Listen interfaces, none for every address]]. A GUI on
     * every address holds its port everywhere; one on its Listen interfaces holds it there and on the
     * loopback, which Apache on every address takes too.
     */
    public static function conflicts(array $gui, array $ports, array $interfaces)
    {
        $out = [];
        $wanted = array_values(array_unique(array_filter(array_map('intval', $ports))));
        sort($wanted);
        foreach ($wanted as $port) {
            if (!in_array($port, $gui['ports'], true)) {
                continue;
            }
            if (!count($gui['interfaces']) || !count($interfaces) || count(array_intersect($gui['interfaces'], $interfaces))) {
                $out[] = ['port' => $port, 'interfaces' => $gui['interfaces']];
            }
        }
        return $out;
    }

    /**
     * system/webgui of config.xml, as listeners() takes it.
     */
    public static function fromConfig()
    {
        $out = [];
        $config = \OPNsense\Core\Config::getInstance()->object();
        if (isset($config->system->webgui)) {
            foreach ($config->system->webgui->children() as $node) {
                $out[$node->getName()] = (string)$node;
            }
        }
        return $out;
    }
}
