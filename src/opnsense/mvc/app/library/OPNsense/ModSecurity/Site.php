<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 */

namespace OPNsense\ModSecurity;

/**
 * A site's host names and backend as Apache is given them - the same reading as
 * scripts/modsecurity/common.py (names, name_ok, covers, backend), which tools/test-model.php and
 * tools/test-setup.py hold to the same table of taken and refused entries.
 */
class Site
{
    const LABEL = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?';

    /**
     * The names of a comma-separated list, lower case, the dot at an end taken off, each once, in order.
     */
    public static function names($raw)
    {
        $out = [];
        foreach (explode(',', (string)$raw) as $item) {
            $item = rtrim(strtolower(trim($item)), '.');
            if ($item !== '' && !in_array($item, $out, true)) {
                $out[] = $item;
            }
        }
        return $out;
    }

    /**
     * A host name a site may have: a wildcard only as the whole first label, never an IP address.
     */
    public static function nameOk($name)
    {
        if (!is_string($name) || strlen($name) > 253) {
            return false;
        }
        if (!preg_match('/^(?:\*\.)?(?:' . self::LABEL . '\.)*' . self::LABEL . '$/D', $name)) {
            return false;
        }
        return filter_var($name, FILTER_VALIDATE_IP) === false;
    }

    /**
     * Whether the wildcard *.d takes the name: Apache matches * with any run of characters, dots too -
     * a.b.example.com, and every name of a wildcard below it, *.shop.example.com; never example.com.
     */
    public static function covers($wildcard, $name)
    {
        if (strncmp($wildcard, '*.', 2) !== 0 || $wildcard === $name) {
            return false;
        }
        $bare = strncmp($name, '*.', 2) === 0 ? substr($name, 2) : $name;
        $tail = substr($wildcard, 1);
        return strlen($bare) > strlen($tail) && substr($bare, -strlen($tail)) === $tail;
    }

    /**
     * The backend as Apache is given it - ['url', 'scheme', 'host', 'port', 'tls'], its path ending in
     * '/' - or null when it is no URL Apache may proxy to.
     */
    public static function backend($raw)
    {
        $raw = trim((string)$raw);
        if (!preg_match('#^(https?)://(\[[0-9A-Fa-f:.]{2,45}\]|[A-Za-z0-9.-]{1,253})(?::([0-9]{1,5}))?(/[A-Za-z0-9._~%/-]*)?$#D', $raw, $m)) {
            return null;
        }
        $scheme = $m[1];
        $host = $m[2];
        $digits = $m[3] ?? '';
        $path = ($m[4] ?? '') !== '' ? $m[4] : '/';
        if ($host[0] === '[') {
            if (filter_var(substr($host, 1, -1), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
                return null;
            }
        } elseif (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            /* a name - not digits and dots, which would be an IPv4 address that is not one */
            $host = strtolower($host);
            if (!preg_match('/^(?:' . self::LABEL . '\.)*' . self::LABEL . '$/D', $host) || preg_match('/^[0-9.]+$/', $host)) {
                return null;
            }
        }
        $port = null;
        if ($digits !== '') {
            $port = (int)$digits;
            if ($port < 1 || $port > 65535) {
                return null;
            }
        }
        if (substr($path, -1) !== '/') {
            $path .= '/';
        }
        if (strpos($path, '//') !== false || strpos($path, '/../') !== false || strpos($path, '/./') !== false) {
            return null;
        }
        $url = $scheme . '://' . $host . ($port !== null ? ':' . $port : '') . $path;
        return ['url' => $url, 'scheme' => $scheme, 'host' => $host, 'port' => $port, 'tls' => $scheme === 'https'];
    }
}
