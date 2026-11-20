<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 */

namespace OPNsense\ModSecurity;

use OPNsense\Base\BaseModel;
use OPNsense\Base\Messages\Message;
use OPNsense\Core\Config;

class ModSecurity extends BaseModel
{
    /* host names a site has at most; scripts/modsecurity/common.py NAMES_MAX */
    const NAMES_MAX = 32;

    /**
     * Beside each field's own checks, said on the field they are about, each only where its part changed
     * (Settings, or the one site saved), as OPNsense's own models check theirs:
     *
     * Settings, while on: a port for HTTP, for HTTPS or both, not the same one twice; neither held by the
     * web GUI where Apache would listen (settled point 8a: refused, with how to move the GUI - the plugin
     * never moves it); and a port for each kind of site there is.
     *
     * A site, while enabled: no host name another enabled site has, nor one another site's wildcard takes
     * or whose name its own wildcard takes (Apache would give such a request to one of them by the order of
     * its configuration, which the page does not show); a backend Apache can proxy to (library Site); a
     * certificate with its private key; and the port its kind needs in Settings.
     */
    public function performValidation($validateFullModel = false)
    {
        $messages = parent::performValidation($validateFullModel);
        $general = $this->general;
        $http = trim((string)$general->http_port);
        $https = trim((string)$general->https_port);
        $on = (string)$general->enabled === '1';
        $sites = [];
        foreach ($this->sites->site->iterateItems() as $uuid => $site) {
            $sites[$uuid] = $site;
        }

        if ($validateFullModel || $general->isFieldChanged()) {
            /* as numbers: 080 and 80 are one port, as Apache and the scripts read them */
            if ($http !== '' && $https !== '' && (int)$http === (int)$https) {
                $messages->appendMessage(new Message(gettext('HTTP and HTTPS need a port each.'), 'general.https_port'));
            }
            if ($on && $http === '' && $https === '') {
                $messages->appendMessage(new Message(
                    gettext('Give a port for HTTP, for HTTPS or both, or turn the Web Application Firewall off.'),
                    'general.http_port'
                ));
            }
            if ($on) {
                $interfaces = array_values(array_filter(explode(',', (string)$general->interfaces), 'strlen'));
                $gui = WebGui::listeners($this->webgui());
                foreach (WebGui::conflicts($gui, [$http, $https], $interfaces) as $conflict) {
                    $field = $http !== '' && (int)$conflict['port'] === (int)$http ? 'general.http_port' : 'general.https_port';
                    if (count($conflict['interfaces'])) {
                        $text = sprintf(
                            gettext('The web GUI listens on port %s on %s. Move it in System: Settings: Administration - another TCP port, or Listen interfaces without the ones chosen here - or choose another port here.'),
                            $conflict['port'],
                            implode(', ', $this->interfaceNames($conflict['interfaces']))
                        );
                    } else {
                        $text = sprintf(
                            gettext('The web GUI listens on port %s on every interface. Move it in System: Settings: Administration - another TCP port, or Listen interfaces without the ones chosen here - or choose another port here.'),
                            $conflict['port']
                        );
                    }
                    $messages->appendMessage(new Message($text, $field));
                }
                $plain = $secure = false;
                foreach ($sites as $site) {
                    if ((string)$site->enabled === '1') {
                        if (trim((string)$site->certificate) === '') {
                            $plain = true;
                        } else {
                            $secure = true;
                        }
                    }
                }
                if ($plain && $http === '') {
                    $messages->appendMessage(new Message(
                        gettext('Enabled sites without a certificate are served over plain HTTP: give an HTTP port, or each of them a certificate.'),
                        'general.http_port'
                    ));
                }
                if ($secure && $https === '') {
                    $messages->appendMessage(new Message(
                        gettext('Enabled sites with a certificate are served over HTTPS: give an HTTPS port, or take their certificates away.'),
                        'general.https_port'
                    ));
                }
            }
        }

        $keys = null;
        foreach ($sites as $uuid => $site) {
            if ((string)$site->enabled !== '1' || (!$validateFullModel && !$site->isFieldChanged())) {
                continue;
            }
            $at = 'sites.site.' . $uuid . '.';
            $names = Site::names((string)$site->hostnames);
            if (count($names) > self::NAMES_MAX) {
                $messages->appendMessage(new Message(
                    sprintf(gettext('A site has %d host names at most.'), self::NAMES_MAX),
                    $at . 'hostnames'
                ));
            }
            foreach ($sites as $other => $node) {
                if ($other === $uuid || (string)$node->enabled !== '1') {
                    continue;
                }
                foreach (Site::names((string)$node->hostnames) as $theirs) {
                    foreach ($names as $name) {
                        if ($name === $theirs) {
                            $messages->appendMessage(new Message(
                                sprintf(gettext('%s is a host name of another site.'), $name),
                                $at . 'hostnames'
                            ));
                        } elseif (Site::covers($theirs, $name) || Site::covers($name, $theirs)) {
                            $messages->appendMessage(new Message(
                                sprintf(gettext('%s and %s of another site would take the same requests: a host name belongs to one site.'), $name, $theirs),
                                $at . 'hostnames'
                            ));
                        }
                    }
                }
            }
            if (trim((string)$site->backend) !== '' && Site::backend((string)$site->backend) === null) {
                $messages->appendMessage(new Message(
                    gettext('A URL of the site\'s server, http:// or https://, such as http://192.0.2.10:8080 or https://intranet.example.com.'),
                    $at . 'backend'
                ));
            }
            $certificate = trim((string)$site->certificate);
            if ($certificate !== '') {
                if ($keys === null) {
                    $keys = $this->certificateKeys();
                }
                if (isset($keys[$certificate]) && !$keys[$certificate]) {
                    $messages->appendMessage(new Message(
                        gettext('This certificate has no private key in System: Trust: a site cannot be served with it.'),
                        $at . 'certificate'
                    ));
                }
                if ($https === '') {
                    $messages->appendMessage(new Message(
                        gettext('Settings has no HTTPS port: give one there, or no certificate here.'),
                        $at . 'certificate'
                    ));
                }
            } elseif ($http === '') {
                $messages->appendMessage(new Message(
                    gettext('Settings has no HTTP port: give one there, or a certificate here.'),
                    $at . 'certificate'
                ));
            }
        }
        return $messages;
    }

    /**
     * Interfaces by the names the page gives them: their descriptions, else the key in capitals, as status.py
     * and OPNsense's own pages name them.
     */
    protected function interfaceNames(array $keys)
    {
        $config = Config::getInstance()->object();
        $out = [];
        foreach ($keys as $key) {
            $descr = isset($config->interfaces->$key) ? trim((string)$config->interfaces->$key->descr) : '';
            $out[] = $descr !== '' ? $descr : strtoupper($key);
        }
        return $out;
    }

    /**
     * system/webgui, as WebGui::listeners() takes it.
     */
    protected function webgui()
    {
        return WebGui::fromConfig();
    }

    /**
     * [refid => whether it has its private key] of System: Trust's certificates.
     */
    protected function certificateKeys()
    {
        $out = [];
        $config = Config::getInstance()->object();
        if (isset($config->cert)) {
            foreach ($config->cert as $cert) {
                $out[(string)$cert->refid] = trim((string)$cert->prv) !== '';
            }
        }
        return $out;
    }
}
