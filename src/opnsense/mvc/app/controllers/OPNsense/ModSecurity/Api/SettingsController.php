<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 */

namespace OPNsense\ModSecurity\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Base\UserException;
use OPNsense\Core\Config;

/**
 * Settings' get and set, and the Sites tab's rows - OPNsense's own; the model's checks run at each save, the
 * grid's switch among them.
 */
class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'modsecurity';
    protected static $internalModelClass = '\OPNsense\ModSecurity\ModSecurity';

    public function searchSitesAction()
    {
        return $this->searchBase(
            'sites.site',
            ['enabled', 'description', 'hostnames', 'backend', 'certificate', 'mode', 'paranoia'],
            'hostnames'
        );
    }

    public function getSiteAction($uuid = null)
    {
        return $this->getBase('site', 'sites.site', $uuid);
    }

    public function addSiteAction()
    {
        return $this->addBase('site', 'sites.site');
    }

    public function setSiteAction($uuid)
    {
        return $this->setBase('site', 'sites.site', $uuid);
    }

    public function delSiteAction($uuid)
    {
        return $this->delBase('sites.site', $uuid);
    }

    /**
     * The grid's switch. OPNsense's toggleBase() saves without the model's checks, so a site switched on with
     * a host name the published site has was saved, and at the next Apply took that name from it - the earlier
     * site in config.xml keeps a name (common.check_sites). Turning a site on is checked first as a Save of it
     * is (ModSecurity::performValidation(), only what changed), and refused with the model's words, in the
     * dialog OPNsense shows for an API's UserException - as delBase() refuses an item in use. Turning one off
     * is never refused.
     */
    public function toggleSiteAction($uuid, $enabled = null)
    {
        if ($this->request->isPost()) {
            Config::getInstance()->lock();
            $refused = $this->refusedOn((string)$uuid, $enabled);
            if ($refused !== '') {
                Config::getInstance()->unlock();
                throw new UserException($refused, gettext('This site cannot be enabled'));
            }
        }
        return $this->toggleBase('sites.site', $uuid, $enabled);
    }

    /**
     * What the model says against the sites of $uuids this switch turns on, as one text; '' for nothing. Each
     * is set on, the model checked, and each set back: toggleBase() makes the change itself.
     */
    private function refusedOn($uuids, $enabled)
    {
        $model = $this->getModel();
        $turned = [];
        foreach (array_filter(explode(',', $uuids), 'strlen') as $uuid) {
            $node = $model->getNodeByReference('sites.site.' . $uuid);
            if ($node === null || (string)$node->enabled === '1') {
                continue;
            }
            if ($enabled === null || (string)$enabled === '1') {
                $turned[$uuid] = (string)$node->enabled;
                $node->enabled = '1';
            }
        }
        if (!count($turned)) {
            return '';
        }
        $said = [];
        foreach ($model->performValidation() as $message) {
            foreach (array_keys($turned) as $uuid) {
                if (strpos($message->getField(), 'sites.site.' . $uuid . '.') === 0) {
                    $said[] = $message->getMessage();
                }
            }
        }
        foreach ($turned as $uuid => $was) {
            $model->getNodeByReference('sites.site.' . $uuid)->enabled = $was;
        }
        return implode(' ', array_values(array_unique($said)));
    }
}
