<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 */

namespace OPNsense\ModSecurity\Api;

use OPNsense\Base\ApiMutableModelControllerBase;

/**
 * Settings' get and set, and the Sites tab's rows - OPNsense's own; the model's checks run at each save.
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

    public function toggleSiteAction($uuid, $enabled = null)
    {
        return $this->toggleBase('sites.site', $uuid, $enabled);
    }
}
