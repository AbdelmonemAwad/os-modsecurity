<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 */

namespace OPNsense\ModSecurity\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

/**
 * The page's questions and its actions. Apache's pid file, Apply's last answer and the Core Rule Set's
 * record are root's, so each is read through configd: the web GUI reads none of them.
 */
class ServiceController extends ApiControllerBase
{
    private function json($action)
    {
        $result = json_decode((string)(new Backend())->configdRun('modsecurity ' . $action), true);
        return is_array($result) ? $result : null;
    }

    /**
     * the cards and the lines under them
     */
    public function statusAction()
    {
        $result = $this->json('status');
        return $result ?? ['state' => 'unreadable', 'error' => ['message' => gettext('No answer could be read.')]];
    }

    /**
     * Apply: the configuration written from the settings saved, tested by Apache, and Apache started,
     * reloaded or stopped by it (scripts/modsecurity/setup.py) - then what the page shows.
     */
    public function reconfigureAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }
        $result = $this->json('apply') ?? ['status' => 'failed', 'code' => 'unreadable',
            'message' => gettext('No answer could be read.')];
        $result['current'] = $this->statusAction();
        return $result;
    }

    /**
     * Settings' Install: the newest signed release of the Core Rule Set's 4.25 line (scripts/modsecurity/crs.py),
     * then Apply where the plugin is on.
     */
    public function crsinstallAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }
        $result = $this->json('crs install') ?? ['status' => 'failed', 'message' => gettext('No answer could be read.')];
        $result['current'] = $this->statusAction();
        return $result;
    }
}
