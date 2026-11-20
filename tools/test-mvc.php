<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * The page's API (Api/ServiceController and Api/SettingsController), its index and the plugin's hook
 * (plugins.inc.d/modsecurity.inc), run as OPNsense runs them, with stand-ins for what they reach of OPNsense:
 * ApiControllerBase and ApiMutableModelControllerBase - the request, the grid's search, get, add, set, del
 * and toggle - IndexController's forms and view, configd (Backend, configd_run), $config and
 * plugins_argument_map().
 *
 * What is checked: the status script's answer passed on, and one that cannot be read said; Apply and the Core
 * Rule Set's install POST only, each the configd action it names and then the status the page draws; the
 * Sites tab's rows on the model's sites.site, its search by the grid's columns; Settings on the plugin's own
 * model; the page's forms and view; the service System: Services lists while on and not while off; the start
 * at boot an Apply while on and nothing while off; a new address an Apply only on a Listen interface chosen;
 * and every configd action any of them asks for in the plugin's actions file.
 *
 *   php tools/test-mvc.php
 */

namespace OPNsense\Base {
    class Request
    {
        public $post = true;

        public function isPost()
        {
            return $this->post;
        }
    }

    class ApiControllerBase
    {
        public $request;

        public function __construct()
        {
            $this->request = new Request();
        }
    }

    class ApiMutableModelControllerBase extends ApiControllerBase
    {
        public $asked = [];

        public function names()
        {
            return [static::$internalModelName, static::$internalModelClass];
        }

        public function searchBase($path, $fields = null, $sort = null)
        {
            return ['search', $path, $fields, $sort];
        }

        public function getBase($key, $path, $uuid = null)
        {
            return ['get', $key, $path, $uuid];
        }

        public function addBase($key, $path)
        {
            return ['add', $key, $path];
        }

        public function setBase($key, $path, $uuid)
        {
            return ['set', $key, $path, $uuid];
        }

        public function delBase($path, $uuid)
        {
            return ['del', $path, $uuid];
        }

        public function toggleBase($path, $uuid, $enabled = null)
        {
            return ['toggle', $path, $uuid, $enabled];
        }
    }

    class IndexController
    {
        public $view;

        public function __construct()
        {
            $this->view = new class {
                public $picked;
                public $generalForm;
                public $formDialogSite;

                public function pick($name)
                {
                    $this->picked = $name;
                }
            };
        }

        protected function getForm($name)
        {
            return 'form:' . $name;
        }
    }
}

namespace OPNsense\Core {
    class Backend
    {
        public static $answers = [];
        public static $asked = [];

        public function configdRun($event, $detach = false)
        {
            self::$asked[] = $event;
            return self::$answers[$event] ?? null;
        }
    }
}

namespace {
    if (!function_exists('gettext')) {
        function gettext($text)
        {
            return $text;
        }
    }

    $ran = [];

    function configd_run($event)
    {
        global $ran;
        $ran[] = $event;
    }

    /* plugins.inc's own, as far as the hook asks it: a list of interfaces, or none */
    function plugins_argument_map(&$arg)
    {
        if (is_string($arg)) {
            $arg = strlen($arg) ? explode(',', $arg) : null;
        }
        if (is_array($arg)) {
            $arg = array_values(array_unique(array_filter($arg)));
            return count($arg) > 0;
        }
        return true;
    }

    $root = dirname(__DIR__);
    $mvc = $root . '/src/opnsense/mvc/app/controllers/OPNsense/ModSecurity';
    require $mvc . '/Api/ServiceController.php';
    require $mvc . '/Api/SettingsController.php';
    require $mvc . '/IndexController.php';
    require $root . '/src/etc/inc/plugins.inc.d/modsecurity.inc';

    use OPNsense\Core\Backend;

    $failed = 0;
    $checks = 0;

    function check($ok, $what)
    {
        global $failed, $checks;
        $checks++;
        if (!$ok) {
            $failed++;
            echo "FAIL $what\n";
        } else {
            echo "ok   $what\n";
        }
    }

    function fresh()
    {
        global $ran;
        Backend::$asked = [];
        $ran = [];
    }

    $service = new OPNsense\ModSecurity\Api\ServiceController();
    Backend::$answers['modsecurity status'] = json_encode(['state' => 'running', 'counts' => ['usable' => 2]]);
    fresh();
    $got = $service->statusAction();
    check($got['state'] === 'running' && Backend::$asked === ['modsecurity status'], 'status: the status script\'s answer');
    Backend::$answers['modsecurity status'] = 'Execute error';
    $got = $service->statusAction();
    check($got['state'] === 'unreadable' && $got['error']['message'] === 'No answer could be read.',
          'status: an answer that is no JSON said as such');
    Backend::$answers['modsecurity status'] = json_encode(['state' => 'running']);

    $service->request->post = false;
    fresh();
    check($service->reconfigureAction() === ['status' => 'failed'] && $service->crsinstallAction() === ['status' => 'failed'] &&
          Backend::$asked === [], 'Apply and Install: nothing for a GET');
    $service->request->post = true;

    Backend::$answers['modsecurity apply'] = json_encode(['status' => 'ok', 'state' => 'running', 'sites' => 2]);
    fresh();
    $got = $service->reconfigureAction();
    check(Backend::$asked === ['modsecurity apply', 'modsecurity status'], 'Apply: the Apply, then the status');
    check($got['status'] === 'ok' && $got['sites'] === 2 && $got['current']['state'] === 'running',
          'Apply: its answer, and the status the page draws');
    Backend::$answers['modsecurity apply'] = '';
    $got = $service->reconfigureAction();
    check($got['status'] === 'failed' && $got['message'] === 'No answer could be read.', 'Apply: no answer, said as failed');

    Backend::$answers['modsecurity crs install'] = json_encode(['status' => 'installed', 'version' => '4.25.2']);
    fresh();
    $got = $service->crsinstallAction();
    check(Backend::$asked === ['modsecurity crs install', 'modsecurity status'] && $got['version'] === '4.25.2' &&
          $got['current']['state'] === 'running', 'Install: the Core Rule Set\'s install, then the status');
    Backend::$answers['modsecurity crs install'] = null;
    check($service->crsinstallAction()['status'] === 'failed', 'Install: no answer, said as failed');

    $settings = new OPNsense\ModSecurity\Api\SettingsController();
    check($settings->names() === ['modsecurity', '\OPNsense\ModSecurity\ModSecurity'], 'Settings: the plugin\'s own model, modsecurity');
    check($settings->searchSitesAction() === ['search', 'sites.site', ['enabled', 'description', 'hostnames', 'backend', 'certificate',
          'mode', 'paranoia'], 'hostnames'], 'Sites: searched by the grid\'s columns, sorted by host names');
    check($settings->getSiteAction('u1') === ['get', 'site', 'sites.site', 'u1'] && $settings->addSiteAction() === ['add', 'site', 'sites.site'] &&
          $settings->setSiteAction('u1') === ['set', 'site', 'sites.site', 'u1'] && $settings->delSiteAction('u1') === ['del', 'sites.site', 'u1'] &&
          $settings->toggleSiteAction('u1', '0') === ['toggle', 'sites.site', 'u1', '0'], 'Sites: get, add, set, delete and toggle on sites.site');

    $index = new OPNsense\ModSecurity\IndexController();
    $index->indexAction();
    check($index->view->picked === 'OPNsense/ModSecurity/index' && $index->view->generalForm === 'form:general' &&
          $index->view->formDialogSite === 'form:dialogSite', 'the page: its view, its Settings form and its site dialog');
    foreach (['general', 'dialogSite'] as $form) {
        check(is_file($mvc . "/forms/$form.xml"), "the form $form is there");
    }

    /* the hook */
    $config = [];
    check(modsecurity_services() === [], 'never turned on: no service listed');
    fresh();
    modsecurity_configure_do();
    check($ran === [], 'never turned on: nothing at boot');
    $config['OPNsense']['ModSecurity']['general'] = ['enabled' => '1', 'interfaces' => ''];
    $services = modsecurity_services();
    check(count($services) === 1 && $services[0]['name'] === 'modsecurity' && $services[0]['pidfile'] === '/var/run/modsecurity.pid' &&
          $services[0]['configd'] === ['restart' => ['modsecurity restart'], 'start' => ['modsecurity start'], 'stop' => ['modsecurity stop']],
          'on: the service listed, by its pid file, started and stopped through configd');
    check(modsecurity_configure() === ['bootup' => ['modsecurity_configure_do'], 'newwanip' => ['modsecurity_configure_do:2']],
          'at boot and at a new address');
    fresh();
    modsecurity_configure_do(false);
    check($ran === ['modsecurity apply'], 'on, at boot: an Apply');
    fresh();
    modsecurity_configure_do(false, 'wan');
    check($ran === [], 'on every address, a new address: nothing - Apache takes it already');
    $config['OPNsense']['ModSecurity']['general']['interfaces'] = 'wan,opt1';
    fresh();
    modsecurity_configure_do(false, 'lan');
    check($ran === [], 'on WAN and OPT1, a new address on LAN: nothing');
    fresh();
    modsecurity_configure_do(false, ['opt1']);
    check($ran === ['modsecurity apply'], 'on WAN and OPT1, a new address on OPT1: an Apply');
    fresh();
    modsecurity_configure_do(false, '');
    check($ran === ['modsecurity apply'], 'a new address on no interface named: an Apply, as the web GUI reloads then');
    $config['OPNsense']['ModSecurity']['general']['enabled'] = '0';
    fresh();
    modsecurity_configure_do(false, 'opt1');
    check($ran === [] && modsecurity_services() === [], 'off: nothing at a new address, no service listed');

    /* every configd action asked for is the plugin's */
    $actions = file_get_contents($root . '/src/opnsense/service/conf/actions.d/actions_modsecurity.conf');
    preg_match_all('/^\[([\w.]+)\]$/m', $actions, $found);
    check($found[1] === ['status', 'apply', 'crs.install', 'start', 'stop', 'restart'],
          'configd: status, apply and crs install for the page; start, stop and restart for the service');
    $asked = [];
    foreach ([$mvc . '/Api/ServiceController.php', $root . '/src/etc/inc/plugins.inc.d/modsecurity.inc', $root . '/install/install.sh',
              $root . '/pkg/post-install.sh'] as $file) {
        preg_match_all("/(?:configdRun\\('modsecurity ' \\. |json\\(')([a-z. ]+)'|'modsecurity ([a-z ]+)'|configctl modsecurity ([a-z ]+?) [>]/",
                       file_get_contents($file), $m, PREG_SET_ORDER);
        foreach ($m as $hit) {
            $name = trim($hit[1] !== '' ? $hit[1] : ($hit[2] !== '' ? $hit[2] : $hit[3]));
            if ($name !== '') {
                $asked[] = str_replace(' ', '.', $name);
            }
        }
    }
    $asked = array_values(array_unique($asked));
    sort($asked);
    check($asked === ['apply', 'crs.install', 'restart', 'start', 'status', 'stop'] && !array_diff($asked, $found[1]),
          'every action the API, the hook, the installer and the package ask for is there: ' . implode(', ', $asked));

    echo $failed ? "$failed of $checks checks failed\n" : "$checks checks passed\n";
    exit($failed ? 1 : 0);
}
