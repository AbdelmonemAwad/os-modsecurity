<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * The page's API (Api/ServiceController and Api/SettingsController), its index and the plugin's hook
 * (plugins.inc.d/modsecurity.inc), run as OPNsense runs them, with stand-ins for what they reach of OPNsense:
 * ApiControllerBase and ApiMutableModelControllerBase - the request, the grid's search, get, add, set and
 * del, and its toggleBase() as OPNsense 26.7 writes it (ApiMutableModelControllerBase.php:641-681, saving
 * without the model's checks) - BaseModel's fields, Config's lock, UserException, IndexController's forms
 * and view, configd (Backend, configd_run), $config and plugins_argument_map(); the plugin's own model
 * (ModSecurity.php, library Site and WebGui) as it is.
 *
 * What is checked: the status script's answer passed on, and one that cannot be read said; Apply and the Core
 * Rule Set's install POST only, each the configd action it names and then the status the page draws; the
 * Sites tab's rows on the model's sites.site, its search by the grid's columns; the grid's switch turning a
 * site on only past the model's checks, as a Save of it - refused with the model's words - and turning one off
 * always; Settings on the plugin's own
 * model; the page's forms and view; the service System: Services lists while on and not while off; the start
 * at boot an Apply while on and nothing while off; a new address an Apply only on a Listen interface chosen;
 * and every configd action any of them asks for in the plugin's actions file.
 *
 *   php tools/test-mvc.php
 */

namespace OPNsense\Base\Messages {
    class Message
    {
        private $message;
        private $field;

        public function __construct($message, $field = '')
        {
            $this->message = $message;
            $this->field = $field;
        }

        public function getMessage()
        {
            return $this->message;
        }

        public function getField()
        {
            return $this->field;
        }
    }
}

namespace OPNsense\Base {
    class UserException extends \Exception
    {
        public $title;

        public function __construct($message, $title = '')
        {
            parent::__construct($message);
            $this->title = $title;
        }
    }

    class Messages implements \IteratorAggregate
    {
        public $all = [];

        public function appendMessage($message)
        {
            $this->all[] = $message;
        }

        public function getIterator(): \Iterator
        {
            return new \ArrayIterator($this->all);
        }
    }

    /* a field: its text, and whether it differs from what config.xml had */
    class Field
    {
        public $value;
        private $initial;

        public function __construct($value)
        {
            $this->value = $this->initial = (string)$value;
        }

        public function __toString()
        {
            return $this->value;
        }

        public function isFieldChanged()
        {
            return $this->value !== $this->initial;
        }
    }

    class Node
    {
        private $fields = [];

        public function __construct(array $values)
        {
            foreach ($values as $name => $value) {
                $this->fields[$name] = new Field($value);
            }
        }

        public function __get($name)
        {
            return $this->fields[$name] ?? new Field('');
        }

        public function __set($name, $value)
        {
            if (!isset($this->fields[$name])) {
                $this->fields[$name] = new Field('');
            }
            $this->fields[$name]->value = (string)$value;
        }

        public function isFieldChanged()
        {
            foreach ($this->fields as $field) {
                if ($field->isFieldChanged()) {
                    return true;
                }
            }
            return false;
        }
    }

    class Rows
    {
        public $rows = [];

        public function iterateItems()
        {
            foreach ($this->rows as $uuid => $row) {
                yield $uuid => $row;
            }
        }

        public function __get($uuid)
        {
            return $this->rows[$uuid] ?? null;
        }
    }

    /* the plugin's model as config.xml gives it: Settings and the sites, each field's own checks none here */
    abstract class BaseModel
    {
        public static $givenGeneral = [];
        public static $givenSites = [];
        public $general;
        public $sites;

        public function __construct()
        {
            $this->general = new Node(self::$givenGeneral);
            $rows = new Rows();
            foreach (self::$givenSites as $uuid => $values) {
                $rows->rows[$uuid] = new Node($values);
            }
            $this->sites = (object)['site' => $rows];
        }

        public function getNodeByReference($reference)
        {
            if ($reference === 'sites.site') {
                return $this->sites->site;
            }
            if (strpos($reference, 'sites.site.') === 0) {
                return $this->sites->site->rows[substr($reference, strlen('sites.site.'))] ?? null;
            }
            return null;
        }

        public function performValidation($validateFullModel = false)
        {
            return new Messages();
        }
    }

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
        public $saved = 0;
        private $modelHandle = null;

        protected function getModel()
        {
            if ($this->modelHandle === null) {
                $class = static::$internalModelClass;
                $this->modelHandle = new $class();
            }
            return $this->modelHandle;
        }

        public function model()
        {
            return $this->getModel();
        }

        protected function save($validateFullModel = false, $disable_validation = false)
        {
            $this->saved++;
            return ['result' => 'saved'];
        }

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

        /* OPNsense 26.7's own, as it is there (ApiMutableModelControllerBase.php:641-681): no check before its save */
        public function toggleBase($path, $uuids, $enabled = null)
        {
            $result = ['result' => 'failed'];
            if ($this->request->isPost()) {
                \OPNsense\Core\Config::getInstance()->lock();
                $uuids = !empty($uuids) ? explode(",", $uuids) : [];
                if (count($uuids) > 1 && $enabled === null) {
                    throw new UserException('Toggle with a list of items in only supported for explicit actions [0,1]', 'Toggle');
                }
                $rootnode = $this->getModel()->getNodeByReference($path);
                if ($rootnode === null) {
                    return $result;
                }
                foreach ($uuids as $uuid) {
                    $node = $rootnode->$uuid;
                    if ($node !== null) {
                        $result['changed'] = true;
                        if ($enabled == "0" || $enabled == "1") {
                            $result['result'] = !empty($enabled) ? "Enabled" : "Disabled";
                            $result['changed'] = (string)$node->enabled !== (string)$enabled;
                            $node->enabled = (string)$enabled;
                        } elseif ($enabled !== null) {
                            $result['changed'] = false;
                            break;
                        } elseif ((string)$node->enabled == "1") {
                            $result['result'] = "Disabled";
                            $node->enabled = "0";
                        } else {
                            $result['result'] = "Enabled";
                            $node->enabled = "1";
                        }
                    }
                }
                if (!empty($result['changed'])) {
                    $this->save(false, true);
                }
            }
            return $result;
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
    class Config
    {
        public static $locked = 0;
        public static $unlocked = 0;

        public static function getInstance()
        {
            return new self();
        }

        public function lock()
        {
            self::$locked++;
            return $this;
        }

        public function unlock()
        {
            self::$unlocked++;
        }

        /* config.xml as the model reads it at a site's check: System: Trust's certificates, none here */
        public function object()
        {
            return (object)['cert' => []];
        }
    }

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
    require $root . '/src/opnsense/mvc/app/library/OPNsense/ModSecurity/Site.php';
    require $root . '/src/opnsense/mvc/app/library/OPNsense/ModSecurity/WebGui.php';
    require $root . '/src/opnsense/mvc/app/models/OPNsense/ModSecurity/ModSecurity.php';
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
    foreach (['[]', '["running"]', '{}', '', 'null', '"running"'] as $answer) {
        Backend::$answers['modsecurity status'] = $answer;
        check($service->statusAction()['state'] === 'unreadable', "status: an answer that is no object, $answer, is none");
    }
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
    foreach (['', '[]'] as $answer) {
        Backend::$answers['modsecurity apply'] = $answer;
        $got = $service->reconfigureAction();
        check($got['status'] === 'failed' && $got['message'] === 'No answer could be read.',
              "Apply: no answer ('$answer'), said as failed");
    }

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
          $settings->setSiteAction('u1') === ['set', 'site', 'sites.site', 'u1'] && $settings->delSiteAction('u1') === ['del', 'sites.site', 'u1'],
          'Sites: get, add, set and delete on sites.site');

    /* the grid's switch: on only past the model's checks, off always */
    $published = ['enabled' => '1', 'hostnames' => 'www.example.com', 'backend' => 'http://192.0.2.10:8088', 'certificate' => '',
        'mode' => 'detection', 'paranoia' => '1', 'verify' => '1'];
    function grid($sites)
    {
        \OPNsense\Base\BaseModel::$givenGeneral = ['enabled' => '1', 'interfaces' => '', 'http_port' => '8080', 'https_port' => '8443'];
        \OPNsense\Base\BaseModel::$givenSites = $sites;
        return new OPNsense\ModSecurity\Api\SettingsController();
    }
    function switched($settings, $uuid, $enabled = null)
    {
        try {
            return $settings->toggleSiteAction($uuid, $enabled);
        } catch (\OPNsense\Base\UserException $refused) {
            return ['refused' => $refused->getMessage(), 'title' => $refused->title];
        }
    }
    $before = ['s1' => array_merge($published, ['enabled' => '0', 'backend' => 'http://192.0.2.20']), 's2' => $published];
    foreach ([null, '1'] as $enabled) {
        $settings = grid($before);
        $got = switched($settings, 's1', $enabled);
        check($got === ['refused' => 'www.example.com is a host name of another site.', 'title' => 'This site cannot be enabled'] &&
              $settings->saved === 0 && (string)$settings->model()->getNodeByReference('sites.site.s1')->enabled === '0',
              'the switch turning on a site, earlier in config.xml, with the published site\'s name (' . json_encode($enabled) .
              '): refused with the model\'s words, nothing saved - the published one stays');
    }
    $settings = grid($before);
    $got = switched($settings, 's2');
    check($got === ['result' => 'Disabled', 'changed' => true] && $settings->saved === 1 &&
          (string)$settings->model()->getNodeByReference('sites.site.s2')->enabled === '0', 'the switch turning a site off: saved, never checked');
    $settings = grid(['s1' => $before['s1'], 's2' => array_merge($published, ['enabled' => '0'])]);
    $got = switched($settings, 's1');
    check($got === ['result' => 'Enabled', 'changed' => true] && $settings->saved === 1 &&
          (string)$settings->model()->getNodeByReference('sites.site.s1')->enabled === '1',
          'the switch turning on a site whose name no other enabled site has: saved, as OPNsense\'s own');
    $settings = grid($before);
    check(switched($settings, 's1', '0') === ['result' => 'Disabled', 'changed' => false] && $settings->saved === 0,
          'the switch set off where it is off: nothing to save, nothing checked');
    $settings = grid(['s3' => array_merge($published, ['enabled' => '0', 'hostnames' => 'shop.example.com', 'backend' => 'http://192.0.2.10/a/../b'])]);
    $got = switched($settings, 's3');
    check(isset($got['refused']) && strpos($got['refused'], 'A URL of the site\'s server') === 0 && $settings->saved === 0,
          'every check of a site\'s Save, not the names alone: a backend Apache cannot proxy to refused');
    $settings = grid(['s1' => $before['s1'], 's2' => $published, 's4' => array_merge($published, ['enabled' => '0', 'hostnames' => 'wiki.example.com'])]);
    $got = switched($settings, 's4,s1', '1');
    check(($got['refused'] ?? '') === 'www.example.com is a host name of another site.' && $settings->saved === 0 &&
          (string)$settings->model()->getNodeByReference('sites.site.s4')->enabled === '0',
          'a list switched on at once: one refused, none saved');
    $settings = grid($before);
    $settings->request->post = false;
    check(switched($settings, 's1') === ['result' => 'failed'] && $settings->saved === 0, 'the switch by a GET: nothing');

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
