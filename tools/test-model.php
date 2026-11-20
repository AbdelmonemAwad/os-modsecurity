<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * The plugin's model (models/OPNsense/ModSecurity/ModSecurity.php) and how it reads a site and the web GUI
 * (library OPNsense\ModSecurity\Site and WebGui), run as a Save runs them, with stand-ins for what they reach
 * of OPNsense: BaseModel - its fields, whose own checks give nothing here, as for valid entries, each with
 * whether it changed - Message, and config.xml's web GUI and certificates (Config).
 *
 * What is checked: a site's names, wildcards and backend and the web GUI's listeners read as
 * scripts/modsecurity/common.py reads them - one table, tools/fixtures/cases.json, which tools/test-setup.py
 * holds common.py to; Settings, while on: a port, not the same one twice, none the web GUI holds where Apache
 * would listen - said with how to move the GUI (settled point 8a) - and a port for each kind of site there
 * is; a site, while enabled: no name another site has or takes with a wildcard, a backend Apache can proxy
 * to, a certificate with its key, the port its kind needs - each said on its field, and only where its part
 * changed; and the model's XML in step with common.py: the defaults, the options, the pattern of
 * os-xgs-npu's own links.
 *
 *   php tools/test-model.php
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

    /* a field: its text, and whether this save changed it */
    class Field
    {
        private $value;
        private $changed;

        public function __construct($value, $changed)
        {
            $this->value = $value;
            $this->changed = $changed;
        }

        public function __toString()
        {
            return (string)$this->value;
        }

        public function isFieldChanged()
        {
            return $this->changed;
        }
    }

    /* a container - Settings, a site - changed when one of its fields is */
    class Node
    {
        private $fields = [];

        public function __construct(array $values, array $changed)
        {
            foreach ($values as $name => $value) {
                $this->fields[$name] = new Field($value, in_array($name, $changed, true));
            }
        }

        public function __get($name)
        {
            return $this->fields[$name] ?? new Field('', false);
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
    }

    abstract class BaseModel
    {
        public static $givenGeneral = [];
        public static $givenChanged = [];
        public static $givenSites = [];
        public static $givenSitesChanged = [];
        public $general;
        public $sites;

        public function __construct()
        {
            $this->general = new Node(self::$givenGeneral, self::$givenChanged);
            $rows = new Rows();
            foreach (self::$givenSites as $uuid => $values) {
                $rows->rows[$uuid] = new Node($values, self::$givenSitesChanged[$uuid] ?? []);
            }
            $this->sites = (object)['site' => $rows];
        }

        public function performValidation($validateFullModel = false)
        {
            return new Messages();
        }
    }
}

namespace OPNsense\Core {
    /* config.xml as SimpleXML gives it, as far as the model and WebGui read it: an element's children of one
       name, which foreach goes through and whose first one a property or a text reads */
    class XmlList implements \IteratorAggregate
    {
        private $items;

        public function __construct(array $items)
        {
            $this->items = $items;
        }

        public function getIterator(): \Iterator
        {
            return new \ArrayIterator($this->items);
        }

        public function __get($name)
        {
            return $this->items[0]->__get($name);
        }

        public function __isset($name)
        {
            return $this->items[0]->__isset($name);
        }

        public function children()
        {
            return $this->items[0]->children();
        }

        public function __toString()
        {
            return (string)$this->items[0];
        }
    }

    class Xml
    {
        public $name;
        public $text;
        public $kids = [];

        public function __construct($name, $text = '', array $kids = [])
        {
            $this->name = $name;
            $this->text = $text;
            foreach ($kids as $kid) {
                $this->kids[] = $kid;
            }
        }

        public function __get($name)
        {
            $found = array_values(array_filter($this->kids, function ($kid) use ($name) {
                return $kid->name === $name;
            }));
            return count($found) ? new XmlList($found) : null;
        }

        public function __isset($name)
        {
            return $this->__get($name) !== null;
        }

        public function children()
        {
            return $this->kids;
        }

        public function getName()
        {
            return $this->name;
        }

        public function __toString()
        {
            return (string)$this->text;
        }
    }

    class Config
    {
        public static $root;

        public static function getInstance()
        {
            return new self();
        }

        public function object()
        {
            return self::$root;
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

    $root = dirname(__DIR__);
    require $root . '/src/opnsense/mvc/app/library/OPNsense/ModSecurity/Site.php';
    require $root . '/src/opnsense/mvc/app/library/OPNsense/ModSecurity/WebGui.php';
    require $root . '/src/opnsense/mvc/app/models/OPNsense/ModSecurity/ModSecurity.php';

    use OPNsense\Base\BaseModel;
    use OPNsense\Core\Config;
    use OPNsense\Core\Xml;
    use OPNsense\ModSecurity\ModSecurity;
    use OPNsense\ModSecurity\Site;
    use OPNsense\ModSecurity\WebGui;

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

    /* --- the table both readings share ------------------------------------------------------------- */

    $cases = json_decode(file_get_contents(__DIR__ . '/fixtures/cases.json'), true);
    foreach ($cases['names']['taken'] as $name) {
        check(Site::nameOk($name), "a host name taken: '$name'");
    }
    foreach ($cases['names']['refused'] as $name) {
        check(!Site::nameOk($name), 'a host name refused: ' . json_encode($name));
    }
    foreach ($cases['normalize'] as [$raw, $want]) {
        check(Site::names($raw) === $want, "names read as kept: '$raw'");
    }
    foreach ($cases['covers'] as [$wildcard, $name, $want]) {
        check(Site::covers($wildcard, $name) === $want, "$wildcard takes $name: " . json_encode($want));
    }
    foreach ($cases['backends']['taken'] as [$raw, $url, $tls]) {
        $found = Site::backend($raw);
        check($found !== null && $found['url'] === $url && $found['tls'] === $tls, "a backend taken: '$raw' as $url");
    }
    foreach ($cases['backends']['refused'] as $raw) {
        check(Site::backend($raw) === null, 'a backend refused: ' . json_encode($raw));
    }
    foreach ($cases['webgui'] as $case) {
        $gui = WebGui::listeners($case['webgui']);
        check($gui === $case['listeners'], 'the web GUI listens on ' . json_encode($case['webgui']) . ': ' . json_encode($gui));
        $found = array_map(function ($c) {
            return $c['port'];
        }, WebGui::conflicts($gui, array_map(function ($p) {
            return $p === null ? '' : (string)$p;
        }, $case['ports']), $case['interfaces']));
        check($found === $case['conflicts'], 'the plugin on ' . json_encode($case['ports']) . ' ' . json_encode($case['interfaces']) .
              ': the GUI holds ' . json_encode($found));
    }

    Config::$root = new Xml('opnsense', '', [
        new Xml('system', '', [new Xml('webgui', '', [new Xml('protocol', 'https'), new Xml('port', ''), new Xml('interfaces', 'lan'),
            new Xml('disablehttpredirect', '1')])]),
        new Xml('cert', '', [new Xml('refid', 'withkey'), new Xml('prv', 'LS0tLS1')]),
        new Xml('cert', '', [new Xml('refid', 'nokey'), new Xml('prv', '')]),
    ]);
    check(WebGui::fromConfig() === ['protocol' => 'https', 'port' => '', 'interfaces' => 'lan', 'disablehttpredirect' => '1'],
          'config.xml\'s web GUI read by its elements, one that is there with no text kept as there');
    check(WebGui::listeners(WebGui::fromConfig()) === ['ports' => [443], 'interfaces' => ['lan']],
          'its redirect turned off: 443 alone, on its LAN');

    /* --- a Save -------------------------------------------------------------------------------------- */

    $on = ['enabled' => '1', 'interfaces' => 'wan', 'http_port' => '80', 'https_port' => '443'];
    $shop = ['enabled' => '1', 'hostnames' => 'www.example.com,example.com', 'backend' => 'http://192.0.2.10:8080',
        'certificate' => 'withkey', 'mode' => 'blocking', 'paranoia' => '2', 'verify' => '1'];
    $intranet = ['enabled' => '1', 'hostnames' => '*.intranet.example.org', 'backend' => 'https://[2001:db8::10]:8443/app',
        'certificate' => '', 'mode' => 'detection', 'paranoia' => '1', 'verify' => '0'];

    /* [[field, message]] of a Save; general: Settings' fields, changed: Settings' changed ones; sites: uuid => fields,
       changedSites: uuid => changed fields; full: the whole model checked */
    function saved($general, $changed, $sites = [], $changedSites = [], $full = false)
    {
        BaseModel::$givenGeneral = $general;
        BaseModel::$givenChanged = $changed;
        BaseModel::$givenSites = $sites;
        BaseModel::$givenSitesChanged = $changedSites;
        $out = [];
        foreach ((new ModSecurity())->performValidation($full) as $message) {
            $out[] = [$message->getField(), $message->getMessage()];
        }
        return $out;
    }

    $moved = new Xml('webgui', '', [new Xml('protocol', 'https'), new Xml('port', '4443'), new Xml('interfaces', 'lan')]);
    $every = new Xml('webgui', '', [new Xml('protocol', 'https')]);
    function gui($webgui)
    {
        Config::$root->kids[0]->kids = [$webgui];
    }

    gui($moved);
    $sites = ['s1' => $shop, 's2' => $intranet];
    check(saved($on, ['enabled'], $sites) === [], 'on, on WAN, the GUI on its LAN at 4443: saved');
    check(saved(['enabled' => '0', 'http_port' => '80', 'https_port' => '443'], ['enabled']) === [],
          'off: saved, whatever the GUI holds');
    gui($every);
    check(saved(['enabled' => '0', 'http_port' => '80', 'https_port' => '443'], ['https_port']) === [],
          'off, the GUI on 443 everywhere: saved - nothing listens');
    $got = saved($on, ['enabled'], $sites);
    check(count($got) === 2 && $got[0][0] === 'general.http_port' && $got[1][0] === 'general.https_port' &&
          strpos($got[1][1], 'The web GUI listens on port 443 on every interface. Move it in System: Settings: Administration') === 0,
          'on, the GUI on 80 and 443 everywhere: both refused on their fields, with how to move the GUI');
    gui(new Xml('webgui', '', [new Xml('protocol', 'https'), new Xml('interfaces', 'lan')]));
    check(saved($on, ['enabled'], $sites) === [], 'the GUI on its LAN, the plugin on WAN: saved');
    $got = saved(array_merge($on, ['interfaces' => '']), ['interfaces'], $sites);
    check(count($got) === 2 && strpos($got[0][1], 'The web GUI listens on port 80 on lan.') === 0,
          'the GUI on its LAN, the plugin on every address: refused, the GUI\'s interfaces named');
    $got = saved(array_merge($on, ['interfaces' => 'wan,lan']), ['interfaces'], $sites);
    check(count($got) === 2, 'the GUI on its LAN, the plugin on WAN and LAN: refused');
    gui($moved);
    check(saved(array_merge($on, ['https_port' => '80']), ['https_port'], $sites) ===
          [['general.https_port', 'HTTP and HTTPS need a port each.']], 'the same port twice: refused');
    check(saved(array_merge($on, ['http_port' => '', 'https_port' => '']), ['http_port'], []) ===
          [['general.http_port', 'Give a port for HTTP, for HTTPS or both, or turn the Web Application Firewall off.']],
          'on with no port: refused');
    check(saved(array_merge($on, ['http_port' => '']), ['http_port'], $sites) ===
          [['general.http_port', 'Enabled sites without a certificate are served over plain HTTP: give an HTTP port, or each of them a certificate.']],
          'no HTTP port, a site without a certificate: said on HTTP port');
    check(saved(array_merge($on, ['https_port' => '']), ['https_port'], $sites) ===
          [['general.https_port', 'Enabled sites with a certificate are served over HTTPS: give an HTTPS port, or take their certificates away.']],
          'no HTTPS port, a site with one: said on HTTPS port');
    check(saved(array_merge($on, ['https_port' => '']), [], $sites) === [],
          'Settings unchanged - a site saved: Settings\' checks not run, as OPNsense\'s own models');
    gui($every);
    check(saved($on, [], $sites) === [], 'Settings unchanged, the GUI moved back since: not said at a site\'s save (Apply says it)');
    check(count(saved($on, [], $sites, [], true)) === 2, 'the whole model checked: said');
    gui($moved);

    $at = 'sites.site.s2.';
    check(saved($on, [], $sites, ['s2' => ['hostnames']]) === [], 'a site saved, its names its own: saved');
    $dup = ['s1' => $shop, 's2' => array_merge($intranet, ['hostnames' => 'example.com'])];
    check(saved($on, [], $dup, ['s2' => ['hostnames']]) === [[$at . 'hostnames', 'example.com is a host name of another site.']],
          'a name another site has: refused on Host names');
    $under = ['s1' => $shop, 's2' => array_merge($intranet, ['hostnames' => '*.example.com'])];
    check(saved($on, [], $under, ['s2' => ['hostnames']]) === [[$at . 'hostnames',
          '*.example.com and www.example.com of another site would take the same requests: a host name belongs to one site.']],
          'a wildcard that takes another site\'s name: refused');
    $taken = ['s1' => array_merge($shop, ['hostnames' => '*.example.com']), 's2' => array_merge($intranet, ['hostnames' => 'a.b.example.com'])];
    check(count(saved($on, [], $taken, ['s2' => ['hostnames']])) === 1, 'a name under another site\'s wildcard: refused');
    $off = ['s1' => array_merge($shop, ['enabled' => '0']), 's2' => array_merge($intranet, ['hostnames' => 'example.com'])];
    check(saved($on, [], $off, ['s2' => ['hostnames']]) === [], 'a name a disabled site has: saved');
    check(saved($on, [], $dup, ['s1' => ['mode']]) !== [], 'the other site saved, the clash its too: said on its own names');
    check(saved($on, [], $dup) === [], 'nothing of the sites changed: not checked');
    $many = ['s2' => array_merge($intranet, ['hostnames' => implode(',', array_map(function ($i) {
        return "n$i.example.com";
    }, range(1, 33)))])];
    check(saved($on, [], $many, ['s2' => ['hostnames']]) === [[$at . 'hostnames', 'A site has 32 host names at most.']],
          'more than 32 names: refused');
    $bad = ['s2' => array_merge($intranet, ['backend' => 'http://192.0.2.10/a/../b'])];
    check(saved($on, [], $bad, ['s2' => ['backend']]) === [[$at . 'backend',
          'A URL of the site\'s server, http:// or https://, such as http://192.0.2.10:8080 or https://intranet.example.com.']],
          'a backend Apache cannot proxy to: refused on Backend');
    $nokey = ['s2' => array_merge($intranet, ['certificate' => 'nokey'])];
    check(saved($on, [], $nokey, ['s2' => ['certificate']]) === [[$at . 'certificate',
          'This certificate has no private key in System: Trust: a site cannot be served with it.']],
          'a certificate without its private key: refused on Certificate');
    $tls = ['s2' => array_merge($intranet, ['certificate' => 'withkey'])];
    check(saved(array_merge($on, ['https_port' => '']), [], $tls, ['s2' => ['certificate']]) === [[$at . 'certificate',
          'Settings has no HTTPS port: give one there, or no certificate here.']], 'a certificate, no HTTPS port: refused');
    check(saved(array_merge($on, ['http_port' => '']), [], $sites, ['s2' => ['mode']]) === [[$at . 'certificate',
          'Settings has no HTTP port: give one there, or a certificate here.']], 'no certificate, no HTTP port: refused');
    check(saved(array_merge($on, ['http_port' => '']), [], ['s2' => array_merge($intranet, ['enabled' => '0'])],
                ['s2' => ['enabled']]) === [], 'a disabled site: not checked');

    /* --- the model's XML in step with common.py -------------------------------------------------------- */

    /* read as text: not every PHP the checks run on has SimpleXML (os-quota's test reads its model the same way) */
    $xml = preg_replace('/<!--.*?-->/s', '', file_get_contents($root . '/src/opnsense/mvc/app/models/OPNsense/ModSecurity/ModSecurity.xml'));
    $common = file_get_contents($root . '/src/opnsense/scripts/modsecurity/common.py');

    function element($xml, $path)
    {
        foreach (explode('/', $path) as $tag) {
            if (!preg_match('#<' . $tag . '\b[^>]*>(.*?)</' . $tag . '>#s', $xml, $m)) {
                return null;
            }
            $xml = $m[1];
        }
        return trim($xml);
    }

    check(element($xml, 'mount') === '//OPNsense/ModSecurity', 'mounted where common.py reads it: OPNsense/ModSecurity');
    check(element($xml, 'general/enabled/Default') === '0', 'off by default');
    preg_match('/^HTTP_PORT = (\d+)$/m', $common, $http);
    preg_match('/^HTTPS_PORT = (\d+)$/m', $common, $https);
    check([element($xml, 'general/http_port/Default'), element($xml, 'general/https_port/Default')] === [$http[1] ?? '', $https[1] ?? ''],
          'the ports where nothing is saved: 80 and 443 in both');
    check(element($xml, 'sites/site/mode/Default') === 'detection' && (bool)preg_match("/^MODES = \\{'detection': 'DetectionOnly', 'blocking': 'On'\\}$/m", $common),
          'a new site in Detection only (settled point 5a); the modes the same in both');
    preg_match_all('#<pl(\d) value="(\d)">#', $xml, $levels);
    check($levels[2] === ['1', '2', '3', '4'] && element($xml, 'sites/site/paranoia/Default') === '1' &&
          (bool)preg_match('/^PARANOIA = \(1, 2, 3, 4\)$/m', $common), 'paranoia levels 1 to 4 (settled point 6a), 1 for a new site');
    preg_match("/^INTERNAL = re\\.compile\\(r'\\^\\(([a-z|]+)\\)\\[0-9\\]\\+\\$'\\)$/m", $common, $internal);
    $if = element($xml, 'general/interfaces/Filters/if');
    check($if === '/^(?!(' . ($internal[1] ?? '?') . ')[0-9]+$).*/', 'Listen interfaces: never os-xgs-npu\'s own links - the pattern common.py has');
    foreach (['oxips0', 'oxmgmt0', 'mvmgmt0'] as $device) {
        check(!preg_match((string)$if, $device), "Listen interfaces: $device never offered");
    }
    preg_match('/^NAMES_MAX = (\d+)$/m', $common, $most);
    check((string)ModSecurity::NAMES_MAX === ($most[1] ?? ''), '32 host names at most in both');
    check(element($xml, 'sites/site/hostnames/IpAllowed') === 'N' && element($xml, 'sites/site/hostnames/FqdnWildcardAllowed') === 'Y',
          'host names: no IP address, a wildcard as the first label');
    $mask = element($xml, 'sites/site/backend/Mask');
    foreach ($cases['backends']['taken'] as [$raw]) {
        check((bool)preg_match($mask, trim($raw)), "the backend's mask lets the form through what Site takes: '" . trim($raw) . "'");
    }

    echo $failed ? "$failed of $checks checks failed\n" : "$checks checks passed\n";
    exit($failed ? 1 : 0);
}
