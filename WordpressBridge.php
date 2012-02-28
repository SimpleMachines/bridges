<?php

/* * **** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is http://code.mattzuba.com code.
 *
 * The Initial Developer of the Original Code is
 * Matt Zuba.
 * Portions created by the Initial Developer are Copyright (C) 2011
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * ***** END LICENSE BLOCK ***** */

/**
 * @package BlogBridger
 * @version 1.1.4
 * @since 1.0
 * @author Matt Zuba <matt@mattzuba.com>
 * @copyright 2011 Matt Zuba
 * @license http://www.mozilla.org/MPL/MPL-1.1.html Mozilla Public License
 */

/**
 * Wordpress Bridge Class
 * 
 * @package BlogBridger
 */
class WordpressBridge {

    /**
     * @var WordpressBridge Instance of a class
     */
    protected static $instance;
    /**
     * @var array Comma separated list of hooks this class implements
     */
    protected $hooks = array();
    /**
     * @var boolean Should the hooks only be installed once?
     */
    protected $persistHooks = FALSE;
    private $enabled = FALSE;
    // Wordpress settings
    private $db_connection, $db_prefix;
    private $key_salts = array();
    private $wpUser;
    private $bypassRegisterHook = FALSE;

    /**
     * Setup the object, gather all of the relevant settings
     */
    protected function __construct() {
        global $sourcedir, $modSettings;

        $this->hooks = array(
            'integrate_pre_load',
            'integrate_load_theme',
            'integrate_admin_areas',
            'integrate_validate_login',
            'integrate_login',
            'integrate_logout',
            'integrate_register',
            'integrate_reset_pass',
            'integrate_change_member_data',
            'integrate_exit',
        );

        if (!$this->persistHooks)
            $this->installHooks();

        require_once($sourcedir . '/WordpressUser.php');

        $this->enabled = !empty($modSettings['wordpress_enabled']);
    }

    /**
     * Let's try the singleton method
     *
     * @return void
     */
    public static function getInstance() {
        $class = __CLASS__;
        if (!isset(self::$instance) || !(self::$instance instanceof $class))
            self::$instance = new $class();

        return self::$instance;
    }

    /**
     * Installs the hooks to be used by this module.
     */
    public function installHooks() {
        foreach ($this->hooks as $hook)
            add_integration_function($hook, __CLASS__ . '::handleHook', $this->persistHooks);
    }

    /**
     * Takes all call_integration_hook calls from SMF and figures out what
     * method to call within the class
     */
    public static function handleHook() {
        $backtrace = debug_backtrace();
        $method = NULL;
        $args = NULL;
        foreach ($backtrace as $item)
            if ($item['function'] === 'call_integration_hook') {
                $method = $item['args'][0];
                $args = !empty($item['args'][1]) ? $item['args'][1] : array();
                break;
            }

        if (!isset($method) || !is_callable(array(self::$instance, $method)))
            trigger_error('Invalid call to handleHook', E_USER_ERROR);

        return call_user_func_array(array(self::$instance, $method), $args);
    }

    public function integrate_pre_load() {
        global $boardurl;

        // Check if we came from Wordpress and if so, redirect to the appropriate action
        if (!isset($_GET['fromWp']) || empty($_GET['url']) || time() - (int) $_GET['fromWp'] > 30 || empty($_SERVER['HTTP_REFERER']))
            return;

        $referer = parse_url($_SERVER['HTTP_REFERER']);

        // We don't want to allow cross domain shit
        if (empty($referer['host']))
            return;

        $boardhost = parse_url($boardurl, PHP_URL_HOST);
        if ($boardhost !== $referer['host']) {
            // Compare them, TLD must at least match
            $boardHostParts = array_reverse(explode('.', $boardhost));
            $refererHostParts = array_reverse(explode('.', $referer['host']));
            $matches = 0;
            while (!empty($boardHostParts) && !empty($refererHostParts))
                $matches += array_shift($boardHostParts) === array_shift($refererHostParts) ? 1 : 0;
            if ($matches < 2)
                return;
        }

        define('WIRELESS', FALSE);
        $_SERVER['REQUEST_URL'] = !empty($_SERVER['REQUEST_URL']) ? $_SERVER['REQUEST_URL'] : '';

        $orgin = parse_url($_GET['url']);
        // Coming from wp-login.php?
        if (strpos($orgin['path'], 'wp-login.php') !== FALSE) {
            if (empty($orgin['query']))
                $orgin['query'] = 'action=login';
            $query = array();
            parse_str($orgin['query'], $query);
            if (empty($query['action']))
                $query['action'] = 'login';
            switch ($query['action']) {
                case 'register':
                    redirectexit('action=register');
                    break;

                case 'logout':
                    // Need to load the session real quick so we can properly logout and redirect
                    loadSession();
                    $_SESSION['logout_url'] = $_SERVER['HTTP_REFERER'];
                    redirectexit('action=logout&' . $_SESSION['session_var'] . '=' . $_SESSION['session_value']);
                    break;

                case 'lostpassword':
                case 'retrievepassword':
                    redirectexit('action=reminder');
                    break;

                default:
                    redirectexit('action=login&wp_redirect=' . $this->encodeRedirect($_SERVER['HTTP_REFERER']));
                    break;
            }
        }
    }

    /**
     * Load the language files for the bridge settings
     */
    public function integrate_load_theme() {
        loadLanguage('WordpressBridge');
    }

    /**
     * Adds the Wordpress menu options to SMF's admin panel
     *
     * @param array &$admin_areas Admin areas from SMF
     */
    public function integrate_admin_areas(&$admin_areas) {
        global $txt, $modSettings;

        // We insert it after Features and Options
        $counter = 0;
        foreach ($admin_areas['config']['areas'] as $area => $dummy)
            if (++$counter && $area == 'featuresettings')
                break;

        $admin_areas['config']['areas'] = array_merge(
                array_slice($admin_areas['config']['areas'], 0, $counter, TRUE),
                array('wordpress' => array(
                        'label' => $txt['wordpress bridge'],
                        'function' => create_function(NULL, 'WordpressBridge::getInstance()->ModifyWordpressBridgeSettings();'),
                        'icon' => 'administration.gif',
                        'subsections' => array(
                            'bridge' => array($txt['wordpress bridge settings']),
                            'roles' => array($txt['wordpress roles'], 'enabled' => !empty($modSettings['wordpress_path'])),
                        ),
                )),
                array_slice($admin_areas['config']['areas'], $counter, NULL, TRUE)
        );
    }

    /**
     * This checks to see if the user exists in WP or not.  If they do but don't
     * exist in SMF, the SMF user is created.  If they are in SMF but not WP,
     * they are created in WP.  If they exist in both or don't exist in either,
     * we fall through and let SMF handle it.
     *
     * @param string $user Username
     * @param string $hashPasswd Hashed password from SMF
     * @return string 'retry' if we need a non-hashed password or '' if we are okay 
     */
    public function integrate_validate_login($user, $hashPasswd) {
        global $smcFunc, $sourcedir, $modSettings, $txt;

        if (!$this->enabled)
            return '';

        $this->loadWordpressSettings();

        // Check if they exist in Wordpress
        $this->wpUser = new WordpressUser($this->db_prefix, $this->db_connection, $user);

        // We need to know if they exist in SMF too
        $request = $smcFunc['db_query']('', '
			SELECT *
			FROM {db_prefix}members
			WHERE member_name = {string:user}
			LIMIT 1',
                array(
                    'user' => $user,
            ));
        $smfUser = $smcFunc['db_num_rows']($request) > 0 ? $smcFunc['db_fetch_assoc']($request) : FALSE;
        $smcFunc['db_free_result']($request);

        // Not in either table, or in both, fall through
        if ((!isset($this->wpUser->ID) && !$smfUser) || (isset($this->wpUser->ID) && $smfUser))
            return '';

        // A hashed password but missing user requires a retry to populate the user
        if ($hashPasswd !== NULL)
            return 'retry';

        $roleMaps = !empty($modSettings['wordpress_role_maps']) ? unserialize($modSettings['wordpress_role_maps']) : array('smf' => array(), 'wp' => array());

        // Create a SMF user
        if (isset($this->wpUser->ID)) {
            // First make sure they used the right password
            if (!$this->wpUser->isLegit($_POST['passwrd']))
                return 'retry';

            $role = array_shift(array_flip(@unserialize($this->wpUser->role)));

            $regOptions = array(
                'interface' => 'wordpress_bridge',
                'auth_method' => 'password',
                'username' => $this->wpUser->user_login,
                'email' => $this->wpUser->user_email,
                'require' => 'nothing',
                'password' => $_POST['passwrd'],
                'password_check' => $_POST['passwrd'],
                'check_password_strength' => FALSE,
                'check_email_ban' => FALSE,
                'extra_register_vars' => array(
                    'id_group' => !empty($roleMaps['wp'][$role]) ? $roleMaps['wp'][$role] : 0,
                    'real_name' => !empty($this->wpUser->display_name) ? $this->wpUser->display_name : $this->wpUser->user_login,
                    'date_registered' => strtotime($this->wpUser->user_registered),
                ),
            );

            require_once($sourcedir . '/Subs-Members.php');
            $this->bypassRegisterHook = TRUE;
            $errors = registerMember($regOptions, TRUE);

            // Errors have to be dealt with
            if (!is_array($errors))
                return '';

            log_error(sprintf($txt['wordpress cannot sync'], $this->wpUser->user_login) . "\n" . print_r($errors, TRUE), 'user');
            fatal_lang_error('wordpress cannot sync', FALSE, array($this->wpUser->user_login));
        }

        // Create a WP user
        else {
            $this->wpUser->user_login = $smfUser['member_name'];
            $this->wpUser->user_nicename = $smfUser['member_name'];
            $this->wpUser->user_email = $smfUser['email_address'];
            $this->wpUser->user_pass = $_POST['passwrd'];
            $this->wpUser->user_url = $smfUser['website_url'];
            $this->wpUser->user_registered = gmdate("Y-m-d H:i:s", $smfUser['date_registered']);
            $this->wpUser->user_status = 0;
            $this->wpUser->display_name = $smfUser['real_name'];
            $this->wpUser->role = $smfUser['id_group'];

            $this->wpUser->save();
            return '';
        }
    }

    /**
     * Logs a user into Wordpress by setting cookies
     *
     * @param string $user Username
     * @param string $hashPasswd SMF's version of the hashed password (unused)
     * @param int $cookieTime Time cookie should be live for
     * @return void
     */
    public function integrate_login($user, $hashPasswd, $cookieTime) {
        if (!$this->enabled)
            return;

        $this->loadWordpressSettings();

        if (!isset($this->wpUser->ID) && ($this->wpUser = new WordpressUser($this->db_prefix, $this->db_connection, $user)) === FALSE)
            return;

        $expires = 60 * $cookieTime;
        $ssl = !empty($this->wpUser->use_ssl);

        $paths = $this->getCookiePaths($ssl);

        // We're doing two schemes - (secure_)auth and logged_in (salt is secret_key + salt)
        $auth_cookie_data = $this->createCookieData(time() + $expires, ($ssl ? 'secure_' : '') . 'auth');
        $logged_cookie_data = $this->createCookieData(time() + $expires, 'logged_in');

        $this->setcookie($paths['logged_in_cookie_name'], $logged_cookie_data, $expires, $paths['cookie_path'], $paths['cookie_domain'], $ssl, TRUE);
        if ($paths['cookie_path'] !== $paths['site_cookie_path'])
            $this->setcookie($paths['logged_in_cookie_name'], $logged_cookie_data, $expires, $paths['site_cookie_path'], $paths['cookie_domain'], $ssl, TRUE);
        $this->setcookie($paths['auth_cookie_name'], $auth_cookie_data, $expires, $paths['admin_cookie_path'], $paths['cookie_domain'], $ssl, TRUE);
        $this->setcookie($paths['auth_cookie_name'], $auth_cookie_data, $expires, $paths['plugin_cookie_path'], $paths['cookie_domain'], $ssl, TRUE);
    }

    /**
     * Deletes the Wordpress cookies
     *
     * @param string $user Username, unused as WP doesn't track this in a database
     * @return void
     */
    public function integrate_logout($user) {
        if (!$this->enabled)
            return;

        $paths = $this->getCookiePaths(TRUE);
        $expires = -90000;
        $this->setcookie($paths['auth_cookie_name'], ' ', $expires, $paths['plugin_cookie_path'], $paths['cookie_domain'], TRUE, TRUE);
        $this->setcookie($paths['auth_cookie_name'], ' ', $expires, $paths['admin_cookie_path'], $paths['cookie_domain'], TRUE, TRUE);
        $this->setcookie($paths['logged_in_cookie_name'], ' ', $expires, $paths['site_cookie_path'], $paths['cookie_domain'], TRUE, TRUE);
        $this->setcookie($paths['logged_in_cookie_name'], ' ', $expires, $paths['cookie_path'], $paths['cookie_domain'], TRUE, TRUE);

        $paths = $this->getCookiePaths(FALSE);
        $expires = -90000;
        $this->setcookie($paths['auth_cookie_name'], ' ', $expires, $paths['plugin_cookie_path'], $paths['cookie_domain'], FALSE, TRUE);
        $this->setcookie($paths['auth_cookie_name'], ' ', $expires, $paths['admin_cookie_path'], $paths['cookie_domain'], FALSE, TRUE);
        $this->setcookie($paths['logged_in_cookie_name'], ' ', $expires, $paths['site_cookie_path'], $paths['cookie_domain'], FALSE, TRUE);
        $this->setcookie($paths['logged_in_cookie_name'], ' ', $expires, $paths['cookie_path'], $paths['cookie_domain'], FALSE, TRUE);
    }

    /**
     * Takes the registration data from SMF, creates a new user in WordPress
     * and populates it's data and saves.
     *
     * @param array &$regOptions Array of Registration data
     * @param array &$theme_vars Theme specific options (we don't use these)
     * @return void 
     */
    public function integrate_register(&$regOptions, &$theme_vars) {
        if (!$this->enabled || $this->bypassRegisterHook)
            return;

        $this->loadWordpressSettings();

        $this->wpUser = new WordpressUser($this->db_prefix, $this->db_connection);

        $this->wpUser->user_login = $regOptions['register_vars']['member_name'];
        $this->wpUser->user_nicename = $regOptions['register_vars']['member_name'];
        $this->wpUser->user_email = $regOptions['register_vars']['email_address'];
        $this->wpUser->user_pass = $regOptions['password'];
        $this->wpUser->user_url = $regOptions['register_vars']['website_url'];
        $this->wpUser->user_registered = gmdate("Y-m-d H:i:s", $regOptions['register_vars']['date_registered']);
        $this->wpUser->user_status = 0;
        $this->wpUser->display_name = $regOptions['register_vars']['member_name'];
        $this->wpUser->role = !empty($regOptions['register_vars']['id_group']) ? $regOptions['register_vars']['id_group'] : 0;
        $this->wpUser->save();
    }

    /**
     * Called when a user resets their password in SMF.  It will properly hash
     * it into a WordPress compatible version and modify the user in WordPress.
     *
     * @param string $user Username to change
     * @param string $user2 Username to change (again?)
     * @param string $password Plaintext password to reset to
     * @return void 
     */
    public function integrate_reset_pass($user, $user2, $password) {
        global $context, $modSettings;

        if (!$this->enabled)
            return;

        $this->loadWordpressSettings();

        $this->wpUser = new WordpressUser($this->db_prefix, $this->db_connection, $user);

        if (!isset($this->wpUser->ID))
            return;

        $this->wpUser->user_pass = $password;
        $this->wpUser->save();

        if ($context['user']['is_owner'])
            $this->integrate_login($user, NULL, $modSettings['cookieTime']);
    }

    /**
     * Updates a users' WordPress information when they change in SMF
     *
     * @param array $member_names All of the members to change
     * @param string $var Variable that is being updated in SMF
     * @param mixed $data Data being updated in SMF
     * @return void 
     */
    public function integrate_change_member_data($member_names, $var, $data) {
        if (!$this->enabled)
            return;

        // SMF var => Wordpress user var
        $integrateVars = array(
            'member_name' => 'user_login',
            'real_name' => 'display_name',
            'email_address' => 'user_email',
            'id_group' => 'role',
            'website_url' => 'user_url',
        );

        if (!isset($integrateVars[$var]))
            return;

        $this->loadWordpressSettings();

        // Load the WP user class
        $wpUser = new WordpressUser($this->db_prefix, $this->db_connection);

        foreach ($member_names as $user) {
            if (!$wpUser->load($user))
                continue;

            // if this is a member_name, we have to update the nicename too
            if ($var === 'member_name')
                $wpUser->user_nicename = $data;

            $wpUser->{$integrateVars[$var]} = $data;
            $wpUser->save();
        }
    }

    /**
     * Handles redirecting back to wordpress after logins
     */
    public function integrate_exit() {
        if (!empty($_GET['wp_redirect']) && ($url = $this->decodeRedirect($_GET['wp_redirect'])) !== FALSE)
            $_SESSION['login_url'] = $url;
    }

    /**
     * Base admin callback function
     */
    public function ModifyWordpressBridgeSettings() {
        global $txt, $context, $sourcedir;

        require_once($sourcedir . '/ManageSettings.php');

        $context['page_title'] = $txt['wordpress bridge'];

        $subActions = array(
            'bridge' => 'ModifyBridgeSettings',
            'roles' => 'ManageRoles',
        );

        loadGeneralSettingParameters($subActions, 'bridge');
        loadTemplate('WordpressBridge');

        // Load up all the tabs...
        $context[$context['admin_menu_name']]['tab_data'] = array(
            'title' => $txt['wordpress bridge'],
            'description' => '',
            'tabs' => array(
                'bridge' => array(
                    'description' => $txt['wordpress settings desc'],
                ),
                'roles' => array(
                    'description' => $txt['wordpress roles desc'],
                ),
            ),
        );

        $this->$subActions[$_REQUEST['sa']]();
    }

    /*     * ***  Private functions beyond this point **** */

    /**
     * General Settings page for bridge in SMF
     */
    private function ModifyBridgeSettings() {
        global $scripturl, $txt, $context, $boarddir, $modSettings;

        $config_vars = array(
            array('check', 'wordpress_enabled'),
            'path' => array('text', 'wordpress_path', 'size' => 50, 'subtext' => $txt['wordpress path desc'],),
        );

        // Saving?
        if (isset($_GET['save'])) {
            checkSession();

            if (isset($_POST['fix-file'])) {
                $fix = array_shift(array_keys($_POST['fix-file']));
                list($action, $file) = explode('-', $fix);
                $method = 'fixWp' . ucfirst($file) . 'File';
                $this->$method($action == 'revert');
            } else {
                if (!empty($_POST['wordpress_path']) && basename($_POST['wordpress_path']) === 'wp-config.php')
                    $_POST['wordpress_path'] = dirname($_POST['wordpress_path']);

                if (!empty($_POST['wordpress_path']) && is_dir($_POST['wordpress_path']))
                    $_POST['wordpress_path'] = realpath($_POST['wordpress_path']);

                if (empty($_POST['wordpress_path']) || !file_exists($_POST['wordpress_path'] . '/wp-config.php'))
                    unset($_POST['wordpress_enabled']);

                $save_vars = $config_vars;

                saveDBSettings($save_vars);
            }
            redirectexit('action=admin;area=wordpress;sa=bridge');
        }

        if (!empty($modSettings['wordpress_path']) && !file_exists($modSettings['wordpress_path'] . '/wp-config.php'))
            $config_vars['path']['subtext'] .= ' ' . $txt['wordpress path desc extra2'];
        elseif (empty($modSettings['wordpress_path']) && ($modSettings['wordpress_path'] = $this->findWordpressPath($boarddir . '/..')) != '')
            $config_vars['path']['subtext'] .= ' ' . $txt['wordpress path desc extra'];
        else
            $config_vars = array_merge($config_vars, array(
                    '',
                    array('callback', 'wordpress_edit_files'),
                ));

        $context['post_url'] = $scripturl . '?action=admin;area=wordpress;sa=bridge;save';
        if (!empty($modSettings['wordpress_path']) && ($errors = $this->findConfigErrors()) !== FALSE)
            $context['settings_insert_above'] = '<div class="errorbox">' . $txt['wordpress problems'] . '<ul><li>' . implode('</li><li>', $errors) . '</li></ul></div>';

        prepareDBSettingContext($config_vars);
    }

    /**
     * Called in SMF admin panel for managing roles
     */
    private function ManageRoles() {
        global $txt, $scripturl, $context, $settings, $smcFunc, $modSettings;

        // Get the basic group data.
        $request = $smcFunc['db_query']('', '
			SELECT id_group, group_name
			FROM {db_prefix}membergroups
			WHERE min_posts = -1
			ORDER BY CASE WHEN id_group < 4 THEN id_group ELSE 4 END, group_name',
                array()
        );
        $context['smfGroups'] = array(
            '0' => array(
                'id_group' => 0,
                'group_name' => $txt['membergroups_members'],
            ),
        );
        while ($row = $smcFunc['db_fetch_assoc']($request))
            $context['smfGroups'][$row['id_group']] = array(
                'id_group' => $row['id_group'],
                'group_name' => $row['group_name'],
            );
        $smcFunc['db_free_result']($request);

        $this->loadWordpressSettings();

        // Get the WP roles
        $request = $smcFunc['db_query']('', '
			SELECT option_value
			FROM {raw:wp_prefix}options
			WHERE option_name LIKE {string:wp_roles}',
                array(
                    'wp_prefix' => $this->db_prefix,
                    'wp_roles' => 'wp_user_roles',
                ),
                $this->db_connection);
        list($wp_roles) = $smcFunc['db_fetch_row']($request);
        $smcFunc['db_free_result']($request);
        $context['wpRoles'] = unserialize($wp_roles);

        // Lastly, our mapping
        $context['wpMapping'] = !empty($modSettings['wordpress_role_maps']) ? unserialize($modSettings['wordpress_role_maps']) : array('smf' => array(), 'wp' => array());

        $config_vars = array(
            array('title', 'wordpress wp to smf mapping'),
            array('desc', 'wordpress wp to smf mapping desc'),
            array('callback', 'wordpress_edit_roles'),
            array('title', 'wordpress smf to wp mapping'),
            array('desc', 'wordpress smf to wp mapping desc'),
            array('callback', 'wordpress_edit_membergroups'),
        );

        $context['post_url'] = $scripturl . '?action=admin;area=wordpress;sa=roles;save';

        if (isset($_GET['save'])) {
            checkSession();

            foreach ($_POST['smfroles'] as $id_group => $role)
                if (empty($context['smfGroups'][$id_group]) || empty($context['wpRoles'][$role]))
                    unset($_POST['smfroles'][$id_group]);

            foreach ($_POST['wproles'] as $role => $id_group)
                if (empty($context['smfGroups'][$id_group]) || empty($context['wpRoles'][$role]))
                    unset($_POST['wproles'][$role]);

            $_POST['wordpress_role_maps'] = serialize(array('smf' => $_POST['smfroles'], 'wp' => $_POST['wproles']));

            $save_vars = array(
                array('text', 'wordpress_role_maps'),
            );
            saveDBSettings($save_vars);

            redirectexit('action=admin;area=wordpress;sa=roles');
        }

        prepareDBSettingContext($config_vars);
    }

    /**
     * Checks the Wordpress database for appropriate settings and creates the
     * necessary paths for the Wordpress cookies.  We could have just set the 
     * path to /, but that would be less secure.
     *
     * @staticvar array $paths All of needed paths and URLs
     * @param bool $ssl True for SSL setting
     * @return array Paths and URLs
     */
    private function getCookiePaths($ssl) {
        global $smcFunc;
        static $paths;

        if (!empty($paths) && (($ssl && strpos($paths['auth_cookie_name'], 'sec_') !== FALSE || !$ssl && strpos($paths['auth_cookie_name'], 'sec_') === FALSE)))
            return $paths;

        $this->loadWordpressSettings();

        $request = $smcFunc['db_query']('', '
			SELECT option_name, option_value
			FROM {raw:wp_prefix}options
			WHERE option_name IN ({array_string:options})',
                array(
                    'wp_prefix' => $this->db_prefix,
                    'options' => array('siteurl', 'home'),
                ),
                $this->db_connection);
        while (($row = $smcFunc['db_fetch_assoc']($request)))
            $$row['option_name'] = rtrim($row['option_value'], '/');
        $smcFunc['db_free_result']($request);
        $main_hash = !empty($siteurl) ? md5($siteurl) : '';

        $paths['auth_cookie_name'] = 'wordpress_' . ($ssl ? 'sec_' : '') . $main_hash;
        $paths['logged_in_cookie_name'] = 'wordpress_logged_in_' . $main_hash;

        $paths['cookie_domain'] = FALSE;
        // Path to main site
        $paths['cookie_path'] = preg_replace('~https?://[^/]+~i', '', $home . '/');
        // Path to wordpress files
        $paths['site_cookie_path'] = preg_replace('~https?://[^/]+~i', '', $siteurl . '/');
        // Path to WPAdmin
        $paths['admin_cookie_path'] = $paths['site_cookie_path'] . 'wp-admin';
        // Path to wp plugins
        $paths['plugin_cookie_path'] = $paths['site_cookie_path'] . 'wp-content/plugins';

        return $paths;
    }

    /**
     * Creates the cookie data needed for Wordpress.
     *
     * @param int $expiration Total time to cookie expiration
     * @param string $scheme What type of cookie are we creating?
     * @return string Cookie data
     */
    private function createCookieData($expiration, $scheme) {
        $passPart = substr($this->wpUser->user_pass, 8, 4);

        switch ($scheme) {
            case 'auth':
                $salt = $this->key_salts['auth_key'] . $this->key_salts['auth_salt'];
                break;

            case 'secure_auth':
                $salt = $this->key_salts['secure_auth_key'] . $this->key_salts['secure_auth_salt'];
                break;

            case 'logged_in':
                $salt = $this->key_salts['logged_in_key'] . $this->key_salts['logged_in_salt'];
                break;
        }

        $firstPassData = $this->wpUser->user_login . $passPart . '|' . $expiration;
        $firstPassHash = hash_hmac('md5', $firstPassData, $salt);

        $secondPassData = $this->wpUser->user_login . '|' . $expiration;
        $secondPassHash = hash_hmac('md5', $secondPassData, $firstPassHash);

        $cookieData = $this->wpUser->user_login . '|' . $expiration . '|' . $secondPassHash;
        return $cookieData;
    }

    /**
     * Attempts to find wp-config.php based on a given path.  Recursive function.
     *
     * @param string $path Base path to start with (needs to be a directory)
     * @param int $level Current depth of search
     * @param int $depth Maximum depth to go
     * @return string Path if file found, empty string if not
     */
    private function findWordpressPath($path, $depth = 3, $level = 1) {
        if ($level > $depth)
            return '';

        // If we found the file return it
        $files = glob($path . '/wp-config.php', GLOB_NOSORT);
        if (!empty($files))
            return realpath($path);

        // Didn't find it, do a directory search
        $dirs = glob($path . '/*', GLOB_ONLYDIR | GLOB_NOSORT);
        foreach ($dirs as $dir) {
            $value = $this->findWordpressPath($dir, $depth, $level + 1);
            if (!empty($value))
                return $value;
        }
    }

    /**
     * Checks various settings and Wordpress files to make sure they're all
     * correct for us to operate properly
     *
     * @return mixed FALSE on no errors or array of errors 
     */
    private function findConfigErrors() {
        global $modSettings, $txt, $context;

        $context['wp-files'] = array();

        // Check wp-login.php
        $context['wp-files'][] = array(
            'title' => 'wordpress edit login file',
            'name' => 'login',
            'fix' => strpos($this->readWpFile($modSettings['wordpress_path'] . '/wp-login.php'), '?fromWp=') === FALSE,
        );

        $errors = array();
        foreach ($context['wp-files'] as $file)
            if ($file['fix'])
                $errors[] = $txt[$file['title'] . ' failed'];

        if (!is_writable($modSettings['wordpress_path']))
            $errors[] = $txt['wordpress path not writable'];

        return!empty($errors) ? $errors : FALSE;
    }

    /**
     * Loads all of the Wordpress settings and creates a database connection
     * to Wordpress.  Safe to be called multiple times during script execution.
     *
     * @return bool Will always return true, fatal error otherwise
     */
    private function loadWordpressSettings() {
        global $modSettings, $smcFunc;

        if (is_resource($this->db_connection))
            return TRUE;

        if (empty($modSettings['wordpress_path']) || !is_readable($modSettings['wordpress_path'] . '/wp-config.php'))
            fatal_lang_error('wordpress no config', 'general');

        // Read in the WP config file
        $config = $this->readWpFile($modSettings['wordpress_path'] . '/wp-config.php');

        // Find the DB info
        $matches = array();
        preg_match_all('~(DB_.*?)\', \'(.*?)\'~', $config, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            if ($match[1] === 'DB_HOST')
                $db_server = $match[2];
            elseif ($match[1] === 'DB_NAME')
                $db_name = $match[2];
            elseif ($match[1] === 'DB_USER')
                $db_user = $match[2];
            elseif ($match[1] === 'DB_PASSWORD')
                $db_passwd = $match[2];
        }

        // Fetch the keys/salts for cookies
        $matches = array();
        preg_match_all('~\'(.*?_(?:KEY|SALT))\',\s*\'(.*?)\'~', $config, $matches, PREG_SET_ORDER);
        foreach ($matches as $match)
            $this->key_salts[strtolower($match[1])] = $match[2];

        // Database prefix
        $match = array();
        preg_match('~table_prefix\s*=\s*\'(.*?)\'~', $config, $match);
        $this->db_prefix = $match[1];

        // Establish the database connection too
        if ($db_server === $GLOBALS['db_server'] && $db_user === $GLOBALS['db_user'] && $db_name === $GLOBALS['db_name'])
            $this->db_connection = $GLOBALS['db_connection'];
        else {
            $this->db_connection = mysql_connect($db_server, $db_user, $db_passwd, TRUE);
            if (!$this->db_connection || !mysql_select_db($db_name, $this->db_connection))
                fatal_lang_error('wordpress cannot connect', 'critical');
        }

        // Check the keys/salts
        $required = array_flip(array('auth_key', 'secure_auth_key', 'logged_in_key', 'auth_salt', 'secure_auth_salt', 'logged_in_salt'));
        $missing = array_diff_key($required, $this->key_salts);
        if (count($missing) > 0) {
            $missing = array_flip($missing);
            $request = $smcFunc['db_query']('', '
				SELECT option_name, option_value
				FROM {raw:wp_prefix}options
				WHERE option_name IN ({array_string:keys})',
                    array(
                        'wp_prefix' => $this->db_prefix,
                        'keys' => $missing,
                    ),
                    $this->db_connection);
            while (($row = $smcFunc['db_fetch_assoc']($request)))
                $this->key_salts[$row['option_name']] = $row['option_value'];

            // One last check
            $missing = array_diff_key($required, $this->key_salts);
            if (count($missing) > 0)
                fatal_lang_error('wordpress invalid keys', 'critical');

            return TRUE;
        }
    }

    /**
     * This is used to read in a Wordpress file using one of as many methods
     * as possible in an effort to provide maximum portability.
     *
     * @param string $path Full path to file wanting to be read
     * @return string Contents of file
     */
    private function readWpFile($path) {
        $methods = array(
            'file_get_contents',
            'file',
            'fopen',
            'shell_exec',
            'exec',
            'popen',
            'system',
            'passthru',
        );

        $disabled_functions = explode(',', @ini_get('disable_functions'));

        // Determine OS
        if (strpos(strtolower(php_uname()), 'win') === 0) {
            $command = 'type ' . escapeshellcmd($path);
            if (version_compare('5.3', PHP_VERSION, '>'))
                $command = '"' . $command . '"';
        }
        else
            $command = 'cat ' . escapeshellcmd($path);

        foreach ($methods as $method) {
            if (in_array($method, $disabled_functions))
                continue;

            if ($method === 'file_get_contents')
                return file_get_contents($path);

            if ($method === 'file')
                return implode('', file($path));

            if ($method === 'fopen' || $method === 'popen') {
                if ($method === 'fopen')
                    $handle = fopen($path, 'r');
                else
                    $handle = popen($command, 'r');
                $string = '';
                while (!feof($handle))
                    $string .= fread($handle, 4096);
                if ($method === 'fopen')
                    fclose($handle);
                else
                    pclose($handle);
                return $string;
            }

            if ($method === 'shell_exec')
                return shell_exec($command);

            if ($method === 'exec') {
                $output = array();
                exec($command, $output);
                return implode("\n", $output);
            }

            if ($method === 'system' || $method === 'passthru') {
                ob_start();
                $method($command);
                $output = ob_get_clean();
                return $output;
            }
        }

        // If we got here, nothing succeeded
        fatal_lang_error('wordpress cannot read', 'critical', array(implode(', ', $methods)));
    }

    private function backupFile($path) {
        $backupName = '~' . basename($path);
        copy($path, dirname($path) . '/' . $backupName);
    }

    private function fixWpLoginFile($revert = FALSE) {
        global $modSettings, $scripturl;

        $path = $modSettings['wordpress_path'] . '/wp-login.php';
        $this->backupFile($path);
        $data = $this->readWpFile($path);

        // Remove any existing redirect if there is one
        $data = preg_replace("~wp_redirect.+?fromWp=.+\nexit\(\);\n\n~i", '', $data);
        if ($revert)
            return file_put_contents($path, $data);

        // Insert the new one
        $data = str_replace('// Redirect to https login if forced to use SSL', "wp_redirect('$scripturl?fromWp=' . time() . '&url=' . \$_SERVER['REQUEST_URI'], 302);\nexit();\n\n// Redirect to https login if forced to use SSL", $data);

        file_put_contents($path, $data);
    }

    private function encodeRedirect($url) {
        $crc = dechex(sprintf('%u', crc32($url)));
        $url = $crc . '::' . time() . '::' . $url;

        if (function_exists('gzdeflate'))
            $url = gzdeflate($url, 9);

        // Finally, encoded it
        return base64_encode($url);
    }

    private function decodeRedirect($string) {
        $string = base64_decode($string);

        if (function_exists('gzinflate'))
            $string = gzinflate($string);

        @list($crc,, $url) = explode('::', $string);
        if (empty($url) || $crc !== dechex(sprintf('%u', crc32($url))))
            return FALSE;

        return $url;
    }

    /**
     * Licensed under CC-BY.
     * Obtained from http://www.php.net/manual/en/function.setcookie.php#81398
     *
     * A better alternative (RFC 2109 compatible) to the php setcookie() function
     *
     * @param string Name of the cookie
     * @param string Value of the cookie
     * @param int Lifetime of the cookie
     * @param string Path where the cookie can be used
     * @param string Domain which can read the cookie
     * @param bool Secure mode?
     * @param bool Only allow HTTP usage?
     * @return bool True or false whether the method has successfully run
     */
    private function setcookie($name, $value='', $maxage=NULL, $path='', $domain='', $secure=false, $HTTPOnly=false) {
        $ob = ini_get('output_buffering');

        // Abort the method if headers have already been sent, except when output buffering has been enabled
        if (headers_sent() && (bool) $ob === false || strtolower($ob) === 'off')
            return false;

        if (isset($maxage)) {
            $expires = gmdate('D, d-M-Y H:i:s', time() + $maxage) . ' GMT';
            if ((int) $maxage < 0)
                $maxage = 0;
        }

        if (!empty($domain)) {
            // Fix the domain to accept domains with and without 'www.'.
            if (strtolower(substr($domain, 0, 4)) === 'www.')
                $domain = substr($domain, 4);
            // Add the dot prefix to ensure compatibility with subdomains
            if (substr($domain, 0, 1) != '.')
                $domain = '.' . $domain;

            // Remove port information.
            $port = strpos($domain, ':');

            if ($port !== false)
                $domain = substr($domain, 0, $port);
        }

        header('Set-Cookie: ' . rawurlencode($name) . '=' . rawurlencode($value)
            . (empty($domain) ? '' : '; Domain=' . $domain)
            . (!isset($maxage) ? '' : '; Max-Age=' . $maxage)
            . (empty($expires) ? '' : '; Expires=' . $expires)
            . (empty($path) ? '' : '; Path=' . $path)
            . (!$secure ? '' : '; Secure')
            . (!$HTTPOnly ? '' : '; HttpOnly'), false);
        return true;
    }

}

if (defined('SMF'))
    WordpressBridge::getInstance();
