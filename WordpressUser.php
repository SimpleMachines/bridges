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
 * @version 1.0
 * @since 1.0
 * @author Matt Zuba <matt@mattzuba.com>
 * @copyright 2011 Matt Zuba
 * @license http://www.mozilla.org/MPL/MPL-1.1.html Mozilla Public License
 */

/**
 * Wordpress User Class
 *
 * @package BlogBridger
 */
class WordpressUser {

    private $password;
    private $properties = array();
    private $db_prefix;
    private $db_connection;

    /**
     * Creates an instance of a wordpress user.  Attempts to preload the user
     * if one is given
     *
     * @param string $db_prefix Wordpress database prefix
     * @param resource $db_connection Connection to wordpress database
     * @param string $user Username to search for in Wordpress
     * @return void
     */
    public function __construct($db_prefix, $db_connection, $user = '') {
        global $sourcedir;

        require_once($sourcedir . '/WordpressPassword.php');

        $this->password = new WordpressPassword(8);

        $this->db_prefix = $db_prefix;

        $this->db_connection = $db_connection;

        $this->load($user);
    }

    /**
     * Loads a user up into the private variables
     *
     * @param string $user User name to find in WordPress
     * @return boolean True if the user was loaded
     */
    public function load($user) {
        global $smcFunc;

        if (empty($user))
            return FALSE;

        $request = $smcFunc['db_query']('', '
			SELECT u.*, um.meta_value AS role, um2.meta_value AS use_ssl
			FROM {raw:wp_prefix}users u
				LEFT JOIN {raw:wp_prefix}usermeta um ON (um.user_id = u.ID AND um.meta_key = {string:capabilities})
				LEFT JOIN {raw:wp_prefix}usermeta um2 ON (um2.user_id = u.ID AND um2.meta_key = {string:ssl})
			WHERE user_login = {string:user}
			LIMIT 1',
                array(
                    'wp_prefix' => $this->db_prefix,
                    'capabilities' => 'wp_capabilities',
                    'ssl' => 'use_ssl',
                    'user' => $user,
                ),
                $this->db_connection);
        $this->properties = $smcFunc['db_num_rows']($request) > 0 ? $smcFunc['db_fetch_assoc']($request) : array();
        $smcFunc['db_free_result']($request);

        return!empty($this->properties);
    }

    /**
     * Saves or creates a new user in the WordPress database.  All variables
     * should be set before calling this method.
     *
     * @return boolean True if the user was saved or created successfully
     */
    public function save() {
        global $smcFunc;

        $knownInts = array('user_status' => 'int');
        $knownStrings = array('user_login' => 'string-60', 'user_pass' => 'string-64', 'user_nicename' => 'string-50', 'user_email' => 'string-100', 'user_url' => 'string-100', 'user_registered' => 'string-19', 'user_activation_key' => 'string-60', 'display_name' => 'string-250');

        // If a ID is present, we update
        if (isset($this->properties['ID'])) {
            $message_columns = array();
            $update_params = array('wp_prefix' => $this->db_prefix, 'id' => $this->properties['ID']);
            foreach ($knownInts as $var => $type)
                if (isset($this->properties[$var])) {
                    $message_columns[] = $var . '= {int:var_' . $var . '}';
                    $update_params['var_' . $var] = (int) $this->properties[$var];
                }
            foreach ($knownStrings as $var => $type)
                if (isset($this->properties[$var])) {
                    $message_columns[] = $var . '= {string:var_' . $var . '}';
                    $update_params['var_' . $var] = $this->properties[$var];
                }

            if (empty($message_columns))
                return TRUE;

            $smcFunc['db_query']('', '
				UPDATE {raw:wp_prefix}users
				SET ' . implode(', ', $message_columns) . '
				WHERE ID = {int:id}',
                $update_params,
                $this->db_connection);

            // Update the role
            if (!empty($this->properties['role']))
                $smcFunc['db_query']('', '
					UPDATE {raw:wp_prefix}usermeta
					SET meta_value = {string:role}
					WHERE user_id = {int:id}
						AND meta_key = {string:capability}',
                    array(
                        'wp_prefix' => $this->db_prefix,
                        'role' => $this->properties['role'],
                        'id' => $this->properties['ID'],
                        'capability' => 'wp_capabilities',
                    ),
                    $this->db_connection);

            return TRUE;
        }
        else {
            $message_columns = array();
            $update_params = array();
            foreach (array_merge($knownInts, $knownStrings) as $var => $type)
                if (isset($this->properties[$var])) {
                    $message_columns[$var] = $type;
                    $update_params[] = $this->properties[$var];
                }

            if (empty($message_columns))
                return FALSE;

            // Create a new one
            $smcFunc['db_insert']('insert',
                $this->db_prefix . 'users',
                $message_columns,
                $update_params,
                array('ID'),
                FALSE,
                $this->db_connection);

            $id = $smcFunc['db_insert_id']($this->db_prefix . 'users', 'ID', $this->db_connection);

            if (empty($id))
                return FALSE;

            $this->properties['ID'] = $id;

            if (!empty($this->properties['role']))
                $smcFunc['db_insert']('insert',
                    $this->db_prefix . 'usermeta',
                    array('user_id' => 'int', 'meta_key' => 'string-255', 'meta_value' => 'string-4294967295',),
                    array(
                        array($id, 'first_name', ''),
                        array($id, 'last_name', ''),
                        array($id, 'description', ''),
                        array($id, 'rich_editing', 'true'),
                        array($id, 'comment_shortcuts', 'true'),
                        array($id, 'wp_capabilities', $this->properties['role']),
                        array($id, 'nickname', $this->properties['user_login']),
                    ),
                    array('umeta_id'),
                    FALSE,
                    $this->db_connection);

            return TRUE;
        }
    }

    /**
     * Takes a plain text password and compares it to the hashed password of
     * the loaded user to determine if the password they entered matched.
     *
     * @param string $password Plaintext password
     * @return boolean If password is valid
     */
    public function isLegit($password) {
        if (empty($this->properties))
            return FALSE;

        return $this->password->checkPassword($password, $this->properties['user_pass']);
    }

    /**
     * Converts a normal username to something nice that wordpress can display
     * in URLs and the such.  It does not convert to a nicename like wordpress,
     * it is much more crude and does the best it can simply.
     *
     * @param string $user Original username
     * @return void Nice username is set in properties variable
     */
    private function set_user_nicename($user) {
        global $txt, $smcFunc;

        // First create a nice name
        $nice = strtolower(iconv($txt['lang_character_set'], 'ASCII//TRANSLIT//IGNORE', $user));
        $nice = preg_replace('~[^a-z0-9-_]+~', '-', $nice);
        $nice = preg_replace('~-+~', '-', $nice);

        if (empty($nice)) {
            $this->properties['user_nicename'] = '';
            return;
        }

        // See if this already exists
        $count = 2;
        $check_nice = $nice . '-';
        do {
            $request = $smcFunc['db_query']('', '
				SELECT user_nicename
				FROM {raw:wp_prefix}users
				WHERE user_nicename = {string:name}
				ORDER BY user_nicename ASC',
                    array(
                        'wp_prefix' => $this->db_prefix,
                        'name' => $nice,
                    ),
                    $this->db_connection);
            if ($smcFunc['db_num_rows']($request) === 0)
                break;
            $smcFunc['db_free_result']($request);
            $nice = $check_nice . $count++;
        } while (TRUE);
        $smcFunc['db_free_result']($request);

        $this->properties['user_nicename'] = $nice;
    }

    /**
     * Hashes a plaintext password to a wordpress readable password
     *
     * @param string $password Plaintext password to hash
     */
    private function set_user_pass($password) {
        $this->properties['user_pass'] = $this->password->hashPassword($password);
    }

    /**
     * Given a SMF group, sets the role of the user according to mapped role
     * or the default role if a mapping is not found.
     *
     * @param int $id SMF group number
     */
    private function set_role($id) {
        global $modSettings, $smcFunc;

        $roleMaps = !empty($modSettings['wordpress_role_maps']) ? unserialize($modSettings['wordpress_role_maps']) : array('smf' => array(), 'wp' => array());

        if (isset($roleMaps['smf'][$id]))
            $role = $roleMaps['smf'][$id];
        else {
            // Query wordpress to find the default
            $request = $smcFunc['db_query']('', '
				SELECT option_value FROM {raw:wp_prefix}options WHERE option_name = {string:default_role}',
                    array(
                        'wp_prefix' => $this->db_prefix,
                        'default_role' => 'default_role',
                    ),
                    $this->db_connection);
            list($role) = $smcFunc['db_fetch_row']($request);
            $smcFunc['db_free_result']($request);
        }

        $this->properties['role'] = serialize(array($role => '1'));
    }

    private function get_role() {
        $array = unserialize($this->properties['role']);
        return array_shift(array_flip($array));
    }

    public function __get($key) {
        if (!isset($this->properties[$key]))
            return NULL;

        $method = 'get_' . strtolower($key);
        if (method_exists($this, $method))
            return $this->$method();
        else
            return $this->properties[$key];
    }

    public function __set($key, $value) {
        $method = 'set_' . strtolower($key);
        if (method_exists($this, $method))
            $this->$method($value);
        else
            $this->properties[$key] = $value;
    }

    public function __isset($key) {
        return isset($this->properties[$key]);
    }

    public function __toString() {
        return print_r(get_object_vars($this), TRUE);
    }

}
