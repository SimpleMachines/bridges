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

$txt['wordpress bridge'] = 'Wordpress Bridge';
$txt['wordpress bridge settings'] = 'Bridge Settings';
$txt['wordpress settings desc'] = 'Enter and modify settings that pertain to Wordpress and the bridge.';

// Basic Settings
$txt['wordpress_enabled'] = 'Enable Wordpress Bridge';
$txt['wordpress_path'] = 'Wordpress Path';
$txt['wordpress path desc'] = 'This should be the full file path to your wp-config.php file.';
$txt['wordpress path desc extra'] = 'This path is a guess and has NOT been saved yet.  Please click the "Save" button to save this path permamently.';
$txt['wordpress path desc extra2'] = 'Empty this field and hit save to attempt to find this automatically.';
$txt['wordpress fix'] = 'Fix File';
$txt['wordpress unfix'] = 'Revert File';
$txt['wordpress edit login file'] = 'Adjust WordPress wp-login.php file';
$txt['wordpress edit login file desc'] = 'This will <strong>try</strong> to alter your wp-login.php file by redirecting all requests to it to SMF\'s login page instead.';

// Role settings
$txt['wordpress roles'] = 'Role Settings';
$txt['wordpress roles desc'] = 'Select which roles in either software correspond to each other.';
$txt['wordpress smf groups'] = 'SMF Membergroup';
$txt['wordpress wp groups'] = 'Wordpress Role';
$txt['wordpress select one'] = 'Select one...';
$txt['wordpress smf to wp mapping'] = 'Map SMF Membergroups to Wordpress Roles';
$txt['wordpress smf to wp mapping desc'] = 'As users are imported from Wordpress, they will be created with the SMF Membergroup that you assign to their Wordpress role.  Any user with a Wordpress role that is not mapped will be created in SMF as a Regular Member.';
$txt['wordpress wp to smf mapping'] = 'Map Wordpress roles to SMF Membergroups';
$txt['wordpress wp to smf mapping desc'] = 'As users are created in Wordpress, they will be created with the Wordpress role that you assign to their primary membergroup.';

// Error strings
$txt['wordpress no config'] = 'No Wordpress configuration file was found';
$txt['wordpress cannot connect'] = 'Could not connect to the Wordpress database';
$txt['wordpress invalid keys'] = 'You do not have the required keys or salts in your Wordpress installation.  Please visit <a href="https://api.wordpress.org/secret-key/1.1/salt/">https://api.wordpress.org/secret-key/1.1/salt/</a> and copy the output to your wp-config.php file.';
$txt['wordpress cannot sync'] = 'There was a problem logging %s into SMF using the Wordpress account.  Please ask the administrator to check the error log for more information.';
$txt['wordpress cannot read'] = 'Could not read the Wordpress file.  Please ask your host to allow one of the following functions: %s';
$txt['wordpress problems'] = 'We found the following problems:';
$txt['wordpress edit login file failed'] = 'wp-login.php is not redirecting to SMF';
$txt['wordpress path not writable'] = 'Wordpress path is not writable by the webserver.  We will not be able to make backups of modified Wordpress files';
