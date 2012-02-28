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

function template_callback_wordpress_edit_roles() {
    global $context, $txt;

    echo '
			<dt><strong>', $txt['wordpress smf groups'], '</strong></dt>
			<dd><strong>', $txt['wordpress wp groups'], '</strong></dd>';
    foreach ($context['smfGroups'] as $group) {
        echo '
			<dt>', $group['group_name'], '</dt>
			<dd>
				<select name="smfroles[', $group['id_group'], ']">
					<option value="">', $txt['wordpress select one'], '</option>';
        foreach ($context['wpRoles'] as $id => $info) {
            echo '
					<option value="', $id, '"', (!empty($context['wpMapping']['smf'][$group['id_group']]) && $context['wpMapping']['smf'][$group['id_group']] === $id ? ' selected="selected"' : ''), '>', $info['name'], '</option>';
        }
        echo '
				</select>
			</dd>';
    }
}

function template_callback_wordpress_edit_membergroups() {
    global $context, $txt;

    echo '
			<dt><strong>', $txt['wordpress wp groups'], '</strong></dt>
			<dd><strong>', $txt['wordpress smf groups'], '</strong></dd>';
    foreach ($context['wpRoles'] as $id => $info) {
        echo '
			<dt>', $info['name'], '</dt>
			<dd>
				<select name="wproles[', $id, ']">
					<option value="">', $txt['wordpress select one'], '</option>';
        foreach ($context['smfGroups'] as $group) {
            echo '
					<option value="', $group['id_group'], '"', (!empty($context['wpMapping']['wp'][$id]) && $context['wpMapping']['wp'][$id] === $group['id_group'] ? ' selected="selected"' : ''), '>', $group['group_name'], '</option>';
        }
        echo '
				</select>
			</dd>';
    }
}

function template_callback_wordpress_edit_files() {
    global $txt, $context;

    foreach ($context['wp-files'] as $file)
        echo '
            <dt>
                ', $txt[$file['title']], '<br />
                <span class="smalltext">', $txt[$file['title'] . ' desc'], '</span>
            </dt>
            <dd>
                <input class="button_submit" type="submit" name="fix-file[', $file['fix'] ? 'fix-' : 'revert-', $file['name'], ']" value="', $txt['wordpress ' . ($file['fix'] ? 'fix' : 'unfix')], '" />&nbsp;
            </dd>';
}