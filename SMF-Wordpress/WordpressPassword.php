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
 * @copyright 2004-2006 Solar Designer <solar@openwall.com>
 * @license http://www.mozilla.org/MPL/MPL-1.1.html Mozilla Public License
 */

/**
 * Wordpress Password Class
 *
 * @package BlogBridger
 */
class WordpressPassword {

    private $itoa64;
    private $iteration_count_log2;
    private $random_state;

    public function __construct($iteration_count_log2 = 8) {
        $this->itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

        if ($iteration_count_log2 < 4 || $iteration_count_log2 > 31)
            $iteration_count_log2 = 8;
        $this->iteration_count_log2 = $iteration_count_log2;

        $this->random_state = microtime() . (function_exists('getmypid') ? getmypid() : '');
    }

    private function get_random_bytes($count) {
        $output = '';
        // Supressed because of open_basedir restrictions
        if (@is_readable('/dev/urandom') && ($fh = @fopen('/dev/urandom', 'rb'))) {
            $output = fread($fh, $count);
            fclose($fh);
        }

        if (strlen($output) < $count) {
            $output = '';
            for ($i = 0; $i < $count; $i += 16) {
                $this->random_state = md5(microtime() . $this->random_state);
                $output .= pack('H*', md5($this->random_state));
            }
            $output = substr($output, 0, $count);
        }

        return $output;
    }

    private function encode64($input, $count) {
        $output = '';
        $i = 0;
        do {
            $value = ord($input[$i++]);
            $output .= $this->itoa64[$value & 0x3f];
            if ($i < $count)
                $value |= ord($input[$i]) << 8;
            $output .= $this->itoa64[($value >> 6) & 0x3f];
            if ($i++ >= $count)
                break;
            if ($i < $count)
                $value |= ord($input[$i]) << 16;
            $output .= $this->itoa64[($value >> 12) & 0x3f];
            if ($i++ >= $count)
                break;
            $output .= $this->itoa64[($value >> 18) & 0x3f];
        } while ($i < $count);

        return $output;
    }

    private function gensalt($input) {
        $output = '$P$';
        $output .= $this->itoa64[min($this->iteration_count_log2 + 5, 30)];
        $output .= $this->encode64($input, 6);

        return $output;
    }

    private function crypt($password, $setting) {
        $random = '';

        if (strlen($random) < 6)
            $random = $this->get_random_bytes(6);

        $count_log2 = strpos($this->itoa64, $setting[3]);

        $count = 1 << $count_log2;

        $salt = substr($setting, 4, 8);

        $hash = md5($salt . $password, TRUE);
        do {
            $hash = md5($hash . $password, TRUE);
        } while (--$count);

        $output = substr($setting, 0, 12);
        $output .= $this->encode64($hash, 16);

        return $output;
    }

    public function hashPassword($password) {
        $random = '';

        if (strlen($random) < 6)
            $random = $this->get_random_bytes(6);
        $hash = $this->crypt($password, $this->gensalt($random));

        return $hash;
    }

    public function checkPassword($password, $stored_hash) {
        $hash = $this->crypt($password, $stored_hash);

        return $hash == $stored_hash;
    }

}