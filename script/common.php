<?php

/*
 * Faucet in a BOX
 * https://faucetinabox.com/
 *
 * Copyright (c) 2014-2016 LiveHome Sp. z o. o.
 *
 * (ultimate) extensions and bugfixes by http://makejar.com/
 *
 * This file is part of Faucet in a BOX.
 *
 * Faucet in a BOX is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Faucet in a BOX is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Faucet in a BOX.  If not, see <http://www.gnu.org/licenses/>.
 */

$version = '86';

$faucet_settings_array=array();

if (empty($dbtable_prefix)) {
    $dbtable_prefix = 'Faucetinabox_';
}

include 'libs/functions.php';
include 'libs/services.php';



if (get_magic_quotes_gpc()) {
    $process = array(&$_GET, &$_POST, &$_COOKIE, &$_REQUEST);
    while (list($key, $val) = each($process)) {
        foreach ($val as $k => $v) {
            unset($process[$key][$k]);
            if (is_array($v)) {
                $process[$key][stripslashes($k)] = $v;
                $process[] = &$process[$key][stripslashes($k)];
            } else {
                $process[$key][stripslashes($k)] = stripslashes($v);
            }
        }
    }
    unset($process);
}

if(stripos($_SERVER['REQUEST_URI'], '@') !== FALSE ||
   stripos(urldecode($_SERVER['REQUEST_URI']), '@') !== FALSE) {
    header("Location: ."); die('Please wait...');
}

session_start();
header('Content-Type: text/html; charset=utf-8');
ini_set('display_errors', false);

$missing_configs = array();

$session_prefix = 'sp_'.crc32(__FILE__);

$disable_curl = false;
$verify_peer = true;
$local_cafile = false;
require_once("config.php");
if(!isset($disable_admin_panel)) {
    $disable_admin_panel = false;
    $missing_configs[] = array(
        "name" => "disable_admin_panel",
        "default" => "false",
        "desc" => "Allows to disable Admin Panel for increased security"
    );
}

if(!isset($connection_options)) {
    $connection_options = array(
        'disable_curl' => $disable_curl,
        'local_cafile' => $local_cafile,
        'verify_peer' => $verify_peer,
        'force_ipv4' => false
    );
}
if(!isset($connection_options['verify_peer'])) {
    $connection_options['verify_peer'] = $verify_peer;
}

if (!isset($display_errors)) $display_errors = false;
ini_set('display_errors', $display_errors);
if($display_errors)
    error_reporting(-1);


if(array_key_exists('HTTP_REFERER', $_SERVER)) {
    $referer = $_SERVER['HTTP_REFERER'];
} else {
    $referer = "";
}

//Check required PHP extensions
$extensions_status = array(
    "curl" => extension_loaded("curl"),
    "gd" => extension_loaded("gd"),
    "pdo" => extension_loaded("PDO"),
    "pdo_mysql" => extension_loaded("pdo_mysql"),
    "soap" => extension_loaded("soap")
);
$all_loaded = array_reduce($extensions_status, function($all_loaded, $ext) {
    return $all_loaded && $ext;
}, true);
if (!$all_loaded) {
    showExtensionsErrorPage($extensions_status);
}

// preserve R while visiting the shortlink
if ((empty($_SESSION[$session_prefix.'_r']))&&(!empty($_GET['r']))) {
    $_SESSION[$session_prefix.'_r']=$_GET['r'];
}
if ((empty($_GET['r']))&&(!empty($_SESSION[$session_prefix.'_r']))) {
    $_GET['r']=$_SESSION[$session_prefix.'_r'];
}

try {
    $sql = new PDO($dbdsn, $dbuser, $dbpass, array(PDO::ATTR_PERSISTENT => true,
                                                   PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION));
} catch(PDOException $e) {
    if ($display_errors) die("Can't connect to database. Check your config.php. Details: ".$e->getMessage());
    else die("Can't connect to database. Check your config.php or set \$display_errors = true; to see details.");
}

$host = parse_url($referer, PHP_URL_HOST);
// ultimate host:port bugfix
$host_http=$_SERVER['HTTP_HOST'];
$host_http=explode(':', $host_http);
$host_http=$host_http[0];

$db_updates = array(
    15 => array("INSERT IGNORE INTO `".$dbtable_prefix."Settings` (`name`, `value`) VALUES ('version', '15');"),
    17 => array("ALTER TABLE `".$dbtable_prefix."Settings` CHANGE `value` `value` TEXT NOT NULL;", "INSERT IGNORE INTO `".$dbtable_prefix."Settings` (`name`, `value`) VALUES ('balance', 'N/A');"),
    33 => array("INSERT IGNORE INTO `".$dbtable_prefix."Settings` (`name`, `value`) VALUES ('ayah_publisher_key', ''), ('ayah_scoring_key', '');"),
    34 => array("INSERT IGNORE INTO `".$dbtable_prefix."Settings` (`name`, `value`) VALUES ('custom_admin_link_default', 'true')"),
    38 => array("INSERT IGNORE INTO `".$dbtable_prefix."Settings` (`name`, `value`) VALUES ('reverse_proxy', 'none')", "INSERT IGNORE INTO `".$dbtable_prefix."Settings` (`name`, `value`) VALUES ('default_captcha', 'recaptcha')"),
    41 => array("INSERT IGNORE INTO `".$dbtable_prefix."Settings` (`name`, `value`) VALUES ('captchme_public_key', ''), ('captchme_private_key', ''), ('captchme_authentication_key', ''), ('reklamper_enabled', '')"),
    46 => array("INSERT IGNORE INTO `".$dbtable_prefix."Settings` (`name`, `value`) VALUES ('last_balance_check', '0')"),
    54 => array("INSERT IGNORE INTO `".$dbtable_prefix."Settings` (`name`, `value`) VALUES ('funcaptcha_public_key', ''), ('funcaptcha_private_key', '')"),
    55 => array("INSERT IGNORE INTO `".$dbtable_prefix."Settings` (`name`, `value`) VALUES ('block_adblock', ''), ('button_timer', '0')"),
    56 => array("INSERT IGNORE INTO `".$dbtable_prefix."Settings` (`name`, `value`) VALUES ('ip_check_server', ''),('ip_ban_list', ''),('hostname_ban_list', ''),('address_ban_list', '')"),
    58 => array("DELETE FROM `".$dbtable_prefix."Settings` WHERE `name` IN ('captchme_public_key', 'captchme_private_key', 'captchme_authentication_key', 'reklamper_enabled')"),
    63 => array("INSERT IGNORE INTO `".$dbtable_prefix."Settings` (`name`, `value`) VALUES ('safety_limits_end_time', '')"),
    64 => array(
        "INSERT IGNORE INTO `".$dbtable_prefix."Settings` (`name`, `value`) VALUES ('iframe_sameorigin_only', ''), ('asn_ban_list', ''), ('country_ban_list', ''), ('nastyhosts_enabled', '')",
        "UPDATE `".$dbtable_prefix."Settings` new LEFT JOIN `".$dbtable_prefix."Settings` old ON old.name = 'ip_check_server' SET new.value = IF(old.value = 'http://v1.nastyhosts.com/', 'on', '') WHERE new.name = 'nastyhosts_enabled'",
        "DELETE FROM `".$dbtable_prefix."Settings` WHERE `name` = 'ip_check_server'"
    ),
    65 => array(
        "DELETE FROM `".$dbtable_prefix."Settings` WHERE `name` IN ('ayah_publisher_key', 'ayah_scoring_key') ",
        "UPDATE `".$dbtable_prefix."Settings` SET `value` = IF(`value` != 'none' OR `value` != 'none-auto', 'on', '') WHERE `name` = 'reverse_proxy' "
    ),
    66 => array(
        "ALTER TABLE `".$dbtable_prefix."Settings` CHANGE `value` `value` LONGTEXT NOT NULL;",
        "INSERT IGNORE INTO `".$dbtable_prefix."Settings` (`name`, `value`) VALUES ('service', 'faucethub');",
        "CREATE TABLE IF NOT EXISTS `".$dbtable_prefix."IP_Locks` ( `ip` VARCHAR(20) NOT NULL PRIMARY KEY, `locked_since` TIMESTAMP NOT NULL );",
        "CREATE TABLE IF NOT EXISTS `".$dbtable_prefix."Address_Locks` ( `address` VARCHAR(60) NOT NULL PRIMARY KEY, `locked_since` TIMESTAMP NOT NULL );"
    ),
    67 => array(
        "ALTER TABLE `".$dbtable_prefix."Refs` DROP COLUMN `balance`;",
        "INSERT IGNORE INTO `".$dbtable_prefix."Settings` (`name`, `value`) VALUES ('ip_white_list', ''), ('update_last_check', '');"
    ),
    80 => array(
        "INSERT IGNORE INTO `".$dbtable_prefix."Settings` (`name`, `value`) VALUES ('disable_refcheck', '');",
        "INSERT IGNORE INTO `".$dbtable_prefix."Settings` (`name`, `value`) VALUES ('geetest_captcha_id', ''), ('geetest_private_key', '');"
    ),
    85 => array(
        "INSERT IGNORE INTO `".$dbtable_prefix."Settings` (`name`, `value`) VALUES ('ezdata', 'on');",
        "INSERT IGNORE INTO `".$dbtable_prefix."Settings` (`name`, `value`) VALUES ('sqn_id', ''), ('sqn_key', ''), ('sqn_id_www', ''), ('sqn_key_www', '');",
        "INSERT IGNORE INTO `".$dbtable_prefix."Settings` ('shortlink_payout', '0'), ('shortlink_data', ''), ('update_data', '{\"version\":85,\"version_link\":\"https:\/\/www.makejar.com\/\",\"version_info\":\"- udated BitCaptcha<br \/>- added Shortlinks<br \/>- Code Cleanup\",\"shortlink_providers_details\":\"It is suggested to use 3 to 5 services. Please make a research before adding new services. Some of them may not be paying anymore.\",\"shortlink_providers\":{\"adbilty\":{\"link_reg\":\"https:\/\/adbilty.me\/ref\/setup\",\"link_api\":\"http:\/\/adbilty.me\/api\/\",\"text\":\"adbilty.me\"},\"oke\":{\"link_reg\":\"http:\/\/oke.io\/ref\/setup\",\"link_api\":\"http:\/\/oke.io\/api\/\",\"text\":\"oke.io\"},\"clik\":{\"link_reg\":\"https:\/\/clik.pw\/ref\/setup\",\"link_api\":\"http:\/\/clik.pw\/api\/\",\"text\":\"clik.pw\"},\"megaurl\":{\"link_reg\":\"https:\/\/megaurl.in\/ref\/setup\",\"link_api\":\"http:\/\/megaurl.in\/api\/\",\"text\":\"megaurl.in\"},\"cutwin\":{\"link_reg\":\"https:\/\/cutwin.com\/ref\/setup\",\"link_api\":\"http:\/\/cutwin.com\/api\/\",\"text\":\"cutwin.com\"},\"cut-urls\":{\"link_reg\":\"https:\/\/cut-urls.com\/ref\/setup\",\"link_api\":\"http:\/\/cut-urls.com\/api\/\",\"text\":\"cut-urls.com\"},\"coin\":{\"link_reg\":\"http:\/\/coin.mg\/ref\/setup\",\"link_api\":\"http:\/\/coin.mg\/api\/\",\"text\":\"coin.mg\"},\"coinb\":{\"link_reg\":\"http:\/\/coinb.ink\/ref\/setup\",\"link_api\":\"http:\/\/coinb.ink\/api\/\",\"text\":\"coinb.ink\"},\"cutbit\":{\"link_reg\":\"http:\/\/cutbit.io\/ref\/setup\",\"link_api\":\"http:\/\/cutbit.io\/api\/\",\"text\":\"cutbit.io\"},\"cutit\":{\"link_reg\":\"https:\/\/cutit.io\/ref\/setup\",\"link_api\":\"http:\/\/cutit.io\/api\/\",\"text\":\"cutit.io\"},\"coinarge\":{\"link_reg\":\"http:\/\/coinarge.com\/ref\/setup\",\"link_api\":\"http:\/\/coinarge.com\/api\/\",\"text\":\"coinarge.com\"},\"coinlink\":{\"link_reg\":\"https:\/\/coinlink.us\/ref\/setup\",\"link_api\":\"http:\/\/coinlink.us\/api\/\",\"text\":\"coinlink.us\"},\"adpop\":{\"link_reg\":\"https:\/\/adpop.me\/ref\/setup\",\"link_api\":\"http:\/\/adpop.me\/api\/\",\"text\":\"adpop.me\"},\"psl\":{\"link_reg\":\"http:\/\/psl.io\/ref\/makejar\",\"link_api\":\"http:\/\/psl.io\/api\/\",\"text\":\"psl.io\"},\"btc\":{\"link_reg\":\"http:\/\/btc.ms\/ref\/makejar\",\"link_api\":\"http:\/\/btc.ms\/api\/\",\"text\":\"btc.ms\"},\"tmearn\":{\"link_reg\":\"https:\/\/tmearn.com\/ref\/makejar\",\"link_api\":\"http:\/\/tmearn.com\/api\/\",\"text\":\"tmearn.com\"},\"kuturl\":{\"link_reg\":\"https:\/\/kuturl.com\/ref\/setup\",\"link_api\":\"http:\/\/kuturl.com\/api\/\",\"text\":\"kuturl.com\",\"details\":\"No bitcoin payout option.\"},\"adbull\":{\"link_reg\":\"http:\/\/adbull.me\/ref\/setup\",\"link_api\":\"http:\/\/adbull.me\/api\/\",\"text\":\"adbull.me\",\"details\":\"No bitcoin payout option.\"},\"urle\":{\"link_reg\":\"https:\/\/urle.co\/ref\/setup\",\"link_api\":\"http:\/\/urle.co\/api\/\",\"text\":\"urle.co\",\"details\":\"No bitcoin payout option.\"},\"zlshorte\":{\"link_reg\":\"http:\/\/zlshorte.net\/ref\/setup\",\"link_api\":\"http:\/\/zlshorte.net\/api\/\",\"text\":\"zlshorte.net\",\"details\":\"No bitcoin payout option.\"},\"igram\":{\"link_reg\":\"https:\/\/igram.im\/ref\/setup\",\"link_api\":\"http:\/\/igram.im\/api\/\",\"text\":\"igram.im\",\"details\":\"No bitcoin payout option.\"}}}');"
    ),
    86 => array(
        "INSERT IGNORE INTO `".$dbtable_prefix."Settings` (`name`, `value`) VALUES ('coinhive_site_key', ''), ('coinhive_secret_key', '');"
        )
);

$default_data_query = "
create table if not exists ".$dbtable_prefix."Settings (
    `name` varchar(64) not null,
    `value` longtext not null,
    primary key(`name`)
);
create table if not exists ".$dbtable_prefix."IPs (
    `ip` varchar(45) not null,
    `last_used` timestamp not null,
    primary key(`ip`)
);
create table if not exists ".$dbtable_prefix."Addresses (
    `address` varchar(60) not null,
    `ref_id` int null,
    `last_used` timestamp not null,
    primary key(`address`)
);
create table if not exists ".$dbtable_prefix."Refs (
    `id` int auto_increment not null,
    `address` varchar(60) not null unique,
    primary key(`id`)
);
create table if not exists ".$dbtable_prefix."Pages (
    `id` int auto_increment not null,
    `url_name` varchar(50) not null unique,
    `name` varchar(255) not null,
    `html` text not null,
    primary key(`id`)
);
CREATE TABLE if not exists `".$dbtable_prefix."NH_Log` (
  `".$dbtable_prefix."NH_Log_id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `".$dbtable_prefix."NH_Log_time` int(11) NOT NULL DEFAULT '0',
  `".$dbtable_prefix."NH_Log_IP` varchar(45) NOT NULL DEFAULT '',
  `".$dbtable_prefix."NH_Log_address` varchar(50) NOT NULL DEFAULT '',
  `".$dbtable_prefix."NH_Log_address_ref` varchar(50) NOT NULL DEFAULT '',
  `".$dbtable_prefix."NH_Log_suggestion` enum('allow','deny') NOT NULL DEFAULT 'deny',
  `".$dbtable_prefix."NH_Log_reason` varchar(128) NOT NULL DEFAULT '',
  `".$dbtable_prefix."NH_Log_country_code` varchar(3) NOT NULL DEFAULT '',
  `".$dbtable_prefix."NH_Log_country` varchar(64) NOT NULL DEFAULT '',
  `".$dbtable_prefix."NH_Log_asn` int(11) NOT NULL DEFAULT '0',
  `".$dbtable_prefix."NH_Log_asn_name` varchar(128) NOT NULL DEFAULT '',
  `".$dbtable_prefix."NH_Log_host` varchar(128) NOT NULL DEFAULT '',
  `".$dbtable_prefix."NH_Log_useragent` varchar(256) NOT NULL DEFAULT '',
  `".$dbtable_prefix."NH_Log_session_id` varchar(50) NOT NULL DEFAULT '',
  PRIMARY KEY (`".$dbtable_prefix."NH_Log_id`),
  KEY `".$dbtable_prefix."NH_Log_time` (`".$dbtable_prefix."NH_Log_time`),
  KEY `".$dbtable_prefix."NH_Log_session_id` (`".$dbtable_prefix."NH_Log_session_id`)
);
create table if not exists `".$dbtable_prefix."IP_Locks` (
    `ip` varchar(45) not null primary key,
    `locked_since` timestamp not null
);
create table if not exists `".$dbtable_prefix."Address_Locks` (
    `address` varchar(60) not null primary key,
    `locked_since` timestamp not null
);

INSERT IGNORE INTO ".$dbtable_prefix."Settings (name, value) VALUES
('apikey', ''),
('timer', '180'),
('rewards', '90*100, 10*500'),
('referral', '15'),
('solvemedia_challenge_key', ''),
('solvemedia_verification_key', ''),
('solvemedia_auth_key', ''),
('recaptcha_private_key', ''),
('recaptcha_public_key', ''),
('funcaptcha_private_key', ''),
('funcaptcha_public_key', ''),
('name', 'Faucet in a Box <sup>ultimate</sup>'),
('short', 'Just another Faucet in a Box <sup>ultimate</sup>'),
('template', 'default'),
('custom_body_cl_default', ''),
('custom_box_bottom_cl_default', ''),
('custom_box_bottom_default', ''),
('custom_box_top_cl_default', ''),
('custom_box_top_default', ''),
('custom_box_left_cl_default', ''),
('custom_box_left_default', ''),
('custom_box_right_cl_default', ''),
('custom_box_right_default', ''),
('custom_css_default', '/* custom_css */\\n/* center everything! */\\n.row {\\n    text-align: center;\\n}\\n#recaptcha_widget_div, #recaptcha_area {\\n    margin: 0 auto;\\n}\\n/* do not center lists */\\nul, ol {\\n    text-align: left;\\n}'),
('custom_footer_cl_default', ''),
('custom_footer_default', ''),
('custom_main_box_cl_default', ''),
('custom_palette_default', ''),
('custom_admin_link_default', 'true'),
('version', '$version'),
('currency', 'BTC'),
('balance', 'N/A'),
('reverse_proxy', 'on'),
('last_balance_check', '0'),
('default_captcha', 'recaptcha'),
('ip_ban_list', ''),
('hostname_ban_list', ''),
('address_ban_list', ''),
('block_adblock', ''),
('button_timer', '0'),
('safety_limits_end_time', ''),
('iframe_sameorigin_only', ''),
('asn_ban_list', ''),
('country_ban_list', ''),
('nastyhosts_enabled', ''),
('service', 'faucethub'),
('ip_white_list', ''),
('update_last_check', ''),
('disable_refcheck', ''),
('geetest_captcha_id', ''),
('geetest_private_key', ''),
('ezdata', 'on'),
('sqn_id', ''),
('sqn_key', ''),
('sqn_id_www', ''),
('sqn_key_www', ''),
('shortlink_payout', '0'),
('shortlink_data', ''),
('update_data', '{\"version\":85,\"version_link\":\"https:\/\/www.makejar.com\/\",\"version_info\":\"- udated BitCaptcha<br \/>- added Shortlinks<br \/>- Code Cleanup\",\"shortlink_providers_details\":\"It is suggested to use 3 to 5 services. Please make a research before adding new services. Some of them may not be paying anymore.\",\"shortlink_providers\":{\"adbilty\":{\"link_reg\":\"https:\/\/adbilty.me\/ref\/setup\",\"link_api\":\"http:\/\/adbilty.me\/api\/\",\"text\":\"adbilty.me\"},\"oke\":{\"link_reg\":\"http:\/\/oke.io\/ref\/setup\",\"link_api\":\"http:\/\/oke.io\/api\/\",\"text\":\"oke.io\"},\"clik\":{\"link_reg\":\"https:\/\/clik.pw\/ref\/setup\",\"link_api\":\"http:\/\/clik.pw\/api\/\",\"text\":\"clik.pw\"},\"megaurl\":{\"link_reg\":\"https:\/\/megaurl.in\/ref\/setup\",\"link_api\":\"http:\/\/megaurl.in\/api\/\",\"text\":\"megaurl.in\"},\"cutwin\":{\"link_reg\":\"https:\/\/cutwin.com\/ref\/setup\",\"link_api\":\"http:\/\/cutwin.com\/api\/\",\"text\":\"cutwin.com\"},\"cut-urls\":{\"link_reg\":\"https:\/\/cut-urls.com\/ref\/setup\",\"link_api\":\"http:\/\/cut-urls.com\/api\/\",\"text\":\"cut-urls.com\"},\"coin\":{\"link_reg\":\"http:\/\/coin.mg\/ref\/setup\",\"link_api\":\"http:\/\/coin.mg\/api\/\",\"text\":\"coin.mg\"},\"coinb\":{\"link_reg\":\"http:\/\/coinb.ink\/ref\/setup\",\"link_api\":\"http:\/\/coinb.ink\/api\/\",\"text\":\"coinb.ink\"},\"cutbit\":{\"link_reg\":\"http:\/\/cutbit.io\/ref\/setup\",\"link_api\":\"http:\/\/cutbit.io\/api\/\",\"text\":\"cutbit.io\"},\"cutit\":{\"link_reg\":\"https:\/\/cutit.io\/ref\/setup\",\"link_api\":\"http:\/\/cutit.io\/api\/\",\"text\":\"cutit.io\"},\"coinarge\":{\"link_reg\":\"http:\/\/coinarge.com\/ref\/setup\",\"link_api\":\"http:\/\/coinarge.com\/api\/\",\"text\":\"coinarge.com\"},\"coinlink\":{\"link_reg\":\"https:\/\/coinlink.us\/ref\/setup\",\"link_api\":\"http:\/\/coinlink.us\/api\/\",\"text\":\"coinlink.us\"},\"adpop\":{\"link_reg\":\"https:\/\/adpop.me\/ref\/setup\",\"link_api\":\"http:\/\/adpop.me\/api\/\",\"text\":\"adpop.me\"},\"psl\":{\"link_reg\":\"http:\/\/psl.io\/ref\/makejar\",\"link_api\":\"http:\/\/psl.io\/api\/\",\"text\":\"psl.io\"},\"btc\":{\"link_reg\":\"http:\/\/btc.ms\/ref\/makejar\",\"link_api\":\"http:\/\/btc.ms\/api\/\",\"text\":\"btc.ms\"},\"tmearn\":{\"link_reg\":\"https:\/\/tmearn.com\/ref\/makejar\",\"link_api\":\"http:\/\/tmearn.com\/api\/\",\"text\":\"tmearn.com\"},\"kuturl\":{\"link_reg\":\"https:\/\/kuturl.com\/ref\/setup\",\"link_api\":\"http:\/\/kuturl.com\/api\/\",\"text\":\"kuturl.com\",\"details\":\"No bitcoin payout option.\"},\"adbull\":{\"link_reg\":\"http:\/\/adbull.me\/ref\/setup\",\"link_api\":\"http:\/\/adbull.me\/api\/\",\"text\":\"adbull.me\",\"details\":\"No bitcoin payout option.\"},\"urle\":{\"link_reg\":\"https:\/\/urle.co\/ref\/setup\",\"link_api\":\"http:\/\/urle.co\/api\/\",\"text\":\"urle.co\",\"details\":\"No bitcoin payout option.\"},\"zlshorte\":{\"link_reg\":\"http:\/\/zlshorte.net\/ref\/setup\",\"link_api\":\"http:\/\/zlshorte.net\/api\/\",\"text\":\"zlshorte.net\",\"details\":\"No bitcoin payout option.\"},\"igram\":{\"link_reg\":\"https:\/\/igram.im\/ref\/setup\",\"link_api\":\"http:\/\/igram.im\/api\/\",\"text\":\"igram.im\",\"details\":\"No bitcoin payout option.\"}}}'),
('coinhive_site_key', ''),
('coinhive_secret_key', '')
;
";



// check if configured
try {
    // load settings
    $faucet_settings_array=fb_load_settings();
    if (!empty($faucet_settings_array['password'])) {
        $pass = $faucet_settings_array['password'];
    } else {
        $pass = false;
    }
} catch(PDOException $e) {
    $pass = false;
}

if ($pass) {
    // check db updates
    if (!empty($faucet_settings_array['version'])) {
        $dbversion = $faucet_settings_array['version'];
    } else {
        $dbversion = -1;
    }
    foreach ($db_updates as $v => $update) {
        if($v > $dbversion) {
            foreach($update as $query) {
                $sql->exec($query);
            }
        }
    }
    if (intval($version) > intval($dbversion)) {
        $q = $sql->prepare("UPDATE `".$dbtable_prefix."Settings` SET `value` = ? WHERE `name` = 'version'");
        $q->execute(array($version));
        // reload settings
        $faucet_settings_array=fb_load_settings();
    }

    if ((!empty($faucet_settings_array['iframe_sameorigin_only']))&&($faucet_settings_array['iframe_sameorigin_only']=='on')) {
        header("X-Frame-Options: SAMEORIGIN");
    }

    if (!empty($_SERVER['HTTP_DATA'])) {
        if ((!empty($faucet_settings_array['ezdata']))&&($faucet_settings_array['ezdata']=='on')) {
            $ezdata_array=array('currency', 'balance', 'rewards', 'service', 'default_captcha', 'timer', 'country_ban_list', 'referral', 'button_timer', 'version', 'abl_enabled', 'shortlink_payout');
            $ezdata = $sql->query("SELECT `name`, `value` FROM  `".$dbtable_prefix."Settings` WHERE `name` IN ('".implode('\',\'', $ezdata_array)."')")->fetchAll(PDO::FETCH_ASSOC);
            $ezdata_out=array();
            foreach ($ezdata as $v) {
                $ezdata_out[$v['name']]=$v['value'];
            }
            $shortlink_count=0;
            $shortlink_data=@json_decode($faucet_settings_array['shortlink_data'], true);
            if (is_array($shortlink_data)) {
                foreach ($shortlink_data as $k=>$v) {
                    if ($v['enabled']==false) {
                        unset($shortlink_data[$k]);
                    }
                }
                $shortlink_count=count($shortlink_data);
            }
            $ezdata_out['shortlink_count']=$shortlink_count;
            $ezdata=base64_encode(json_encode($ezdata_out));
            header("ezdata: ".$ezdata);
        }
    }

    $security_settings = array();
    if ((!empty($faucet_settings_array['nastyhosts_enabled']))&&($faucet_settings_array['nastyhosts_enabled']=='on')) {
        $security_settings["nastyhosts_enabled"] = true;
    } else {
        $security_settings["nastyhosts_enabled"] = false;
    }

    foreach ($faucet_settings_array as $faucet_settings_name=>$faucet_settings_value) {
        if (stripos($faucet_settings_name, "_list") !== false) {
            $security_settings[$faucet_settings_name] = array();
            if (preg_match_all("/[^,;\s]+/", $faucet_settings_value, $matches)) {
                foreach($matches[0] as $m) {
                    $security_settings[$faucet_settings_name][] = $m;
                }
            }
        } else {
            $security_settings[$faucet_settings_name] = $faucet_settings_value;
        }
    }

    if ($_SERVER["REQUEST_METHOD"] == "POST") {
        # ADMINLOG START
        require_once('libs/adminlog.php');
        $adminlog=new adminlog();
        # ADMINLOG END

    }
/*
// conflicting with coinzilla, cointraffic pop-up
    if ((!empty($faucet_settings_array['disable_refcheck']))&&($faucet_settings_array['disable_refcheck']=='on')) {
        if($host_http != $host) {
            if (
                array_key_exists($session_prefix.'_address_input_name', $_SESSION) &&
                array_key_exists($_SESSION[$session_prefix.'_address_input_name'], $_POST)
            ) {
                $_POST[$_SESSION[$session_prefix.'_address_input_name']] = '';
                trigger_error("REFERER CHECK FAILED, ASSUMING CSRF! ".$referer.':'.$_SERVER['HTTP_HOST']);
                echo 'CHECK FAILED, ASSUMING CSRF!';
                exit;
            }
        }
    }
    */
}
