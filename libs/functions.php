<?php

function fb_load_settings() {
    global $sql, $dbtable_prefix;

    $faucet_settings_array=array();

    $faucet_settings_quey = $sql->query("SELECT `name`, `value` FROM `".$dbtable_prefix."Settings`")->fetchAll(PDO::FETCH_ASSOC);
    foreach ($faucet_settings_quey as $faucet_settings_row) {
        $faucet_settings_array[$faucet_settings_row['name']]=$faucet_settings_row['value'];
    }
    return $faucet_settings_array;
}

function getUniqueRequestID() {
    global $unique_request_id;

    if (!empty($unique_request_id)) {
        return $unique_request_id;
    } else {
        return '';
    }
}

function showExtensionsErrorPage($extensions_status) {
    global $version;
    require_once("script/admin_templates.php");
    
    $page = str_replace("<:: content ::>", $extensions_error_template, $master_template);
    
    foreach ($extensions_status as $ext => $status) {
        $page = str_replace("<:: {$ext}_color ::>", ($status ? "success" : "danger"), $page);
        $page = str_replace("<:: {$ext}_glyphicon ::>", ($status ? $extensions_ok_glyphicon : $extensions_error_glyphicon), $page);
    }
    
    die($page);
}

function randHash($length) {
    $hash = '';
    if ($length>2) {
      $alphabet = str_split('qwertyuiopasdfghjklzxcvbnm');
      for($i = 0; $i < 2; $i++) {
          $hash .= $alphabet[array_rand($alphabet)];
      }
      $length-=2;
    }
    $alphabet = str_split('qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890');
    for($i = 0; $i < $length; $i++) {
        $hash .= $alphabet[array_rand($alphabet)];
    }
    return $hash;
}

function getNastyHostsServer() {
    return "http://v1.nastyhosts.com/";
}

function checkRevProxyIp($file) {
    require_once("libs/http-foundation/IpUtils.php");
    return IpUtils::checkIp($_SERVER['REMOTE_ADDR'], array_map(function($v) { return trim($v); }, file($file)));
}

function detectRevProxyProvider() {
    if(checkRevProxyIp("libs/ips/cloudflare.txt")) {
        return "CloudFlare";
    } elseif(checkRevProxyIp("libs/ips/incapsula.txt")) {
        return "Incapsula";
    }
    return "none";
}

function getIP() {
    global $sql, $faucet_settings_array;
    static $cache_ip;
    if ($cache_ip) return $cache_ip;
    $ip = null;
    if ((!empty($faucet_settings_array['reverse_proxy'])) && $faucet_settings_array['reverse_proxy'] == 'on') {
        if (checkRevProxyIp("libs/ips/cloudflare.txt")) {
            $ip = array_key_exists('HTTP_CF_CONNECTING_IP', $_SERVER) ? $_SERVER['HTTP_CF_CONNECTING_IP'] : null;
        } elseif (checkRevProxyIp("libs/ips/incapsula.txt")) {
            $ip = array_key_exists('HTTP_INCAP_CLIENT_IP', $_SERVER) ? $_SERVER['HTTP_INCAP_CLIENT_IP'] : null;
        }
    }
    if (empty($ip)) {
        $ip = $_SERVER['REMOTE_ADDR'];
    }
    $cache_ip = $ip;
    return $ip;
}

function is_ssl(){
    if(isset($_SERVER['HTTPS'])){
        if('on' == strtolower($_SERVER['HTTPS']))
            return true;
        if('1' == $_SERVER['HTTPS'])
            return true;
        if(true == $_SERVER['HTTPS'])
            return true;
    }elseif(isset($_SERVER['SERVER_PORT']) && ('443' == $_SERVER['SERVER_PORT'])){
        return true;
    }
    if(isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower($_SERVER['HTTP_X_FORWARDED_PROTO']) == 'https') {
        return true;
    }
    return false;
}

function ipSubnetCheck ($ip, $network) {
    $network = explode("/", $network);
    $net = $network[0];

    if(count($network) > 1) {
        $mask = $network[1];
    } else {
        $mask = 32;
    }

    $net = ip2long ($net);
    $mask = ~((1 << (32 - $mask)) - 1);

    $ip_net = $ip & $mask;

    return ($ip_net == $net);
}

function nastyhosts_log($suggestion, $reason='', $response=array()) {
    global $sql, $session_prefix, $dbtable_prefix;
    if (empty($session_prefix)) {
        return;
    }
    if (empty($_SESSION[$session_prefix.'_address_input_name'])) {
        return;
    }
    if (empty($_POST[$_SESSION[$session_prefix.'_address_input_name']])) {
        return;
    }
    // Delete the log that is older than a day - for better performance execute every ~20 requests
    if (mt_rand(0, 20)==5) {
        $sql->exec("DELETE FROM `".$dbtable_prefix."NH_Log` WHERE ".$dbtable_prefix."NH_Log_time<".(time()-86400).";");
    }
    $q=$sql->prepare("INSERT INTO `".$dbtable_prefix."NH_Log` SET
                      ".$dbtable_prefix."NH_Log_time=?,
                      ".$dbtable_prefix."NH_Log_IP=?,
                      ".$dbtable_prefix."NH_Log_address=?,
                      ".$dbtable_prefix."NH_Log_address_ref=?,
                      ".$dbtable_prefix."NH_Log_suggestion=?,
                      ".$dbtable_prefix."NH_Log_reason=?,
                      ".$dbtable_prefix."NH_Log_country_code=?,
                      ".$dbtable_prefix."NH_Log_country=?,
                      ".$dbtable_prefix."NH_Log_asn=?,
                      ".$dbtable_prefix."NH_Log_asn_name=?,
                      ".$dbtable_prefix."NH_Log_host=?,
                      ".$dbtable_prefix."NH_Log_useragent=?,
                      ".$dbtable_prefix."NH_Log_session_id=?
                    ;");
    $q->execute(array(
                      time(),
                      trim(getIP()),
                      trim(!empty($_POST[$_SESSION[$session_prefix.'_address_input_name']])?$_POST[$_SESSION[$session_prefix.'_address_input_name']]:''),
                      trim(!empty($_GET['r'])?$_GET['r']:''),
                      trim(!empty($suggestion)?$suggestion:''),
                      trim(!empty($reason)?$reason:''),
                      trim(!empty($response['country']['code'])?$response['country']['code']:''),
                      trim(!empty($response['country']['country'])?$response['country']['country']:''),
                      trim(!empty($response['asn']['asn'])?$response['asn']['asn']:'0'),
                      trim(!empty($response['asn']['name'])?substr($response['asn']['name'], 0, 128):''),
                      trim(!empty($response['hostnames'][0])?$response['hostnames'][0]:''),
                      trim(!empty($_SERVER['HTTP_USER_AGENT'])?$_SERVER['HTTP_USER_AGENT']:''),
                      session_id().'-'.getUniqueRequestID()
                      ));
}


function regenerate_csrf_token() {
    global $session_prefix;
    $_SESSION[$session_prefix.'_csrftoken'] = base64_encode(openssl_random_pseudo_bytes(20));
}

function get_csrf_token() {
    global $session_prefix;
    return "<input type=\"hidden\" name=\"csrftoken\" value=\"". $_SESSION[$session_prefix.'_csrftoken']. "\">";
}



function setNewPass() {
    global $sql, $dbtable_prefix;
    $alphabet = str_split('qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890');
    $password = '';
    for($i = 0; $i < 15; $i++) {
        $password .= $alphabet[array_rand($alphabet)];
    }
    // ultimate - bugfix
    $hash = crypt($password, md5_file('./config.php'));
    $sql->query("REPLACE INTO ".$dbtable_prefix."Settings VALUES ('password', '$hash')");
    return $password;
}



// Check functions

function checkTimeForIP($ip, &$time_left = NULL) {
    global $sql, $data, $dbtable_prefix;
    $q = $sql->prepare("SELECT TIMESTAMPDIFF(MINUTE, last_used, CURRENT_TIMESTAMP()) FROM ".$dbtable_prefix."IPs WHERE ip = ?");
    $q->execute([$ip]);
    if ($time = $q->fetch()) {
        $time = intval($time[0]);
        $required = intval($data["timer"]);
        
        $time_left = $required-$time;
        return $time >= intval($data["timer"]);
    } else {
        $time_left = 0;
        return true;
    }
}

function checkTimeForAddress($address, &$time_left) {
    global $sql, $data, $dbtable_prefix;
    $q = $sql->prepare("SELECT TIMESTAMPDIFF(MINUTE, last_used, CURRENT_TIMESTAMP()) FROM ".$dbtable_prefix."Addresses WHERE `address` = ?");
    $q->execute([$address]);
    if ($time = $q->fetch()) {
        $time = intval($time[0]);
        $required = intval($data["timer"]);

        $time_left = $required-$time;
        return $time >= intval($data["timer"]);
    } else {
        $time_left = 0;
        return true;
    }
}

function checkAddressValidity($address) {
    global $data;

    return (preg_match("/^[0-9A-Za-z]{26,50}$/", $address) === 1);
}

function checkAddressBlacklist($address) {
    global $security_settings;
    return !in_array($address, $security_settings["address_ban_list"]);
}

function checkIPIsWhitelisted() {
    global $security_settings;
    $ip = ip2long(getIP());
    if ($ip) { // only ipv4 supported here
        foreach ($security_settings["ip_white_list"] as $whitelisted) {
            if (ipSubnetCheck($ip, $whitelisted)) {
                return true;
            }
        }
    }
    return false;
}

function checkIPBlacklist() {
    global $security_settings;
    $ip = ip2long(getIP());
    if ($ip) { // only ipv4 supported here
        foreach ($security_settings["ip_ban_list"] as $ban) {
            if (ipSubnetCheck($ip, $ban)) {
                trigger_error("Banned: ".getIP()." (blacklist: {$ban})");
                return false;
            }
        }
    }
    return true;
}

function checkNastyHosts(&$return_exact_error) {
    global $security_settings;
    if ($security_settings["nastyhosts_enabled"]) {
        $hostnames = @file_get_contents(getNastyHostsServer().getIP().'?source=fiab');
        $hostnames_array = json_decode($hostnames, true);
        $hostnames = json_decode($hostnames);

        if ($hostnames && property_exists($hostnames, "status") && $hostnames->status == 200) {
            if (property_exists($hostnames, "suggestion") && $hostnames->suggestion == "deny") {
                $return_exact_error='Your IP address has been blacklisted by nastyhosts.';
                // log banned - nastyhosts
                nastyhosts_log('deny', 'Banned by NastyHosts.', $hostnames_array);
                trigger_error("Banned: ".getIP()." (NastyHosts)");
                return false;
            }
            if (property_exists($hostnames, "asn") && property_exists($hostnames->asn, "asn")) {
                foreach ($security_settings["asn_ban_list"] as $ban) {
                    if ($ban == $hostnames->asn->asn) {
                        $return_exact_error='Your ASN has been blacklisted.';
                        // log banned - asn
                        nastyhosts_log('deny', 'Banned by ASN.', $hostnames_array);
                        trigger_error("Banned: ".getIP()." (ASN: {$ban})");
                        return false;
                    }
                }
            }
            if (property_exists($hostnames, "country") && property_exists($hostnames->country, "code")) {
                foreach ($security_settings["country_ban_list"] as $ban) {
                    if ($ban == $hostnames->country->code) {
                        $return_exact_error='Your country '.$hostnames->country->code.' has been blacklisted.';
                        // log banned - country
                        nastyhosts_log('deny', 'Banned by Country.', $hostnames_array);
                        trigger_error("Banned: ".getIP()." (country: {$ban})");
                        return false;
                    }
                }
            }
            if (property_exists($hostnames, "hostnames")) {
                foreach ($security_settings["hostname_ban_list"] as $ban) {
                    foreach ($hostnames->hostnames as $hostname) {
                        if (stripos($hostname, $ban) !== false) {
                            $return_exact_error='Your hostname '.$hostname.' has been blacklisted.';
                            // log banned - hostname
                            nastyhosts_log('deny', 'Banned by Hostname.', $hostnames_array);
                            trigger_error("Banned: ".getIP()." (hostname: {$ban})");
                            return false;
                        }
                    }
                }
            }
            nastyhosts_log('allow', 'Seems legit.', $hostnames_array);
        } else {
            // nastyhosts down or status != 200
            $return_exact_error='Couldn\'t connect to NastyHost, refusing to payout!';
            nastyhosts_log('deny', 'Couldn\'t connect to NastyHost, refusing to payout!', $hostnames_array);
            trigger_error("Couldn't connect to NastyHost, refusing to payout!");
            return false;
        }
    }
    

    return true;
}

function checkCaptcha() {
    global $data, $captcha;
    
    switch ($captcha['selected']) {
        case 'SolveMedia':
            require_once('libs/solvemedialib.php');
            $resp = solvemedia_check_answer(
                $data['solvemedia_verification_key'],
                getIP(),
                (array_key_exists('adcopy_challenge', $_POST) ? $_POST['adcopy_challenge'] : ''),
                (array_key_exists('adcopy_response', $_POST) ? $_POST['adcopy_response'] : ''),
                $data['solvemedia_auth_key']
            );
            return $resp->is_valid;
        break;
        case 'reCaptcha':
            $url = 'https://www.google.com/recaptcha/api/siteverify?secret='.$data['recaptcha_private_key'].'&response='.(array_key_exists('g-recaptcha-response', $_POST) ? $_POST['g-recaptcha-response'] : '').'&remoteip='.getIP();
            $resp = json_decode(file_get_contents($url), true);
            return $resp['success'];
        break;
        case 'FunCaptcha':
            require_once('libs/funcaptcha.php');
            $funcaptcha = new FUNCAPTCHA();
            return $funcaptcha->checkResult($data['funcaptcha_private_key']);
        break;
        case 'BitCaptcha':
            require_once('libs/sqn.php');
            $captcha = $_POST['sqn_captcha'];
            $sqn_key = (strpos($_SERVER['HTTP_HOST'], 'ww.') > 0) ? $data['sqn_key_www'] : $data['sqn_key'];
            $sqn_id = (strpos($_SERVER['HTTP_HOST'], 'ww.') > 0) ? $data['sqn_id_www'] : $data['sqn_id'];
            $gtResult = sqn_validate($captcha, $sqn_key, $sqn_id, true);
            return $gtResult;
        break;
        case 'CoinHive':
            require_once('libs/coinhive.php');
            $coinhiveobj = new coinhive();
            return $coinhiveobj->checkResult($_POST['coinhive-captcha-token']);
        break;
    }

    return false;
}

function releaseAddressLock($address) {
    global $sql, $dbtable_prefix;
    $q = $sql->prepare("DELETE FROM ".$dbtable_prefix."Address_Locks WHERE address = ?");
    $q->execute([$address]);
}

function claimAddressLock($address) {
    global $sql, $dbtable_prefix;
    $q = $sql->prepare("DELETE FROM ".$dbtable_prefix."Address_Locks WHERE address = ? AND TIMESTAMPDIFF(MINUTE, locked_since, CURRENT_TIMESTAMP()) > 5");
    $q->execute([$address]);
    $q = $sql->prepare("INSERT INTO ".$dbtable_prefix."Address_Locks (address, locked_since) VALUES (?, CURRENT_TIMESTAMP())");
    try {
        $q->execute([$address]);
    } catch (PDOException $e) {
        if($e->getCode() == 23000) {
            return false;
        } else {
            throw $e;
        }
    }
    register_shutdown_function("releaseAddressLock", $address);
    return true;
}

function releaseIPLock($ip) {
    global $sql, $dbtable_prefix;
    $q = $sql->prepare("DELETE FROM ".$dbtable_prefix."IP_Locks WHERE ip = ?");
    $q->execute([$ip]);
}

function claimIPLock($ip) {
    global $sql, $dbtable_prefix;
    $q = $sql->prepare("DELETE FROM ".$dbtable_prefix."IP_Locks WHERE ip = ? AND TIMESTAMPDIFF(MINUTE, locked_since, CURRENT_TIMESTAMP()) > 5");
    $q->execute([$ip]);
    $q = $sql->prepare("INSERT INTO ".$dbtable_prefix."IP_Locks (ip, locked_since) VALUES (?, CURRENT_TIMESTAMP())");
    try {
        $q->execute([$ip]);
    } catch (PDOException $e) {
        if($e->getCode() == 23000) {
            return false;
        } else {
            throw $e;
        }
    }
    register_shutdown_function("releaseIPLock", $ip);
    return true;
}

function getClaimError($address) {
    global $sql, $dbtable_prefix;

    if (!claimAddressLock($address)) {
        return 'You were locked for multiple claims, try again in 5 minutes.';
    }
    if (!claimIPLock(getIP())) {
        return 'You were locked for multiple claims, try again in 5 minutes.';
    }
    if (!checkAddressValidity($address)) {
        return 'Invalid address';
    }
    if (!checkTimeForAddress($address, $time_left)) {
        return 'You have to wait '.$time_left.' minutes';
    }
    if (!checkTimeForIP(getIP(), $time_left)) {
        return 'You have to wait '.$time_left.' minutes';
    }
    # AntiBotLinks START
    global $antibotlinks;
    if (!$antibotlinks->is_valid()) {
        return 'Invalid AntiBot verification!';
    }
    # AntiBotLinks END
    if (!checkCaptcha()) {
        nastyhosts_log('deny', 'Invalid captcha code.', array());
        return 'Invalid captcha code';
    }
    if (!checkAddressBlacklist($address)) {
        nastyhosts_log('deny', 'Your *coin address has been blacklisted.', array());
        return 'Your *coin address has been blacklisted.';
    }
    // check if R is allowed
    if (!empty($_GET['r'])) {
      if (!checkAddressBlacklist($_GET['r'])) {
          nastyhosts_log('deny', 'Your ref *coin address has been blacklisted.', array());
          return 'Your ref *coin address has been blacklisted.';
      }
    }
    $q = $sql->prepare("SELECT address FROM ".$dbtable_prefix."Refs WHERE id = (SELECT ref_id FROM ".$dbtable_prefix."Addresses WHERE address = ?)");
    $q->execute(array(trim($address)));
    if ($ref = $q->fetch()) {
        if (!checkAddressBlacklist(trim($ref[0]))) {
            nastyhosts_log('deny', 'Your ref *coin address has been blacklisted.', array());
            return 'Your ref *coin address has been blacklisted.';
        }
    }
    //
    if(!checkIPIsWhitelisted()) {
        if (!checkIPBlacklist()) {
            nastyhosts_log('deny', 'Your IP address has been blacklisted.', array());
            return 'Your IP address has been blacklisted.';
        }
        $return_exact_error='';
        if (!checkNastyHosts($return_exact_error)) {
            return $return_exact_error;
        }
        # WFM START
        global $wfm;
        $return_exact_error='';
        if (!$wfm->is_valid($return_exact_error)) {
            return $return_exact_error;
        }
        # WFM END
    }

    return null;
}

?>