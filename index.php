<?php

/*
 * Faucet in a BOX
 * https://faucetinabox.com/
 *
 * Copyright (c) 2014-2016 LiveHome Sp. z o. o.
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

$unique_request_id=mt_rand(1000, 9999);

// ultimate - not needed
if (!empty($_POST['mmc'])) {
    exit;
}

require_once("script/common.php");

if (!$pass) {
    // first run
    header("Location: admin.php");
    die("Please wait...");
}

if (array_key_exists("p", $_GET) && in_array($_GET["p"], ["admin", "password-reset"])) {
    header("Location: admin.php?p={$_GET["p"]}");
    die("Please wait...");
}

// Check protocol
if (array_key_exists("HTTPS", $_SERVER) && $_SERVER["HTTPS"]) {
    $protocol = "https://";
} else {
    $protocol = "http://";
}

// data array
$data = array(
    "paid" => false,
    "disable_admin_panel" => $disable_admin_panel,
    "address" => "",
    "captcha_valid" => true, //for people who won't update templates
    "captcha" => false,
    "enabled" => false,
    "error" => false,
    "address_eligible" => true,
    "reflink" => $protocol.$_SERVER['HTTP_HOST'].strtok($_SERVER['REQUEST_URI'], '?').'?r='
);

// Get settings from DB
foreach ($faucet_settings_array as $faucet_settings_name=>$faucet_settings_value) {
    if ($faucet_settings_name == 'safety_limits_end_time') {
        $time = strtotime($faucet_settings_value);
        if ($time !== false && $time < time()) {
            $faucet_settings_value = '';
        }
    }
    $data[$faucet_settings_name] = $faucet_settings_value;
}

// Set unit name
$data['unit'] = 'satoshi';
if ($data['currency'] == 'DOGE') {
    $data['unit'] = 'DOGE';
}

// Get address
if (array_key_exists($session_prefix.'_address_input_name', $_SESSION) && array_key_exists($_SESSION[$session_prefix.'_address_input_name'], $_POST)) {
    $_POST["address"] = $_POST[$_SESSION[$session_prefix.'_address_input_name']];
} else {
    if ($_SERVER['REQUEST_METHOD'] == "POST") {
        if (array_key_exists($session_prefix.'_address_input_name', $_SESSION)) {
            trigger_error("Post request, but invalid address input name.");
        } else {
            trigger_error("Post request, but session is invalid.");
        }
    }
    unset($_POST["address"]);
}

// Generate ref link
if (array_key_exists('address', $_POST)) {
    $data["reflink"] .= $_POST['address'];
    $data["address"] = $_POST['address'];
} else if (array_key_exists('address', $_COOKIE)) {
    $data["reflink"] .= $_COOKIE['address'];
    $data["address"] = $_COOKIE['address'];
} else {
    $data["reflink"] .= 'Your_Address';
}

// Get template
$template = $faucet_settings_array['template'];
if (!file_exists("templates/{$template}/index.php")) {
    $templates = glob("templates/*");
    if ($templates) {
        $template = substr($templates[0], strlen("templates/"));
    } else {
        die(str_replace('<:: content ::>', "<div class='alert alert-danger' role='alert'>No templates found!</div>", $master_template));
    }
}

// Update balance
if (time() - $data['last_balance_check'] > 60*10) {
    $fb = new Service($data['service'], $data['apikey'], $data['currency'], $connection_options);
    $ret = $fb->getBalance();
    if (!empty($ret)) {
        if (array_key_exists('balance', $ret)) {
            if ($data['currency'] != 'DOGE') {
                $balance = $ret['balance'];
            } else {
                $balance = $ret['balance_bitcoin'];
            }
            $q = $sql->prepare("UPDATE ".$dbtable_prefix."Settings SET value = ? WHERE name = ?");
            $q->execute(array(time(), 'last_balance_check'));
            $q->execute(array($balance, 'balance'));
            $data['balance'] = $balance;
            $data['last_balance_check'] = time();
        }
        if ((!empty($ret['status']))&&($ret['status']==452)) {
            $q = $sql->prepare("UPDATE ".$dbtable_prefix."Settings SET value = ? WHERE name = ?");
            $q->execute(array('', 'apikey'));
        }
    }
}

#MuliCaptcha: Firstly check chosen captcha system
$captcha = array('available' => array(), 'selected' => null);
if ($data['solvemedia_challenge_key'] && $data['solvemedia_verification_key'] && $data['solvemedia_auth_key']) {
    $captcha['available'][] = 'SolveMedia';
}
if ($data['recaptcha_public_key'] && $data['recaptcha_private_key']) {
    $captcha['available'][] = 'reCaptcha';
}
if ($data['funcaptcha_public_key'] && $data['funcaptcha_private_key']) {
    $captcha['available'][] = 'FunCaptcha';
}
if (($data['sqn_id'] && $data['sqn_key']) || ($data['sqn_id_www'] && $data['sqn_key_www'])) {
    $captcha['available'][] = 'BitCaptcha';
}
if ($data['coinhive_site_key'] && $data['coinhive_secret_key']) {
    $captcha['available'][] = 'CoinHive';
}

#MuliCaptcha: Secondly check if user switched captcha or choose default
if (array_key_exists('cc', $_GET) && in_array($_GET['cc'], $captcha['available'])) {
    $captcha['selected'] = $captcha['available'][array_search($_GET['cc'], $captcha['available'])];
    $_SESSION[$session_prefix.'_selected_captcha'] = $captcha['selected'];
} elseif (array_key_exists($session_prefix.'_selected_captcha', $_SESSION) && in_array($_SESSION[$session_prefix.'_selected_captcha'], $captcha['available'])) {
    $captcha['selected'] = $_SESSION[$session_prefix.'_selected_captcha'];
} else {
    if ($captcha['available']) {
        $captcha['selected'] = $captcha['available'][0];
    }
    if (in_array($data['default_captcha'], $captcha['available'])) {
        $captcha['selected'] = $data['default_captcha'];
    } else if ($captcha['available']) {
        $captcha['selected'] = $captcha['available'][0];
    }
}

#MuliCaptcha: And finally handle chosen captcha system
# -> checkCaptcha()
switch ($captcha['selected']) {
    case 'SolveMedia':
        require_once('libs/solvemedialib.php');
        $data['captcha'] = solvemedia_get_html($data['solvemedia_challenge_key'], null, is_ssl());
    break;
    case 'reCaptcha':
        #reCaptcha template
        $recaptcha_template = '
        <script src="https://www.google.com/recaptcha/api.js" async defer></script>
        <div class="g-recaptcha" data-sitekey="<:: your_site_key ::>"></div>
        <noscript>
          <div style="width: 302px; height: 352px;">
            <div style="width: 302px; height: 352px; position: relative;">
              <div style="width: 302px; height: 352px; position: absolute;">
                <iframe src="https://www.google.com/recaptcha/api/fallback?k=<:: your_site_key ::>"
                        frameborder="0" scrolling="no"
                        style="width: 302px; height:352px; border-style: none;">
                </iframe>
              </div>
              <div style="width: 250px; height: 80px; position: absolute; border-style: none;
                          bottom: 21px; left: 25px; margin: 0px; padding: 0px; right: 25px;">
                <textarea id="g-recaptcha-response" name="g-recaptcha-response"
                          class="g-recaptcha-response"
                          style="width: 250px; height: 80px; border: 1px solid #c1c1c1;
                                 margin: 0px; padding: 0px; resize: none;" value="">
                </textarea>
              </div>
            </div>
          </div>
        </noscript>
        ';
        $data['captcha'] = str_replace('<:: your_site_key ::>', $data['recaptcha_public_key'], $recaptcha_template);
    break;
    case 'FunCaptcha':
        require_once('libs/funcaptcha.php');
        $funcaptcha = new FUNCAPTCHA();
        $data['captcha'] =  $funcaptcha->getFunCaptcha($data['funcaptcha_public_key']);
    break;
    case 'BitCaptcha':
        $sqn_id = trim((strpos($_SERVER['HTTP_HOST'], 'ww.') > 0) ? $data['sqn_id_www'] : $data['sqn_id']);
        $data['captcha'] = '
<div id="SQNView" style="margin-left:auto;margin-right:auto;width:300px;">
    <div id="SQNContainer" sqn-height="40">
        <div id="SQN-load-bg"></div>
        <div class="SQN-init">
            <a href="https://www.shenqiniao.com/" target="_blank"><img src="//static.shenqiniao.net/loading.gif"/></a>
            <span class="vaptcha-text">Loading...</span>
        </div>
    </div>
    <a class="SQN-tips" href="http://bitcaptcha.io/help.html" title="Help" target="_blank"><img src="//static.shenqiniao.net/t.png"/></a>
</div>
<script src="//static.shenqiniao.net/sqn.js?id=' . $sqn_id . '&btn=&lng=en" type="text/javascript"></script>';
    break;
    case 'CoinHive':
        $data['captcha'] = '
<div class="coinhive-captcha" style="margin-left:auto;margin-right:auto;width:304px;" data-hashes="1024" data-key="'.$data['coinhive_site_key'].'">
    <em>Loading Captcha...<br>If it doesn\'t load, please disable Adblock!</em>
</div>
<script src="https://authedmine.com/lib/captcha.min.js" async></script>';
    break;
}

$data['captcha_info'] = $captcha;

# AntiBotLinks START
require_once('libs/antibotlinks.php');
$antibotlinks = new antibotlinks(true, 'ttf,otf');// true if GD is on on the server, false is less secure, also you can enable ttf and/or otf
if (array_key_exists('address', $_POST)) {
  if (!$antibotlinks->check()) {
    // suggested (it is way better to have more word universes than more links)
    // 4 links should be enough to discourage (and make easy to detect) brute-force
    $antibotlinks->generate(4, true);// number of links once they fail, the second param MUST BE true
  }
} else {
  // suggested (it is way better to have more word universes than more links)
  // 4 links should be enough to discourage (and make easy to detect) brute-force
  $antibotlinks->generate(4);// initial number of links
}
# AntiBotLinks END

# WFM START
require_once('libs/wfm.php');
$wfm = new wfm($connection_options);
$wfm->is_visit_check_valid();
# WFM END

// Check if faucet's enabled
if ($data['captcha'] && $data['apikey'] && $data['rewards']) {
    $data['enabled'] = true;
}

// check if IP eligible
$data["eligible"] = checkTimeForIP(getIP(), $time_left);
$data['time_left'] = $time_left." minutes";


// Rewards
$rewards = explode(',', $data['rewards']);
$total_weight = 0;
$nrewards = array();
foreach ($rewards as $reward) {
    $reward = explode("*", trim($reward));
    if (count($reward) < 2) {
        $reward[1] = $reward[0];
        $reward[0] = 1;
    }
    $total_weight += intval($reward[0]);
    $nrewards[] = $reward;
}
$rewards = $nrewards;
if (count($rewards) > 1) {
    $possible_rewards = array();
    foreach ($rewards as $r) {
        $chance_per = 100 * $r[0]/$total_weight;
        if ($chance_per < 0.1)
            $chance_per = '< 0.1%';
        else
            $chance_per = round(floor($chance_per*10)/10, 1).'%';

        $possible_rewards[] = $r[1]." ($chance_per)";
    }
} else {
    $possible_rewards = array($rewards[0][1]);
}



if (array_key_exists('address', $_POST) && $data['enabled'] && $data['eligible']) {
    $address = trim($_POST["address"]);

    if(empty($data['address']))
        $data['address'] = $address;

    $error = getClaimError($address);
    if ($error) {
        $data["error"] = "<div class=\"alert alert-danger\">{$error}</div>";
        $adminlog->admin_set_message($error);
    } else {
        // Rand amount
        $r = mt_rand()/mt_getrandmax();
        $t = 0;
        foreach ($rewards as $reward) {
            $t += intval($reward[0])/$total_weight;
            if ($t > $r) {
                break;
            }
        }
        if (strpos($reward[1], '-') !== false) {
            $reward_range = explode('-', $reward[1]);
            $from = floatval($reward_range[0]);
            $to = floatval($reward_range[1]);
            $reward = mt_rand($from, $to);
        } else {
            $reward = floatval($reward[1]);
        }

        if ((isset($_SESSION['shortlink']['solved']))&&($_SESSION['shortlink']['solved']==true)) {
            unset($_SESSION['shortlink']);
            if (strpos($faucet_settings_array['shortlink_payout'], '%')!==false) {
                $shortlink_reward=(int)$faucet_settings_array['shortlink_payout'];
                $reward=$reward+$reward*($shortlink_reward/100);
            } else {
                if ($faucet_settings_array['currency']=='DOGE') {
                    $reward=$reward+(float)$faucet_settings_array['shortlink_payout'];
                } else {
                    $reward=$reward+(int)$faucet_settings_array['shortlink_payout'];
                }
            }
        }

        $fb = new Service($data['service'], $data['apikey'], $data['currency'], $connection_options);
        $ret = $fb->send($address, $reward, getIP());
        if ((!empty($ret['status']))&&($ret['status']==452)) {
            $q = $sql->prepare("UPDATE ".$dbtable_prefix."Settings SET value = ? WHERE name = ?");
            $q->execute(array('', 'apikey'));
            $q->execute(array('0', 'balance'));
        }
        if (strpos($ret['html'], 'make an account')!==false) {
            $ret['html']=str_replace('FaucetHub.io', '<a href="http://faucethub.io/" onmousedown="$(this).attr(\'href\', \''.$faucethub_ref_url.'\');" target="_blank">FaucetHub.io</a>', $ret['html']);
            $ret['html']=str_replace('make an account', '<a href="http://faucethub.io/" onmousedown="$(this).attr(\'href\', \''.$faucethub_ref_url.'\');" target="_blank">make an account</a>', $ret['html']);
        }

        $user_hash_claim='';
        if (!empty($ret['user_hash'])) {
            $user_hash_claim=$ret['user_hash'];
        }
        $ret_msg='<b>'.trim($_POST['address']).'</b>'."\n".(empty($ret['user_hash'])?'':$ret['user_hash']."\n").strip_tags($ret['html']);
        if ($ret['success']) {
            setcookie('address', trim($_POST['address']), time() + 60*60*24*60);
            if (!empty($ret['balance'])) {
                $q = $sql->prepare("UPDATE ".$dbtable_prefix."Settings SET `value` = ? WHERE `name` = 'balance'");

                if ($data['unit'] == 'satoshi') {
                    $data['balance'] = $ret['balance'];
                } else {
                    $data['balance'] = $ret['balance_bitcoin'];
                }
                $q->execute(array($data['balance']));
            }

            if (!empty($faucet_settings_array['safety_limits_end_time'])) {
                $sql->exec("UPDATE ".$dbtable_prefix."Settings SET value = '' WHERE `name` = 'safety_limits_end_time' ");
            }

            // handle refs
            if (array_key_exists('r', $_GET) && trim($_GET['r']) != $address) {
                $q = $sql->prepare("INSERT IGNORE INTO ".$dbtable_prefix."Refs (address) VALUES (?)");
                $q->execute(array(trim($_GET['r'])));
                $q = $sql->prepare("INSERT IGNORE INTO ".$dbtable_prefix."Addresses (`address`, `ref_id`, `last_used`) VALUES (?, (SELECT id FROM ".$dbtable_prefix."Refs WHERE address = ?), CURRENT_TIMESTAMP())");
                $q->execute(array(trim($_POST['address']), trim($_GET['r'])));
            }
            $refamount = floatval($data['referral'])*$reward/100;
            if ($data['unit'] == 'satoshi') {
                $refamount=round($refamount);
                if (($refamount<1)&&($data['referral']>0)) {
                    $refamount=1;
                }
            }
            if ($refamount>0) {
                $q = $sql->prepare("SELECT address FROM ".$dbtable_prefix."Refs WHERE id = (SELECT ref_id FROM ".$dbtable_prefix."Addresses WHERE address = ?)");
                $q->execute(array(trim($_POST['address'])));
                if ($ref = $q->fetch()) {
                    // moved to security check
                    $ret_ref=$fb->sendReferralEarnings(trim($ref[0]), $refamount, getIP());
                    $ret_msg.="\n".'<b>'.trim($ref[0]).'</b>'."\n".(empty($ret_ref['user_hash'])?'':$ret_ref['user_hash']."\n").strip_tags($ret_ref['html']);
                    if (!empty($ret_ref['user_hash'])) {
                        $user_hash_ref=$ret_ref['user_hash'];
                        if ($user_hash_ref==$user_hash_claim) {
                            // disconnect the user from the R if they have the same user_hash
                            $sql->prepare("UPDATE ".$dbtable_prefix."Addresses SET ref_id=NULL WHERE address = ?)");
                            $q->execute(array(trim($_POST['address'])));
                        }
                    }
                }
            }
            if ($data['unit'] == 'satoshi') {
                $data['paid'] = $ret['html'];
            } else {
                $data['paid'] = $ret['html_coin'];
            }
        } else {
            $response = json_decode($ret["response"]);
            if ($response && property_exists($response, "status") && $response->status == 450) {
                // how many minutes until next safety limits reset?
                $end_minutes  = (date("i") > 30 ? 60 : 30) - date("i");
                // what date will it be exactly?
                $end_date = date("Y-m-d H:i:s", time()+$end_minutes*60-date("s"));
                $sql->prepare("UPDATE ".$dbtable_prefix."Settings SET value = ? WHERE `name` = 'safety_limits_end_time' ")->execute([$end_date]);
            }
            $data['error'] = $ret['html'];
        }
        
        if ($ret['success'] || $fb->communication_error) {
            $q = $sql->prepare("INSERT INTO ".$dbtable_prefix."IPs (`ip`, `last_used`) VALUES (?, CURRENT_TIMESTAMP()) ON DUPLICATE KEY UPDATE `last_used` = CURRENT_TIMESTAMP()");
            $q->execute([getIP()]);
            $q = $sql->prepare("INSERT INTO ".$dbtable_prefix."Addresses (`address`, `last_used`) VALUES (?, CURRENT_TIMESTAMP()) ON DUPLICATE KEY UPDATE `last_used` = CURRENT_TIMESTAMP()");
            $q->execute([$address]);

        }
        $adminlog->admin_set_message($ret_msg);
    }
}

if (!$data['enabled']) {
    $page = 'disabled';
} elseif ($data['paid']) {
    $page = 'paid';
} elseif ($data['eligible'] && $data['address_eligible']) {
    $page = 'eligible';
} else {
    $page = 'visit_later';
}
$data['page'] = $page;

// shortlink
$data['shortlink']='';
$shortlink_enabled=true;
$shortlink_data=@json_decode($faucet_settings_array['shortlink_data'], true);
if (!is_array($shortlink_data)) {
    $shortlink_enabled=false;
}
foreach ($shortlink_data as $k=>$v) {
    if ($v['enabled']==false) {
        unset($shortlink_data[$k]);
    }
}
if (count($shortlink_data)<1) {
    $shortlink_enabled=false;
}    
if (($shortlink_enabled)&&($page=='eligible')) {
    if (empty($_SESSION['shortlink']['hash'])||empty($_SESSION['shortlink']['solved'])) {
        $_SESSION['shortlink']['hash']=randHash(rand(10, 12));
        $_SESSION['shortlink']['solved']=false;
    }
    if ($_SESSION['shortlink']['solved']==true) {
        $data['shortlink']='<div id="id_shortlink" class="alert alert-success shortlink">';
        $data['shortlink'].='You will get ';
        if (strpos($faucet_settings_array['shortlink_payout'], '%')!==false) {
            $data['shortlink'].=(int)$faucet_settings_array['shortlink_payout'].'%';
        } else {
            $currency_text='satoshi';
            if ($faucet_settings_array['currency']=='DOGE') {
                $currency_text='DOGE';
            }
            $data['shortlink'].=(float)$faucet_settings_array['shortlink_payout'].' '.$currency_text;
        }
        $data['shortlink'].=' extra during the claim.';
        $data['shortlink'].='</div>';
    } else {
        $data['shortlink']='<div id="id_shortlink"></div>';
        $data['shortlink'].='<script>
$.ajax({
    url: \'shortlink.php\',
    type: \'GET\', 
    data: { gensl: 1 },
    dataType: \'json\'
}).done(function(data) {
    if (typeof(data.shortlink_html)!==\'undefined\') {
        $(\'#id_shortlink\').html(\'<div class="alert alert-info shortlink">\'+data.shortlink_html+\'</div>\');
    }
});
</script>';
    }
}

if (!empty($_SERVER["HTTP_X_REQUESTED_WITH"]) && strtolower($_SERVER["HTTP_X_REQUESTED_WITH"]) === "xmlhttprequest") {
    trigger_error("AJAX call that would break session");
    die();
}

$_SESSION[$session_prefix.'_address_input_name'] = randHash(rand(10, 12));
$data['address_input_name'] = $_SESSION[$session_prefix.'_address_input_name'];

$data['rewards'] = implode(', ', $possible_rewards);

$q = $sql->query("SELECT url_name, name FROM ".$dbtable_prefix."Pages ORDER BY id");
$data["user_pages"] = $q->fetchAll();

$allowed = array("shortlink", "page", "name", "rewards", "short", "error", "paid", "captcha_valid", "captcha", "captcha_info", "time_left", "referral", "reflink", "template", "user_pages", "timer", "unit", "address", "balance", "disable_admin_panel", "address_input_name", "block_adblock", "iframe_sameorigin_only", "button_timer", "safety_limits_end_time");

preg_match_all('/\$data\[([\'"])(custom_(?:(?!\1).)*)\1\]/', file_get_contents("templates/$template/index.php"), $matches);
foreach (array_unique($matches[2]) as $box) {
    $key = "{$box}_$template";
    if (!array_key_exists($key, $data)) {
        $data[$key] = '';
    }
    $allowed[] = $key;
}

foreach (array_keys($data) as $key) {
    if (!(in_array($key, $allowed))) {
        unset($data[$key]);
    }
}

foreach (array_keys($data) as $key) {
    if (array_key_exists($key, $data) && strpos($key, 'custom_') === 0) {
        $data[substr($key, 0, strlen($key) - strlen($template) - 1)] = $data[$key];
        unset($data[$key]);
    }
}

if (array_key_exists('p', $_GET)) {
    $q = $sql->prepare("SELECT url_name, name, html FROM ".$dbtable_prefix."Pages WHERE url_name = ?");
    $q->execute(array($_GET['p']));
    if ($page = $q->fetch()) {
        $data['page'] = 'user_page';
        $data['user_page'] = $page;
    } else {
        $data['error'] = "<div class='alert alert-danger'>That page doesn't exist!</div>";
    }
}

$data['address'] = htmlspecialchars($data['address']);

require_once('templates/'.$template.'/index.php');
