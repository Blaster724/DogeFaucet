<?php

require_once 'config.php';

if (empty($dbtable_prefix)) {
    $dbtable_prefix = 'Faucetinabox_';
}

session_start();
header('Content-Type: text/html; charset=utf-8');
ini_set('display_errors', false);

if ((!empty($_GET['sl']))&&(!empty($_SESSION['shortlink']['hash']))) {
    if ($_GET['sl']==$_SESSION['shortlink']['hash']) {
        // success, redirect to home
        $_SESSION['shortlink']['solved']=true;
        header('Location: .');
        exit;
    }
}

if (!empty($_GET['gensl'])) {
    $return_data=array();
    $return_data['log']=array();

    include_once 'libs/functions.php';
    if (empty($_SESSION['shortlink']['hash'])) {
        $return_data['log'][]='Missing hash.';
        echo json_encode($return_data);
        exit;
    }
    // generate new shortlink
    try {
        $sql = new PDO($dbdsn, $dbuser, $dbpass, array(PDO::ATTR_PERSISTENT => true,
                                                       PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION));
    } catch(PDOException $e) {
        $return_data['log'][]='No SQL connection.';
        echo json_encode($return_data);
        exit;
    }

    // get random shortlink service
    $settings=array();
    $q = $sql->prepare("SELECT name, value FROM ".$dbtable_prefix."Settings;");
    $q->execute(array());
    while ($row = $q->fetch()) {
        $settings[$row['name']]=$row['value'];
    }

    $shortlink_data=@json_decode($settings['shortlink_data'], true);
    if (!is_array($shortlink_data)) {
        $return_data['log'][]='Bad shortlink data.';
        echo json_encode($return_data);
        exit;
    }
    foreach ($shortlink_data as $k=>$v) {
        if ($v['enabled']==false) {
            unset($shortlink_data[$k]);
        }
    }
    if (count($shortlink_data)<1) {
        $return_data['log'][]='No shortlinks enabled.';
        echo json_encode($return_data);
        exit;
    }

    while (true) {
        // get random key
        $key=array_rand($shortlink_data);
        $api_token = $shortlink_data[$key]['apikey'];
        $api_url = $shortlink_data[$key]['apilink'];
        // shortlink text
        $shortlink_text='Visit this link to get ';
        if (strpos($settings['shortlink_payout'], '%')!==false) {
            $shortlink_text.=(int)$settings['shortlink_payout'].'%';
        } else {
            $currency_text='satoshi';
            if ($settings['currency']=='DOGE') {
                $currency_text='DOGE';
            }
            $shortlink_text.=(float)$settings['shortlink_payout'].' '.$currency_text;
        }
        $shortlink_text.=' extra when you claim!';

        // Check protocol
        if (array_key_exists("HTTPS", $_SERVER) && $_SERVER["HTTPS"]) {
            $protocol = "https://";
        } else {
            $protocol = "http://";
        }
        //
        $return_url = $protocol.$_SERVER['HTTP_HOST'].strtok($_SERVER['REQUEST_URI'], '?').'?sl='.$_SESSION['shortlink']['hash'];
        $return_url_encoded = urlencode($return_url);
        $api_url.= '?api='.$api_token.'&url='.$return_url_encoded.'&alias=F'.randHash(9).'&expiry='.(time()+86400);//.'&type=1'

        $return_data['shortlink']='';
        $return_data['shortlink_html']='';

        // get the shortlink
        if ($ch = curl_init()) {
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 7); 
            curl_setopt($ch, CURLOPT_TIMEOUT, 7);
            curl_setopt($ch, CURLOPT_URL, $api_url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
            $shortlink_response = @curl_exec($ch);
            curl_close($ch);
            $result = @json_decode($shortlink_response, true);
            if ((!empty($result['status']))&&($result['status']=='success')) {
                $return_data['log'][]=$key.' success';
                $return_data['shortlink']=$result['shortenedUrl'];
                $return_data['shortlink_html']='<a href="'.$result['shortenedUrl'].'">'.$shortlink_text.'</a>';
                echo json_encode($return_data);
                exit;
            } else {
                $return_data['log'][]=$key.' fail';
                unset($shortlink_data[$key]);
                if (count($shortlink_data)<1) {
                    // no more shortlink providers to try
                    echo json_encode($return_data);
                    exit;
                }
            }
        } else {
            // curl not enabled
            $return_data['log'][]='curl not enabled';
            echo json_encode($return_data);
            exit;
        }
    }
}

// error, redirect to home
header('Location: .');
exit;

?>