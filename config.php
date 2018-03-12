<?php

$dbhost = "localhost";
$dbuser = "ultimate";
$dbpass = "ultimate";
$dbname = "ultimate";
$dbtable_prefix = 'Faucetinabox_'; // default empty
$display_errors = true;
$disable_admin_panel = false;

$faucethub_ref_url='https://faucethub.io/r/13852';

$connection_options = array(
    'disable_curl' => false,
    'local_cafile' => false,
    'force_ipv4' => false    // cURL only
);

// dsn - Data Source Name
// if you use MySQL, leave it as is
// more information:
// http://php.net/manual/en/pdo.construct.php
$dbdsn = "mysql:host=$dbhost;dbname=$dbname";
