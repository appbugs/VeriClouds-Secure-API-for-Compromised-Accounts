<?php
include "api.php";

$token = $_GET['token'];

//test credentials
$test_credentials = [
        array('email'=>'wearetesting@yahoo.com','password'=>'12345678'),
        array('email'=>'whynottest@mit.edu','password'=>'asDF6789!'),
        array('email'=>'letustest@163.com','password'=>'thisisgoodPass!')
    ];
foreach ($test_credentials as $cred) {
    //test the username and password against VeriClouds server without revealing the username and password
    $match = private_preserving_compromise_detection($cred['email'],$cred['password'],$token);
    if ($match) {
        echo $cred['email'] . ',' . $cred['password'] . ', compromised!!!!!!<br>';
    } else {
        echo $cred['email'] . ',' . $cred['password'] . ', not compromised.<br>';
    }
}

?>