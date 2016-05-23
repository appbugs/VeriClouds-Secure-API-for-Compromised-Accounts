<?php
include "bcrypt.php";
define ('API_BASE_URL','https://www.vericlouds.com/private_search/api.php?');

$bcrypt = new Bcrypt();

/**
 * @function    For Detecting Compromised Customer Accounts in a Privacy Preserving Way
 * @author      Rui Wang <ruiw@vericlouds.com>
 * @date        4th April, 2016
*/
function private_preserving_compromise_detection($email, $password, $token) {
        $email = strtolower($email); //lower case the email

        //Create anonymized email for sending to API
        $anonymized_email = $email;
        $anonymized_email[0] = '_';
        $anonymized_email[1] = '_';

        //Call to API 
        $url_req = API_BASE_URL . 'token=' . $token . '&mode=privacy_preserving_account_query&email=' . $anonymized_email; //to server
        $json_str = file_get_contents($url_req);

        $result = json_decode($json_str, true);
        if ($result['result'] != 'succeeded') {
            echo "query failed. reason: " . $result['reason'];
            return false;
        }

        //Checking for compromised status
        $records = $result['records'];
        foreach ($records as $row) {
            if ($email == $row['email']) {
                $hash_algorithm = $row['hash_algorithm'];
                if ($hash_algorithm['ca_hash'] == 'bcrypt') { //currently only bcrypt hash supported
                    if (!isset($bcrypt)) $bcrypt = new Bcrypt();
                    $password_hash = $bcrypt->hash($password,$hash_algorithm['ca_salt']);
                    $remote_password_hashes = explode(',',$row['password_hash']);
                    foreach ($remote_password_hashes as $remote_hash) {
                        if ($remote_hash === $password_hash) { //compromise detected
                            return true;
                        }
                    }
                }
            }
        }

        return false;        
}

?>