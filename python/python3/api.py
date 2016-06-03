import bcrypt
import json
import urllib.request
import hashlib

version = '0.90' #change the number for every update
API_BASE_URL = 'https://www.vericlouds.com/private_search/api.php?'

def private_preserving_compromise_detection(email, password, token):
    email = email.lower() #lower case the email
    
    #Create anonymized email for sending to API
    anonymized_email = email
    #anonymized_email = '__' + anonymized_email[1:]
    anonymized_email = '__' + anonymized_email[2:]
    
    #Call to API 
    url_req = '{0}token={1}&mode=privacy_preserving_account_query&email={2}'.format(API_BASE_URL,token,anonymized_email)
    json_str = urllib.request.urlopen(url_req).read().decode("utf-8")
    result = json.loads(json_str)
    #print result
    if result['result'] != 'succeeded':
        print ('query failed.reason: {0}'.format(result['reason']))
        return False
        
    #Checking for compromised status
    records = result['records']
    for row in records:
        if email == row['email']:  #encode email because email is unicode
            hash_algorithm = row['hash_algorithm']
            if hash_algorithm['ca_hash'] == 'bcrypt':  #currently only bcrypt hash supported 
                salt = hash_algorithm['ca_salt']
                password_hash = bcrypt.hashpw(password.encode("utf-8"), salt.encode("utf-8"))
                password_hash = password_hash.decode("utf-8")
                remote_password_hashes = row['password_hash'].split(',')
                for remote_hash in remote_password_hashes:
                    if remote_hash == password_hash:   #compromise detected
                       return True
                        
    return False




