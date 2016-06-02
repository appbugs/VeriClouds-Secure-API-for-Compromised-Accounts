from api import *

token = 'PUT_YOUR_ADMIN_TOKEN_HERE' #put admin token you get from vericlouds before running the script. If you do not have one, sign up on https://vericlouds.com/product-signup-page/?product=secure_API to get one.
token = 'FkFbRrrmtzJG3LjRMInI'

#test credentials
test_credentials = []
test_credentials.append({'email':'wearetesting@yahoo.com','password':'12345678'})
test_credentials.append({'email':'whynottest@mit.edu','password':'asDF6789!'})
test_credentials.append({'email':'letustest@163.com','password':'thisisgoodPass!'})

for cred in test_credentials:
    #test the username and password against VeriClouds server without revealing the username and password
    match = private_preserving_compromise_detection(cred['email'],cred['password'],token)
    if match:
        print 'username="{0}",password="{1}", compromised!!!'.format(cred['email'],cred['password'])
    else:
        print 'username="{0}",password="{1}", no compromise detected'.format(cred['email'],cred['password'])