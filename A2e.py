'''
File: a2e.py
Author: Logan Dihel, Matt Macduff
Date: 5/24/2018
Last Modified: 5/24/2018
Description: This file shall be imported and handle 
all of the respective A2e APIs with simple, high-level
wrapper functions
'''

import os
import os.path
import re
import sys
import json
import base64
import requests
from getpass import getpass

class BadStatusCodeError(RuntimeError):
    def __init__(self, req):
        self.status_code = req.status_code
        self.reason = req.reason

    def __str__(self):
        return ((
            'Server Returned Bad Status Code\n'
            'Status Code: {}\n'
            'Reason: {}').format(self.status_code, self.reason)
        )

class A2e:

    def __init__(self, cert=None):
        '''cert can be an existing certificate
        or a file path to a .cert file
        '''
        self.api_url = 'https://l77987ttq5.execute-api.us-west-2.amazonaws.com/prod'
        self.cert = cert
        self.auth = None

        # TODO: certify from cert string
        # TODO: certify from ~/.cert file

    # --------------------------------------------------------------
    # - Getting Authenticated --------------------------------------
    # --------------------------------------------------------------
    
    def _request_cert(self, params):
        '''Request a certificate
        '''
        req = requests.put('{}/creds'.format(self.api_url), params=params)

        if req.status_code != 200:
            raise BadStatusCodeError(req)
        
        self.cert = json.loads(req.text)['text']


    def _create_cert_auth(self):
        '''Given an existing certificate, create an auth token
        '''
        self.auth = {
            "Authorization": "Cert {}".format(
                base64.b64encode(self.cert.encode("utf-8")).decode("ascii"))
        }
        

    def _request_cert_auth(self, params):
        '''Requests certificate and creates auth token
        '''
        self._request_cert(params)
        self._create_cert_auth()


    def _create_basic_auth(self, username, password):
        '''Create the auth token without 
        '''
        self.auth = {
            "Authorization": "Basic {}".format(base64.b64encode(
                ("{}:{}".format(username, password)).encode("utf-8")
            ).decode("ascii"))
        }


    def guest_auth(self):
        self._create_basic_auth('guest', 'guest')


    def user_pass_auth(self, username, password):
        '''Given username and password request a
        cert token and generate an auth code
        '''
        params = {
            'username': username,
            'password': password,
        }

        self._request_cert_auth(params)


    def two_factor_auth(self, username, password, email, authcode):
        '''Given username, password, email, and authcode,
        request a cert token and generate an auth code
        '''
        params = {
            'username': username,
            'password': password,
            'email': email,
            'authcode': authcode
        }

        self._request_cert_auth(params)

    # --------------------------------------------------------------
    # - Search for Filenames ---------------------------------------
    # --------------------------------------------------------------

    def search(self, filter_arg, table='Inventory'):
        '''Search the table and return the matching file paths
        https://github.com/a2edap/tools/tree/master/lambda/api/get-info
        '''
        if not self.auth:
            raise Exception('Auth token cannot be None')

        req = requests.post(
            '{}/searches'.format(self.api_url),
            headers=self.auth,
            data=json.dumps({
                'source': table,
                'output': 'json',
                'filter': filter_arg
            })
        )

        if req.status_code != 200:
            raise BadStatusCodeError(req)
        
        req = req.json()
        files = [x['Filename'] for x in req]
        return files

    # --------------------------------------------------------------
    # - Placing Orders ---------------------------------------------
    # --------------------------------------------------------------

    def place_order(self, files):
        '''Place an order and return the order ID
        '''
        if not self.auth:
            raise Exception('Auth token cannot be None')

        params = {
            'files': files,
        }

        req = requests.put(
            '{}/orders'.format(self.api_url), 
            headers=self.auth, 
            data=json.dumps(params)
        )

        if req.status_code != 200:
            raise BadStatusCodeError(req)

        id = json.loads(req.text)['id']
        return id

    # --------------------------------------------------------------
    # - Getting download URLs --------------------------------------
    # --------------------------------------------------------------

    def get_download_urls(self, id):
        '''Given order ID, return the download urls
        '''
        if not self.auth:
            raise Exception('Auth token cannot be None')

        req = requests.get(
            '{}/orders/{}/urls'.format(self.api_url, id), 
            headers=self.auth
        )

        if req.status_code != 200:
            raise BadStatusCodeError(req)

        urls = json.loads(req.text)['urls']
        return urls

    


    
