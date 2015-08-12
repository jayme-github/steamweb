import os
import shutil
import unittest
import tempfile
import httpretty
import json
import datetime
import random
import string
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from base64 import b64decode

from steamweb.steamwebbrowser import SteamWebBrowser, SteamWebError

def random_ascii_string(lengh):
    ''' Return a random string
    May contain ASCII upper and lowercase as well as digits
    '''
    return ''.join(random.choice(
        string.ascii_letters + string.digits
        ) for i in range(lengh))

def random_number(lengh):
    ''' Return a random numbe rwith fixed length of lengh '''
    range_start = 10**(lengh-1)
    range_end = (10**lengh)-1
    return random.randint(range_start, range_end)


class TestSteamWebBrowser(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        os.environ['STEAMWEBROWSER_HOME'] = self.temp_dir

    def tearDown(self):
        if os.path.isdir(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_appdata_path(self):
        ''' Test if appdata path is created '''
        swb = SteamWebBrowser('user', 'password')
        self.assertTrue(os.path.isdir(swb.appdata_path) and os.access(swb.appdata_path, os.W_OK))

    @httpretty.activate
    def test_not_logged_in(self):
        httpretty.register_uri(httpretty.HEAD, 'https://store.steampowered.com/login/',
                                status=200,
                                adding_headers={
                                    'Set-Cookie': 'steamCountry=DE%%7C%s; path=/' % (
                                        random_ascii_string(32),
                                    ),
                                    'Set-Cookie': 'browserid=%d; expires=%s; path=/' % (
                                        random_number(18),
                                        (datetime.datetime.now() + datetime.timedelta(days=365)).strftime('%a, %d-%b-%Y %H:%M:%S GMT'),
                                    ),
                                })

        swb = SteamWebBrowser('user', 'password')
        self.assertFalse(swb.logged_in())

    @httpretty.activate
    def test_rsa_fail(self):
        body='{"success": false}'
        httpretty.register_uri(httpretty.POST, 'https://steamcommunity.com/login/getrsakey/',
                                body=body,
                                content_type='text/json')
        swb = SteamWebBrowser('user', 'password')
        with self.assertRaises(SteamWebError):
            swb._get_rsa_key()

    @httpretty.activate
    def test_encryption(self):
        rsa_full = RSA.generate(2048)
        cipher_full = PKCS1_v1_5.new(rsa_full)

        body = {
            'success': True,
            'publickey_mod': format(rsa_full.n, 'x').upper(),
            'publickey_exp': format(rsa_full.e, 'x').upper(),
            'timestamp': '64861350000', # TODO don't know how this is constructed
        }
        httpretty.register_uri(httpretty.POST, 'https://steamcommunity.com/login/getrsakey/',
                                body=json.dumps(body),
                                content_type='text/json')
        swb = SteamWebBrowser('user', 'password')
        ciphertext = b64decode(swb._get_encrypted_password())
        self.assertEqual(cipher_full.decrypt(ciphertext, None), swb._password)
