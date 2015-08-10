import os
import shutil
import unittest
import tempfile
import httpretty
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from base64 import b64decode

from steamweb.steamwebbrowser import *

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
        httpretty.register_uri(httpretty.GET, 'https://store.steampowered.com/account/',
                                status=302,
                                adding_headers={
                                    'Location': 'https://store.steampowered.com/login/?redir=account%2F&redir_ssl=1'
                                })
        httpretty.register_uri(httpretty.GET, 'https://store.steampowered.com/login/',
                                status=200,
                                body='OK',
                                )

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

if __name__ == '__main__':
    unittest.main()
